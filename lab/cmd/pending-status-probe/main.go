package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"openvpn-auth-aws/internal/mgmt"
)

const probeTimeout = 90 * time.Second

type phase int

const (
	waitConnect phase = iota
	waitBeforeAuthStatus
	waitAuthAck
	waitAfterAuthStatus
	waitAfterGraceStatus
	waitKillAck
	waitDisconnect
	waitAfterKillStatus
)

func main() {
	socket := flag.String("socket", "/run/openvpn/management.sock", "OpenVPN management socket")
	passwordFile := flag.String("password-file", "/etc/openvpn/management-pw", "management password file")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	client, err := mgmt.Dial(ctx, *socket, *passwordFile, time.Second)
	if err != nil {
		fatalf("connect management socket: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		fatalf("set read deadline: %v", err)
	}

	logMarker("PROBE_READY")
	scanner := client.Scanner()
	currentPhase := waitConnect
	var cid, kid string
	var statusLines []string

	for scanner.Scan() {
		line := scanner.Text()
		logLine("RECV", line)

		if strings.HasPrefix(line, ">HOLD:") {
			writeLine(client, "hold release")
			continue
		}

		if strings.HasPrefix(line, ">CLIENT:CONNECT,") && currentPhase == waitConnect {
			parts := strings.Split(line, ",")
			if len(parts) < 3 {
				fatalf("invalid CLIENT:CONNECT line: %q", line)
			}
			cid, kid = parts[1], parts[2]
			continue
		}

		if line == ">CLIENT:ENV,END" && currentPhase == waitConnect && cid != "" {
			writeLine(client, "status 3")
			currentPhase = waitBeforeAuthStatus
			statusLines = nil
			continue
		}

		if strings.HasPrefix(line, ">CLIENT:ESTABLISHED,"+cid) {
			logMarker("PROBE_EVENT established cid=%s", cid)
			continue
		}

		if strings.HasPrefix(line, ">CLIENT:DISCONNECT,"+cid) {
			logMarker("PROBE_EVENT disconnected cid=%s", cid)
			if currentPhase == waitDisconnect {
				writeLine(client, "status 3")
				currentPhase = waitAfterKillStatus
				statusLines = nil
			}
			continue
		}

		switch currentPhase {
		case waitBeforeAuthStatus, waitAfterAuthStatus, waitAfterGraceStatus, waitAfterKillStatus:
			if strings.HasPrefix(line, ">") {
				continue
			}
			if line != "END" {
				statusLines = append(statusLines, line)
				continue
			}

			found, virtualAddress, err := findStatusClient(statusLines, cid)
			if err != nil {
				fatalf("parse status for cid=%s: %v", cid, err)
			}
			switch currentPhase {
			case waitBeforeAuthStatus:
				if !found || virtualAddress != "" {
					fatalf("pre-auth status: found=%t virtual_address=%q, want pending row", found, virtualAddress)
				}
				logMarker("PROBE_ASSERT pre_auth_pending_present cid=%s", cid)
				writeLine(client, fmt.Sprintf("client-auth %s %s", cid, kid))
				writeLine(client, "END")
				currentPhase = waitAuthAck
			case waitAfterAuthStatus:
				if !found {
					fatalf("post-ACK status: cid=%s absent", cid)
				}
				logMarker("PROBE_ASSERT post_ack_present cid=%s virtual_address=%q", cid, virtualAddress)
				time.Sleep(5 * time.Second)
				writeLine(client, "status 3")
				currentPhase = waitAfterGraceStatus
				statusLines = nil
			case waitAfterGraceStatus:
				if !found {
					fatalf("post-grace status: cid=%s absent", cid)
				}
				logMarker("PROBE_ASSERT post_grace_present cid=%s established=%t virtual_address=%q", cid, virtualAddress != "", virtualAddress)
				writeLine(client, fmt.Sprintf("client-kill %s HALT", cid))
				currentPhase = waitKillAck
			case waitAfterKillStatus:
				if found {
					fatalf("post-disconnect status: cid=%s still present", cid)
				}
				logMarker("PROBE_ASSERT post_disconnect_absent cid=%s", cid)
				logMarker("PROBE_COMPLETE")
				return
			}

		case waitAuthAck:
			if strings.HasPrefix(line, "ERROR:") {
				fatalf("client-auth failed: %s", line)
			}
			if strings.HasPrefix(line, "SUCCESS:") {
				logMarker("PROBE_ASSERT client_auth_ack cid=%s", cid)
				writeLine(client, "status 3")
				currentPhase = waitAfterAuthStatus
				statusLines = nil
			}

		case waitKillAck:
			if strings.HasPrefix(line, "ERROR:") {
				fatalf("client-kill failed: %s", line)
			}
			if strings.HasPrefix(line, "SUCCESS:") {
				logMarker("PROBE_ASSERT client_kill_ack cid=%s", cid)
				currentPhase = waitDisconnect
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fatalf("read management socket: %v", err)
	}
	fatalf("management socket closed before probe completed")
}

func writeLine(client *mgmt.Client, line string) {
	logLine("SEND", line)
	if err := client.WriteLine(line); err != nil {
		fatalf("write %q: %v", line, err)
	}
}

func findStatusClient(lines []string, cid string) (bool, string, error) {
	var header map[string]int
	for _, line := range lines {
		fields, err := splitStatusLine(line)
		if err != nil {
			return false, "", err
		}
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "HEADER":
			if fields[1] != "CLIENT_LIST" {
				continue
			}
			header = make(map[string]int, len(fields)-2)
			for i, name := range fields[2:] {
				header[normalizeHeader(name)] = i + 1
			}
		case "CLIENT_LIST":
			if header == nil {
				return false, "", errors.New("CLIENT_LIST appeared before its header")
			}
			cidIndex, ok := header[normalizeHeader("Client ID")]
			if !ok || cidIndex >= len(fields) || fields[cidIndex] != cid {
				continue
			}
			virtualIndex, ok := header[normalizeHeader("Virtual Address")]
			if !ok || virtualIndex >= len(fields) {
				return true, "", nil
			}
			return true, fields[virtualIndex], nil
		}
	}
	return false, "", nil
}

func splitStatusLine(line string) ([]string, error) {
	if strings.Contains(line, "\t") {
		return strings.Split(line, "\t"), nil
	}
	reader := csv.NewReader(strings.NewReader(line))
	reader.FieldsPerRecord = -1
	fields, err := reader.Read()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %q: %w", line, err)
	}
	return fields, nil
}

func normalizeHeader(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer(" ", "", "_", "", "-", "", "(", "", ")", "").Replace(value)
}

func logLine(direction, line string) {
	fmt.Printf("%s %s %s\n", time.Now().UTC().Format(time.RFC3339Nano), direction, line)
}

func logMarker(format string, args ...any) {
	fmt.Printf("%s %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s PROBE_FAILED %s\n", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
	os.Exit(1)
}
