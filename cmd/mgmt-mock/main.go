// mgmt-mock simulates the OpenVPN management interface on a Unix socket.
// It accepts daemon connections, handles password auth, and lets you
// send CLIENT events interactively from stdin.
//
// Usage:
//
//	go run ./cmd/mgmt-mock
//
// Then type commands like:
//
//	connect 3 john@example.com        — send CLIENT:CONNECT for CID=3
//	reauth  3 john@example.com        — send CLIENT:REAUTH  for CID=3
//	disconnect 3                       — send CLIENT:DISCONNECT for CID=3
//	quit                               — exit
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	socketPath   = "/tmp/openvpn-mgmt.sock"
	passwordFile = "/tmp/mgmt-pw"
)

func main() {
	// Read expected password, create file with default if missing.
	pwBytes, err := os.ReadFile(passwordFile)
	if os.IsNotExist(err) {
		pwBytes = []byte("test-password\n")
		if err := os.WriteFile(passwordFile, pwBytes, 0600); err != nil {
			log.Fatalf("cannot create %s: %v", passwordFile, err)
		}
		log.Printf("Created %s with default password", passwordFile)
	} else if err != nil {
		log.Fatalf("cannot read %s: %v", passwordFile, err)
	}
	expectedPw := strings.TrimSpace(string(pwBytes))
	if expectedPw == "" {
		log.Fatalf("%s is empty", passwordFile)
	}

	// Clean up stale socket.
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			log.Printf("ln.Close: %v", err)
		}
	}()
	log.Printf("Listening on %s (password from %s)", socketPath, passwordFile)
	log.Println("Waiting for daemon to connect...")

	conn, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	log.Println("Daemon connected")

	scanner := bufio.NewScanner(conn)

	// --- Password handshake ---
	// Mock acts as OpenVPN management interface server:
	// 1. Send "ENTER PASSWORD:" prompt (no newline, exactly 15 bytes)
	// 2. Read password from daemon
	// 3. Send SUCCESS or ERROR
	if expectedPw != "" {
		if _, err := fmt.Fprintf(conn, "ENTER PASSWORD:"); err != nil {
			log.Fatalf("write prompt: %v", err)
		}
		if !scanner.Scan() {
			log.Fatal("daemon disconnected before sending password")
		}
		got := scanner.Text()
		if got != expectedPw {
			_, _ = fmt.Fprintf(conn, "ERROR: bad password\r\n")
			if err := conn.Close(); err != nil {
				log.Printf("conn.Close: %v", err)
			}
			log.Fatalf("bad password: got %q", got)
		}
		if _, err := fmt.Fprintf(conn, "SUCCESS: password is correct\r\n"); err != nil {
			log.Fatalf("write success: %v", err)
		}
		log.Println("Auth OK")
	}

	// --- Read daemon responses in background ---
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for scanner.Scan() {
			log.Printf("<< daemon: %s", scanner.Text())
		}
		log.Println("Daemon disconnected")
	}()

	// --- Interactive prompt ---
	printHelp()
	stdin := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for stdin.Scan() {
		line := strings.TrimSpace(stdin.Text())
		if line == "" {
			fmt.Print("> ")
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "connect", "reauth":
			if len(parts) < 3 {
				log.Printf("usage: %s <CID> <username>", cmd)
				fmt.Print("> ")
				continue
			}
			cid := parts[1]
			username := parts[2]
			kid := "1"
			if len(parts) >= 4 {
				kid = parts[3]
			}
			sendClientEvent(conn, cmd, cid, kid, username)

		case "disconnect":
			if len(parts) < 2 {
				log.Println("usage: disconnect <CID>")
				fmt.Print("> ")
				continue
			}
			cid := parts[1]
			_, _ = fmt.Fprintf(conn, ">CLIENT:DISCONNECT,%s\n", cid)
			_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,time_duration=120\n")
			_, _ = fmt.Fprintf(conn, ">CLIENT:END\n")
			log.Printf(">> sent DISCONNECT cid=%s", cid)

		case "help":
			printHelp()

		case "quit", "exit":
			log.Println("Closing connection")
			if err := conn.Close(); err != nil {
				log.Printf("conn.Close: %v", err)
			}
			wg.Wait()
			return

		default:
			log.Printf("unknown command: %s (type 'help')", cmd)
		}
		fmt.Print("> ")
	}

	if err := conn.Close(); err != nil {
		log.Printf("conn.Close: %v", err)
	}
	wg.Wait()
}

func sendClientEvent(conn net.Conn, cmd, cid, kid, username string) {
	eventType := "CONNECT"
	if cmd == "reauth" {
		eventType = "REAUTH"
	}
	_, _ = fmt.Fprintf(conn, ">CLIENT:%s,%s,%s\n", eventType, cid, kid)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,username=%s\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,common_name=%s\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,IV_SSO=webauth\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:END\n")
	log.Printf(">> sent %s cid=%s kid=%s user=%s", eventType, cid, kid, username)
}

func printHelp() {
	fmt.Println(`
Commands:
  connect    <CID> <username> [KID]  — CLIENT:CONNECT event (KID defaults to 1)
  reauth     <CID> <username> [KID]  — CLIENT:REAUTH event
  disconnect <CID>                   — CLIENT:DISCONNECT event
  help                               — show this help
  quit                               — close connection and exit`)
}
