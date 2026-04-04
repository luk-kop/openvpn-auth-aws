package mgmt

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// BootstrapStatus releases the management hold, requests `status 3`, and
// returns the currently established sessions plus any async CLIENT events that
// arrived while reading the snapshot.
func BootstrapStatus(client *Client) ([]EstablishedSession, []Event, error) {
	if err := client.WriteLine("hold release"); err != nil {
		return nil, nil, fmt.Errorf("write hold release: %w", err)
	}
	if err := client.WriteLine("status 3"); err != nil {
		return nil, nil, fmt.Errorf("write status 3: %w", err)
	}

	var (
		parser    statusParser
		gotStatus bool
		events    []Event
	)

	scanner := client.Scanner()
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case isStatusLine(line):
			gotStatus = true
			done, err := parser.consume(line)
			if err != nil {
				return nil, nil, err
			}
			if done {
				return parser.sessions, events, nil
			}
		case strings.HasPrefix(line, ">CLIENT:"):
			event, err := ReadEvent(scanner, line)
			if err != nil {
				return nil, nil, err
			}
			events = append(events, event)
		case strings.HasPrefix(line, ">HOLD:"):
			// We already sent hold release above. Ignore duplicate HOLD lines.
		default:
			if gotStatus {
				// Ignore unknown non-CLIENT lines inside status output to stay
				// resilient across OpenVPN versions.
				continue
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("unexpected EOF waiting for status 3 response")
}

func isStatusLine(line string) bool {
	return line == "END" ||
		strings.HasPrefix(line, "TITLE,") ||
		strings.HasPrefix(line, "TIME,") ||
		strings.HasPrefix(line, "HEADER,") ||
		strings.HasPrefix(line, "CLIENT_LIST,") ||
		strings.HasPrefix(line, "GLOBAL_STATS,") ||
		strings.HasPrefix(line, "ROUTING_TABLE,")
}

type statusParser struct {
	clientHeader map[string]int
	sessions     []EstablishedSession
}

func (p *statusParser) consume(line string) (bool, error) {
	if line == "END" {
		return true, nil
	}

	fields := splitCSVLine(line)
	if len(fields) == 0 {
		return false, nil
	}
	switch fields[0] {
	case "HEADER":
		if len(fields) >= 3 && fields[1] == "CLIENT_LIST" {
			p.clientHeader = make(map[string]int, len(fields)-2)
			for i, name := range fields[2:] {
				p.clientHeader[normalizeHeader(name)] = i + 1 // client_list data starts after record type
			}
		}
	case "CLIENT_LIST":
		sess, ok, err := p.parseClient(fields)
		if err != nil {
			return false, err
		}
		if ok {
			p.sessions = append(p.sessions, sess)
		}
	}
	return false, nil
}

func (p *statusParser) parseClient(fields []string) (EstablishedSession, bool, error) {
	get := func(names ...string) string {
		for _, name := range names {
			if idx, ok := p.clientHeader[normalizeHeader(name)]; ok && idx < len(fields) {
				return fields[idx]
			}
		}
		return ""
	}

	cid := get("Client ID", "ClientID")
	cn := get("Common Name", "CommonName")
	connected := get("Connected Since (time_t)", "Connected Since", "ConnectedSince")
	if cid == "" || cn == "" || connected == "" {
		return EstablishedSession{}, false, nil
	}

	sec, err := strconv.ParseInt(connected, 10, 64)
	if err != nil {
		return EstablishedSession{}, false, fmt.Errorf("parse connected since %q: %w", connected, err)
	}
	return EstablishedSession{
		CID:         cid,
		CommonName:  cn,
		ConnectedAt: time.Unix(sec, 0),
	}, true, nil
}

func normalizeHeader(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "_", "", "-", "", "(", "", ")", "").Replace(s)
	return s
}

func splitCSVLine(line string) []string {
	// OpenVPN status 3 output is simple comma-separated text without quoted commas
	// in the fields we consume here.
	return strings.Split(line, ",")
}
