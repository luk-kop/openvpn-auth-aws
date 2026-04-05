package mgmt

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStatusParserParsesEstablishedSessions(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"TITLE,OpenVPN 2.6 mock",
		"HEADER,CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since (time_t),Username,Client ID,Peer ID",
		"CLIENT_LIST,alice@example.com,198.51.100.10:1194,1,2,1700000000,alice@example.com,7,0",
		"END",
	}

	var done bool
	for _, line := range lines {
		var err error
		done, err = parser.consume(line)
		if err != nil {
			t.Fatalf("consume(%q): %v", line, err)
		}
	}
	if !done {
		t.Fatal("expected END to complete status parsing")
	}
	if len(parser.sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(parser.sessions))
	}
	if parser.sessions[0].CID != "7" {
		t.Fatalf("CID = %q, want 7", parser.sessions[0].CID)
	}
	if parser.sessions[0].CommonName != "alice@example.com" {
		t.Fatalf("CommonName = %q", parser.sessions[0].CommonName)
	}
}

func TestStatusParserParsesEstablishedSessions_TabSeparated(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"TITLE\tOpenVPN 2.6 mock",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tBytes Received\tBytes Sent\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID",
		"CLIENT_LIST\talice@example.com\t198.51.100.10:1194\t1\t2\t1700000000\talice@example.com\t7\t0",
		"END",
	}

	var done bool
	for _, line := range lines {
		var err error
		done, err = parser.consume(line)
		if err != nil {
			t.Fatalf("consume(%q): %v", line, err)
		}
	}
	if !done {
		t.Fatal("expected END to complete status parsing")
	}
	if len(parser.sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(parser.sessions))
	}
	if parser.sessions[0].CID != "7" {
		t.Fatalf("CID = %q, want 7", parser.sessions[0].CID)
	}
	if parser.sessions[0].CommonName != "alice@example.com" {
		t.Fatalf("CommonName = %q", parser.sessions[0].CommonName)
	}
}

func TestBootstrapStatusReturnsSnapshotAndBufferedEvents(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		defer func() { _ = server.Close() }()
		scanner := bufio.NewScanner(server)
		if !scanner.Scan() {
			return
		}
		if got := strings.TrimSpace(scanner.Text()); got != "hold release" {
			return
		}
		if !scanner.Scan() {
			return
		}
		if got := strings.TrimSpace(scanner.Text()); got != "status 3" {
			return
		}
		_, _ = server.Write([]byte(">CLIENT:REAUTH,5,2\n"))
		_, _ = server.Write([]byte(">CLIENT:ENV,common_name=alice@example.com\n"))
		_, _ = server.Write([]byte(">CLIENT:ENV,END\n"))
		_, _ = server.Write([]byte("TITLE,OpenVPN 2.6 mock\n"))
		_, _ = server.Write([]byte("HEADER,CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since (time_t),Username,Client ID,Peer ID\n"))
		_, _ = server.Write([]byte("CLIENT_LIST,alice@example.com,198.51.100.10:1194,1,2,1700000000,alice@example.com,5,0\n"))
		_, _ = server.Write([]byte("END\n"))
	}()

	client := &Client{
		conn:    clientConn,
		scanner: bufio.NewScanner(clientConn),
	}

	sessions, events, err := BootstrapStatus(client)
	if err != nil {
		t.Fatalf("BootstrapStatus: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].CID != "5" || sessions[0].CommonName != "alice@example.com" {
		t.Fatalf("unexpected session: %+v", sessions[0])
	}
	if sessions[0].ConnectedAt != time.Unix(1700000000, 0) {
		t.Fatalf("ConnectedAt = %v", sessions[0].ConnectedAt)
	}
	if len(events) != 1 || events[0].Type != EventReauth || events[0].CID != "5" {
		t.Fatalf("unexpected buffered events: %+v", events)
	}
}

func TestBootstrapStatusReturnsSnapshotAndBufferedEvents_TabSeparated(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		defer func() { _ = server.Close() }()
		scanner := bufio.NewScanner(server)
		if !scanner.Scan() {
			return
		}
		if got := strings.TrimSpace(scanner.Text()); got != "hold release" {
			return
		}
		if !scanner.Scan() {
			return
		}
		if got := strings.TrimSpace(scanner.Text()); got != "status 3" {
			return
		}
		_, _ = server.Write([]byte(">CLIENT:REAUTH,5,2\n"))
		_, _ = server.Write([]byte(">CLIENT:ENV,common_name=alice@example.com\n"))
		_, _ = server.Write([]byte(">CLIENT:ENV,END\n"))
		_, _ = server.Write([]byte("TITLE\tOpenVPN 2.6 mock\n"))
		_, _ = server.Write([]byte("HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tBytes Received\tBytes Sent\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\n"))
		_, _ = server.Write([]byte("CLIENT_LIST\talice@example.com\t198.51.100.10:1194\t1\t2\t1700000000\talice@example.com\t5\t0\n"))
		_, _ = server.Write([]byte("END\n"))
	}()

	client := &Client{
		conn:    clientConn,
		scanner: bufio.NewScanner(clientConn),
	}

	sessions, events, err := BootstrapStatus(client)
	if err != nil {
		t.Fatalf("BootstrapStatus: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].CID != "5" || sessions[0].CommonName != "alice@example.com" {
		t.Fatalf("unexpected session: %+v", sessions[0])
	}
	if sessions[0].ConnectedAt != time.Unix(1700000000, 0) {
		t.Fatalf("ConnectedAt = %v", sessions[0].ConnectedAt)
	}
	if len(events) != 1 || events[0].Type != EventReauth || events[0].CID != "5" {
		t.Fatalf("unexpected buffered events: %+v", events)
	}
}
