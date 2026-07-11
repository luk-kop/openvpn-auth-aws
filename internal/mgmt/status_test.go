package mgmt

import (
	"testing"
)

func TestStatusParserParsesEstablishedSessions(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"TITLE,OpenVPN 2.6 mock",
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since (time_t),Username,Client ID,Peer ID",
		"CLIENT_LIST,alice@example.com,198.51.100.10:1194,10.8.0.2,1,2,1700000000,alice@example.com,7,0",
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
	if len(parser.snapshot.Established) != 1 {
		t.Fatalf("expected 1 session, got %d", len(parser.snapshot.Established))
	}
	if parser.snapshot.Established[0].CID != "7" {
		t.Fatalf("CID = %q, want 7", parser.snapshot.Established[0].CID)
	}
	if parser.snapshot.Established[0].CommonName != "alice@example.com" {
		t.Fatalf("CommonName = %q", parser.snapshot.Established[0].CommonName)
	}
}

func TestStatusParserParsesEstablishedSessions_TabSeparated(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"TITLE\tOpenVPN 2.6 mock",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID",
		"CLIENT_LIST\talice@example.com\t198.51.100.10:1194\t10.8.0.2\t1\t2\t1700000000\talice@example.com\t7\t0",
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
	if len(parser.snapshot.Established) != 1 {
		t.Fatalf("expected 1 session, got %d", len(parser.snapshot.Established))
	}
	if parser.snapshot.Established[0].CID != "7" {
		t.Fatalf("CID = %q, want 7", parser.snapshot.Established[0].CID)
	}
	if parser.snapshot.Established[0].CommonName != "alice@example.com" {
		t.Fatalf("CommonName = %q", parser.snapshot.Established[0].CommonName)
	}
}

func TestStatusParserKeepsPendingClientOutOfEstablishedSessions(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"TITLE\tOpenVPN 2.7.5 mock",
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tConnected Since (time_t)\tClient ID",
		"CLIENT_LIST\tAlice@example.com\tudp4:198.51.100.10:1194\t\t\t1700000000\t7",
		"HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address",
		"END",
	}

	for _, line := range lines {
		if _, err := parser.consume(line); err != nil {
			t.Fatalf("consume(%q): %v", line, err)
		}
	}

	if len(parser.snapshot.Clients) != 1 {
		t.Fatalf("Clients = %d, want 1", len(parser.snapshot.Clients))
	}
	client := parser.snapshot.Clients[0]
	if client.CID != "7" || client.Established || client.VirtualAddress != "" {
		t.Fatalf("pending client classified incorrectly: %+v", client)
	}
	if len(parser.snapshot.Established) != 0 {
		t.Fatalf("Established = %+v, want none", parser.snapshot.Established)
	}
}

func TestStatusParserRoutingConfirmationRequiresExactIdentityAndAddress(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Connected Since (time_t),Client ID",
		"CLIENT_LIST,Alice@example.com,tcp4:198.51.100.10:1194,10.8.0.2,1700000000,7",
		"CLIENT_LIST,bob@example.com,tcp4:198.51.100.11:1194,10.8.0.3,1700000001,8",
		"HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address",
		"ROUTING_TABLE,10.8.0.2,alice@example.com,tcp4:198.51.100.10:1194",
		"ROUTING_TABLE,10.8.0.3,bob@example.com,tcp4:198.51.100.99:1194",
		"END",
	}

	for _, line := range lines {
		if _, err := parser.consume(line); err != nil {
			t.Fatalf("consume(%q): %v", line, err)
		}
	}

	if len(parser.snapshot.Clients) != 2 {
		t.Fatalf("Clients = %d, want 2", len(parser.snapshot.Clients))
	}
	for _, client := range parser.snapshot.Clients {
		if client.RoutingConfirmed {
			t.Fatalf("non-exact route confirmed client: %+v", client)
		}
		if !client.Established {
			t.Fatalf("non-empty virtual address not classified as established: %+v", client)
		}
	}
}

func TestStatusParserRoutingConfirmationForExactPair(t *testing.T) {
	parser := &statusParser{}
	lines := []string{
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Connected Since (time_t),Client ID",
		"CLIENT_LIST,alice@example.com,tcp4:198.51.100.10:1194,10.8.0.2,1700000000,7",
		"HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address",
		"ROUTING_TABLE,10.8.0.2,alice@example.com,tcp4:198.51.100.10:1194",
		"END",
	}

	for _, line := range lines {
		if _, err := parser.consume(line); err != nil {
			t.Fatalf("consume(%q): %v", line, err)
		}
	}

	if len(parser.snapshot.Clients) != 1 || !parser.snapshot.Clients[0].RoutingConfirmed {
		t.Fatalf("exact route was not correlated: %+v", parser.snapshot.Clients)
	}
}
