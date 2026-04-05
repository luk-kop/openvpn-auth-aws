package mgmt

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadConnectEvent(t *testing.T) {
	input := strings.NewReader(">CLIENT:ENV,username=john@example.com\n>CLIENT:ENV,common_name=john@example.com\n>CLIENT:ENV,IV_SSO=webauth\n>CLIENT:ENV,END\n")
	scanner := bufio.NewScanner(input)

	event, err := ReadEvent(scanner, ">CLIENT:CONNECT,3,1")
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Type != EventConnect {
		t.Fatalf("event.Type = %q", event.Type)
	}
	if event.CID != "3" || event.KID != "1" {
		t.Fatalf("CID/KID = %s/%s", event.CID, event.KID)
	}
	if got := event.Env["IV_SSO"]; got != "webauth" {
		t.Fatalf("IV_SSO = %q", got)
	}
}

func TestReadDisconnectEvent(t *testing.T) {
	input := strings.NewReader(">CLIENT:ENV,time_duration=3600\n>CLIENT:ENV,END\n")
	event, err := ReadEvent(bufio.NewScanner(input), ">CLIENT:DISCONNECT,7")
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Type != EventDisconnect || event.CID != "7" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestReadAddressEventIgnored(t *testing.T) {
	// >CLIENT:ADDRESS is a single-line notification — no ENV block follows.
	// ReadEvent must return immediately without consuming further input.
	input := strings.NewReader(">CLIENT:CONNECT,3,1\n>CLIENT:ENV,END\n")
	scanner := bufio.NewScanner(input)

	event, err := ReadEvent(scanner, ">CLIENT:ADDRESS,3,10.8.0.2,1")
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Type != EventIgnored {
		t.Fatalf("event.Type = %q, want EventIgnored", event.Type)
	}

	// The scanner must still have the CONNECT event available.
	if !scanner.Scan() {
		t.Fatal("expected next line to be available after ADDRESS event")
	}
	if got := scanner.Text(); got != ">CLIENT:CONNECT,3,1" {
		t.Fatalf("next line = %q", got)
	}
}

func TestReadEstablishedEvent(t *testing.T) {
	// >CLIENT:ESTABLISHED has an ENV block, just like CONNECT/DISCONNECT.
	input := strings.NewReader(">CLIENT:ENV,time_unix=1234567890\n>CLIENT:ENV,END\n")
	scanner := bufio.NewScanner(input)

	event, err := ReadEvent(scanner, ">CLIENT:ESTABLISHED,5")
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Type != EventEstablished {
		t.Fatalf("event.Type = %q, want EventEstablished", event.Type)
	}
	if event.CID != "5" {
		t.Fatalf("CID = %q, want 5", event.CID)
	}
}
