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
