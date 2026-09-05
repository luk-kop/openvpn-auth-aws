package mgmt

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzReadEvent(f *testing.F) {
	f.Add(">CLIENT:CONNECT,3,1", []byte(">CLIENT:ENV,username=user@example.com\n>CLIENT:ENV,END\n"))
	f.Add(">CLIENT:REAUTH,3,2,extra", []byte(">CLIENT:ENV,common_name=user@example.com\n>CLIENT:ENV,END\n"))
	f.Add(">CLIENT:DISCONNECT,7", []byte(">CLIENT:ENV,time_duration=10\n>CLIENT:ENV,END\n"))
	f.Add(">CLIENT:ESTABLISHED,8", []byte(">CLIENT:ENV,END\n"))
	f.Add(">CLIENT:ADDRESS,8,10.8.0.2,1", []byte{})
	f.Add(">CLIENT:FUTURE,8", []byte(">CLIENT:ENV,key=value\n>CLIENT:ENV,END\n"))
	f.Add("invalid", []byte{0xff, '\n'})

	f.Fuzz(func(t *testing.T, header string, body []byte) {
		typ, cid, kid, err := ParseHeader(header)
		if err == nil {
			assertValidEventFields(t, typ, cid, kid)
		}

		event, err := ReadEvent(bufio.NewScanner(bytes.NewReader(body)), header)
		if err != nil {
			return
		}
		if event.Env == nil {
			t.Fatal("ReadEvent returned a nil environment map")
		}
		if event.Type == EventUnknown {
			t.Fatal("ReadEvent returned an unconsumed unknown event")
		}
		assertValidEventFields(t, event.Type, event.CID, event.KID)
	})
}

func assertValidEventFields(t *testing.T, typ EventType, cid, kid string) {
	t.Helper()

	switch typ {
	case EventConnect, EventReauth:
		if cid == "" || kid == "" {
			t.Fatalf("%s event has empty cid/kid: %q/%q", typ, cid, kid)
		}
	case EventDisconnect, EventEstablished:
		if cid == "" || kid != "" {
			t.Fatalf("%s event has invalid cid/kid: %q/%q", typ, cid, kid)
		}
	case EventIgnored, EventUnknown:
		if cid != "" || kid != "" {
			t.Fatalf("%s event has unexpected cid/kid: %q/%q", typ, cid, kid)
		}
	default:
		t.Fatalf("unknown event type %q", typ)
	}
}
