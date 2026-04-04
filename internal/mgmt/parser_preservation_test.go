package mgmt

// Preservation tests for ParseHeader — Property 2: Non-Buggy Input Behavior
//
// These tests MUST PASS on unfixed code. They document correct baseline behavior
// that must not regress after fixes are applied.
//
// Observed on unfixed code:
//   - ParseHeader(">CLIENT:DISCONNECT,42") returns CID "42" on unfixed code
//
// Property: for all >CLIENT:DISCONNECT,{CID} and >CLIENT:ESTABLISHED,{CID}
// lines with a single CID and no trailing fields, ParseHeader continues to
// parse the CID correctly.
//
// Validates: Requirements 3.5, 3.6

import (
	"testing"
)

// TestPreservation_ParseHeader_DisconnectSingleCID verifies that ParseHeader
// correctly parses a DISCONNECT event with a single CID and no trailing fields.
//
// Property: for all >CLIENT:DISCONNECT,{CID} lines with a single CID,
// ParseHeader returns the correct CID.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.5, 3.6
func TestPreservation_ParseHeader_DisconnectSingleCID(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantCID string
	}{
		{"cid_42", ">CLIENT:DISCONNECT,42", "42"},
		{"cid_1", ">CLIENT:DISCONNECT,1", "1"},
		{"cid_0", ">CLIENT:DISCONNECT,0", "0"},
		{"cid_100", ">CLIENT:DISCONNECT,100", "100"},
		{"cid_999", ">CLIENT:DISCONNECT,999", "999"},
		{"cid_large", ">CLIENT:DISCONNECT,123456", "123456"},
		{"cid_with_spaces", ">CLIENT:DISCONNECT, 42 ", "42"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eventType, cid, kid, err := ParseHeader(tc.line)

			if err != nil {
				t.Fatalf("Preservation FAILED: ParseHeader(%q) returned unexpected error: %v", tc.line, err)
			}
			if eventType != EventDisconnect {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned event type %v; expected EventDisconnect", tc.line, eventType)
			}
			if cid != tc.wantCID {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned CID=%q; expected %q", tc.line, cid, tc.wantCID)
			}
			if kid != "" {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned non-empty KID=%q; expected empty", tc.line, kid)
			}
		})
	}
}

// TestPreservation_ParseHeader_EstablishedSingleCID verifies that ParseHeader
// correctly parses an ESTABLISHED event with a single CID and no trailing fields.
//
// Property: for all >CLIENT:ESTABLISHED,{CID} lines with a single CID,
// ParseHeader returns the correct CID.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.5, 3.6
func TestPreservation_ParseHeader_EstablishedSingleCID(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		wantCID string
	}{
		{"cid_42", ">CLIENT:ESTABLISHED,42", "42"},
		{"cid_1", ">CLIENT:ESTABLISHED,1", "1"},
		{"cid_0", ">CLIENT:ESTABLISHED,0", "0"},
		{"cid_100", ">CLIENT:ESTABLISHED,100", "100"},
		{"cid_999", ">CLIENT:ESTABLISHED,999", "999"},
		{"cid_large", ">CLIENT:ESTABLISHED,123456", "123456"},
		{"cid_with_spaces", ">CLIENT:ESTABLISHED, 42 ", "42"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eventType, cid, kid, err := ParseHeader(tc.line)

			if err != nil {
				t.Fatalf("Preservation FAILED: ParseHeader(%q) returned unexpected error: %v", tc.line, err)
			}
			if eventType != EventEstablished {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned event type %v; expected EventEstablished", tc.line, eventType)
			}
			if cid != tc.wantCID {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned CID=%q; expected %q", tc.line, cid, tc.wantCID)
			}
			if kid != "" {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned non-empty KID=%q; expected empty", tc.line, kid)
			}
		})
	}
}

// TestPreservation_ParseHeader_ConnectAndReauthUnaffected verifies that the
// CONNECT and REAUTH parsing (via parseCIDKID) is unaffected by any changes.
//
// Property: CLIENT:CONNECT and CLIENT:REAUTH CID/KID parsing must be unaffected.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.5
func TestPreservation_ParseHeader_ConnectAndReauthUnaffected(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantType EventType
		wantCID  string
		wantKID  string
	}{
		{"connect", ">CLIENT:CONNECT,42,7", EventConnect, "42", "7"},
		{"connect_cid1", ">CLIENT:CONNECT,1,1", EventConnect, "1", "1"},
		{"connect_large", ">CLIENT:CONNECT,100,200", EventConnect, "100", "200"},
		{"reauth", ">CLIENT:REAUTH,42,7", EventReauth, "42", "7"},
		{"reauth_cid1", ">CLIENT:REAUTH,1,1", EventReauth, "1", "1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			eventType, cid, kid, err := ParseHeader(tc.line)

			if err != nil {
				t.Fatalf("Preservation FAILED: ParseHeader(%q) returned unexpected error: %v", tc.line, err)
			}
			if eventType != tc.wantType {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned event type %v; expected %v", tc.line, eventType, tc.wantType)
			}
			if cid != tc.wantCID {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned CID=%q; expected %q", tc.line, cid, tc.wantCID)
			}
			if kid != tc.wantKID {
				t.Errorf("Preservation FAILED: ParseHeader(%q) returned KID=%q; expected %q", tc.line, kid, tc.wantKID)
			}
		})
	}
}
