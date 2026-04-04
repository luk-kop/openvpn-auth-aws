package mgmt

// BugConditionExploration: M17
//
// This file contains a bug condition exploration test that is EXPECTED TO FAIL
// on unfixed code. The failure confirms the bug exists.
//
// Bug: ParseHeader for DISCONNECT and ESTABLISHED uses TrimSpace(TrimPrefix(...))
// without splitting on commas. If the line contains trailing comma-separated fields
// (e.g. ">CLIENT:DISCONNECT,42,extra"), the CID includes the trailing data ("42,extra")
// instead of just the first field ("42").
//
// Counterexample found on unfixed code (actual test output):
//   BUG M17 CONFIRMED: ParseHeader(">CLIENT:DISCONNECT,42,extra") returned CID="42,extra";
//   expected "42" (only the first comma-delimited field)
//   BUG M17 CONFIRMED: ParseHeader(">CLIENT:ESTABLISHED,42,extra") returned CID="42,extra";
//   expected "42" (only the first comma-delimited field)
//
// Root cause: DISCONNECT and ESTABLISHED branches use TrimSpace(TrimPrefix(...)) without
// splitting on commas, unlike parseCIDKID which correctly splits on commas.

import (
	"testing"
)

// TestBugCondition_M17_DisconnectTrailingField demonstrates that ParseHeader
// returns the full payload (including trailing comma-separated fields) as the CID
// for DISCONNECT events, instead of only the first comma-delimited field.
//
// On UNFIXED code: CID="42,extra" — test FAILS (expected outcome).
// On FIXED code:   CID="42"       — test PASSES.
//
// Validates: Requirements 1.6, 2.6
func TestBugCondition_M17_DisconnectTrailingField(t *testing.T) {
	line := ">CLIENT:DISCONNECT,42,extra"

	_, cid, _, err := ParseHeader(line)
	if err != nil {
		t.Fatalf("ParseHeader returned unexpected error: %v", err)
	}

	// On unfixed code: cid="42,extra" — this assertion FAILS (expected).
	// On fixed code:   cid="42"       — this assertion PASSES.
	if cid != "42" {
		t.Errorf("BUG M17 CONFIRMED: ParseHeader(%q) returned CID=%q; expected %q (only the first comma-delimited field)", line, cid, "42")
	}
}

// TestBugCondition_M17_EstablishedTrailingField demonstrates the same bug for
// ESTABLISHED events.
//
// On UNFIXED code: CID="42,extra" — test FAILS (expected outcome).
// On FIXED code:   CID="42"       — test PASSES.
//
// Validates: Requirements 1.6, 2.6
func TestBugCondition_M17_EstablishedTrailingField(t *testing.T) {
	line := ">CLIENT:ESTABLISHED,42,extra"

	_, cid, _, err := ParseHeader(line)
	if err != nil {
		t.Fatalf("ParseHeader returned unexpected error: %v", err)
	}

	// On unfixed code: cid="42,extra" — this assertion FAILS (expected).
	// On fixed code:   cid="42"       — this assertion PASSES.
	if cid != "42" {
		t.Errorf("BUG M17 CONFIRMED: ParseHeader(%q) returned CID=%q; expected %q (only the first comma-delimited field)", line, cid, "42")
	}
}
