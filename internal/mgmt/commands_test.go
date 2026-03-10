package mgmt

import "testing"

func TestCommands(t *testing.T) {
	if got := ClientPendingAuth("1", "2", "https://example.com/auth", 300); got != `client-pending-auth 1 2 "WEB_AUTH::https://example.com/auth" 300` {
		t.Fatalf("ClientPendingAuth() = %q", got)
	}
	if got := ClientAuth("1", "2"); got != "client-auth 1 2\nEND" {
		t.Fatalf("ClientAuth() = %q", got)
	}
	if got := ClientAuthNT("1", "2"); got != "client-auth-nt 1 2" {
		t.Fatalf("ClientAuthNT() = %q", got)
	}
	if got := ClientDeny("1", "2", "auth timeout"); got != `client-deny 1 2 "auth timeout"` {
		t.Fatalf("ClientDeny() = %q", got)
	}
}
