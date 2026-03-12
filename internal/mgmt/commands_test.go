package mgmt

import "testing"

func TestClientPendingAuth(t *testing.T) {
	got := ClientPendingAuth("1", "2", "https://example.com/auth", 300)
	want := `client-pending-auth 1 2 "WEB_AUTH::https://example.com/auth" 300`
	if got != want {
		t.Fatalf("ClientPendingAuth() = %q, want %q", got, want)
	}
}

func TestClientAuth(t *testing.T) {
	got := ClientAuth("1", "2")
	if got[0] != "client-auth 1 2" {
		t.Fatalf("ClientAuth()[0] = %q", got[0])
	}
	if got[1] != "END" {
		t.Fatalf("ClientAuth()[1] = %q", got[1])
	}
}

func TestClientAuthNT(t *testing.T) {
	if got := ClientAuthNT("1", "2"); got != "client-auth-nt 1 2" {
		t.Fatalf("ClientAuthNT() = %q", got)
	}
}

func TestClientDeny(t *testing.T) {
	if got := ClientDeny("1", "2", "auth timeout"); got != `client-deny 1 2 "auth timeout"` {
		t.Fatalf("ClientDeny() = %q", got)
	}
}

func TestClientDenyEmptyReason(t *testing.T) {
	got := ClientDeny("1", "2", "")
	want := `client-deny 1 2 "denied"`
	if got != want {
		t.Fatalf("ClientDeny() with empty reason = %q, want %q", got, want)
	}
}

func TestClientKill(t *testing.T) {
	if got := ClientKill("3"); got != "client-kill 3" {
		t.Fatalf("ClientKill() = %q", got)
	}
}
