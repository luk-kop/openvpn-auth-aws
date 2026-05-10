package app

import "testing"

func TestRedactManagementRawLinePasswordEnv(t *testing.T) {
	line := ">CLIENT:ENV,password=super-secret"
	got := redactManagementRawLine(line)
	want := ">CLIENT:ENV,password=[REDACTED]"
	if got != want {
		t.Fatalf("redacted line = %q, want %q", got, want)
	}
}

func TestRedactManagementRawLineStateQuery(t *testing.T) {
	line := `MANAGEMENT: CMD 'client-pending-auth 0 1 "WEB_AUTH::https://vpn.example.com/callback?state=abc.def&x=1" 300'`
	got := redactManagementRawLine(line)
	want := `MANAGEMENT: CMD 'client-pending-auth 0 1 "WEB_AUTH::https://vpn.example.com/callback?state=[REDACTED]&x=1" 300'`
	if got != want {
		t.Fatalf("redacted line = %q, want %q", got, want)
	}
}

func TestRedactManagementRawLineNoSensitiveValue(t *testing.T) {
	line := ">CLIENT:ENV,common_name=user@example.com"
	if got := redactManagementRawLine(line); got != line {
		t.Fatalf("redacted line = %q, want unchanged %q", got, line)
	}
}
