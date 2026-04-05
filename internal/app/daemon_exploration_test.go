package app

// BugConditionExploration: F4
//
// This file contains a bug condition exploration test that is EXPECTED TO FAIL
// on unfixed code. The failure confirms the bug exists.
//
// F4 Bug: When --cn-cross-check is enabled, the daemon emits no startup WARN
// about the undocumented requirement that the external IdP must map its email
// attribute to the same value as the OpenVPN certificate CN. Operators are
// left unaware of a silent misconfiguration that denies all federated users
// with "Certificate Mismatch".
//
// Counterexample found on unfixed code (actual test output):
//   BUG F4 CONFIRMED: daemon.Run did not emit WARN log when CNCrossCheck=true;
//   expected slog.Warn about cn-cross-check federation requirement
//
// Root cause: daemon.Run has no slog.Warn call guarded by cfg.CNCrossCheck.

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/callback"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/secrets"
)

// TestBugCondition_F4_NoCNCrossCheckWarn demonstrates that daemon.Run does NOT
// emit a WARN log when cfg.CNCrossCheck=true on unfixed code.
//
// On UNFIXED code: no WARN is emitted → test FAILS (expected outcome).
// On FIXED code:   WARN is emitted before the port-bind error → test PASSES.
//
// Validates: Requirements 1.4, 2.4
func TestBugCondition_F4_NoCNCrossCheckWarn(t *testing.T) {
	// Capture slog output by redirecting the default logger to a buffer.
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))
	defer slog.SetDefault(slog.New(origHandler))

	// Occupy a port so daemon.Run fails fast on net.Listen (port-bind error).
	// This lets us observe whether the WARN was emitted BEFORE the bind attempt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := config.Config{
		ManagementSocket:       "/tmp/nonexistent-f4.sock",
		ManagementPasswordFile: "/tmp/nonexistent-f4-pw",
		CallbackPort:           port,
		CNCrossCheck:           true, // this is the bug condition
		HandWindow:             300 * time.Second,
		AuthTimeout:            270 * time.Second,
		ReconnectMaxInterval:   1 * time.Second,
		LogFormat:              "text",
	}

	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sessions := auth.NewSessionStore()
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := auth.NewHandler(cfg, sessions, nil, signer, m)

	cbSrv, err := callback.NewServer(
		sessions, signer,
		&DaemonSink{CmdCh: make(chan string, 1)},
		handler, cfg, m, nil,
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	daemon := New(cfg, handler, sessions, cbSrv, m)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run will fail fast with a port-bind error. We only care about what was
	// logged BEFORE that error.
	_ = daemon.Run(ctx)

	logged := buf.String()

	// On unfixed code: no WARN about cn-cross-check → test FAILS (expected).
	// On fixed code:   WARN is present → test PASSES.
	if !strings.Contains(logged, "cn-cross-check") {
		t.Errorf("BUG F4 CONFIRMED: daemon.Run did not emit WARN log when CNCrossCheck=true; expected slog.Warn mentioning 'cn-cross-check'")
		t.Logf("  Captured slog output: %q", logged)
	}
	if !strings.Contains(strings.ToLower(logged), "federation") && !strings.Contains(strings.ToLower(logged), "federat") {
		t.Errorf("BUG F4 CONFIRMED: WARN log does not mention federation requirement; logged: %q", logged)
	}
}
