package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/callback"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/metrics"
	"openvpn-auth-aws/internal/mgmt"
	"openvpn-auth-aws/internal/secrets"
)

// TestRunFailsWhenCallbackPortBusy verifies that Run returns an error
// immediately when the callback port is already in use, rather than
// continuing in a broken state where auth flows silently time out.
func TestRunFailsWhenCallbackPortBusy(t *testing.T) {
	// Occupy a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	port := ln.Addr().(*net.TCPAddr).Port

	cfg := config.Config{
		ManagementSocket:       "/tmp/nonexistent.sock",
		ManagementPasswordFile: "/tmp/nonexistent-pw",
		CallbackPort:           port,
		HandWindow:             300 * time.Second,
		AuthTimeout:            270 * time.Second,
		ReconnectMaxInterval:   1 * time.Second,
		LogFormat:              "text",
	}

	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sessions := auth.NewSessionStore()
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := auth.NewHandler(cfg, sessions, nil, signer, m)

	cbSrv, err := callback.NewServer(sessions, signer, &DaemonSink{cmdCh: make(chan queuedCommand, 1)}, handler, cfg, m, nil, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	daemon := New(cfg, handler, sessions, cbSrv, m)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = daemon.Run(ctx)
	if err == nil {
		t.Fatal("expected Run to return error when callback port is busy")
	}
	if !strings.Contains(err.Error(), "listen") && !strings.Contains(err.Error(), "bind") {
		t.Fatalf("expected listen/bind error, got: %v", err)
	}
}

// TestReconnectWriterLifecycle verifies that after a management socket
// disconnect, the old commandWriter terminates and does not race with
// the new writer for commands on d.cmdCh.
func TestReconnectWriterLifecycle(t *testing.T) {
	socketPath := t.TempDir() + "/mgmt.sock"
	pwFile := t.TempDir() + "/pw"
	if err := writeFile(pwFile, "testpassword1234"); err != nil {
		t.Fatalf("write pw file: %v", err)
	}

	// Start a mock management server that accepts two connections.
	serverLn, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = serverLn.Close() }()

	conn1Cmds := make(chan []string, 1)
	conn2Cmds := make(chan []string, 1)

	go func() {
		// Connection 1: accept, send password prompt, accept auth, then close.
		conn, err := serverLn.Accept()
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(conn, "ENTER PASSWORD:")
		buf := make([]byte, 256)
		_, _ = conn.Read(buf) // read password
		_, _ = fmt.Fprintf(conn, "SUCCESS: password is correct\n")
		// Read commands until connection closes.
		var cmds []string
		scanner := newLineScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			cmds = append(cmds, line)
			if strings.TrimSpace(line) == "status 3" {
				_, _ = fmt.Fprintf(conn, "TITLE,OpenVPN 2.6 mock\n")
				_, _ = fmt.Fprintf(conn, "HEADER,CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since (time_t),Username,Client ID,Peer ID\n")
				_, _ = fmt.Fprintf(conn, "END\n")
			}
		}
		_ = conn.Close()
		conn1Cmds <- cmds

		// Connection 2: accept, send password prompt, accept auth, read commands.
		conn2, err := serverLn.Accept()
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(conn2, "ENTER PASSWORD:")
		buf2 := make([]byte, 256)
		_, _ = conn2.Read(buf2)
		_, _ = fmt.Fprintf(conn2, "SUCCESS: password is correct\n")
		var cmds2 []string
		scanner2 := newLineScanner(conn2)
		for scanner2.Scan() {
			line := scanner2.Text()
			cmds2 = append(cmds2, line)
			if strings.TrimSpace(line) == "status 3" {
				_, _ = fmt.Fprintf(conn2, "TITLE,OpenVPN 2.6 mock\n")
				_, _ = fmt.Fprintf(conn2, "HEADER,CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since (time_t),Username,Client ID,Peer ID\n")
				_, _ = fmt.Fprintf(conn2, "END\n")
			}
		}
		_ = conn2.Close()
		conn2Cmds <- cmds2
	}()

	cfg := config.Config{
		ManagementSocket:       socketPath,
		ManagementPasswordFile: pwFile,
		CallbackPort:           0, // not used in this test
		HandWindow:             300 * time.Second,
		AuthTimeout:            270 * time.Second,
		ReconnectMaxInterval:   100 * time.Millisecond,
		LogFormat:              "text",
	}

	signer, _ := secrets.NewStaticSigner("test-secret-key!!")
	sessions := auth.NewSessionStore()
	m := metrics.NewEmitter(&strings.Builder{}, "test")
	handler := auth.NewHandler(cfg, sessions, nil, signer, m)

	// Use a real listener on port 0 so Run doesn't fail on bind.
	cbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cb listen: %v", err)
	}
	defer func() { _ = cbLn.Close() }()

	cbSrv, err := callback.NewServer(sessions, signer, &DaemonSink{cmdCh: make(chan queuedCommand, 256)}, handler, cfg, m, nil, func() bool { return true })
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	daemon := New(cfg, handler, sessions, cbSrv, m)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We can't easily use daemon.Run() here because it binds the callback
	// port. Instead, test handleConnection directly.

	// Connection 1: dial, handle, then disconnect.
	client1, err := mgmt.Dial(ctx, socketPath, pwFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}

	// handleConnection in a goroutine; it will return when conn1 closes.
	conn1Done := make(chan error, 1)
	go func() {
		_, err := daemon.handleConnection(ctx, client1)
		conn1Done <- err
	}()

	// Give writer time to send "hold release".
	time.Sleep(100 * time.Millisecond)

	// Close first connection from server side (simulates disconnect).
	// The server goroutine will close conn and send cmds to conn1Cmds.
	// Wait for handleConnection to finish.
	select {
	case err := <-conn1Done:
		_ = err // normal disconnect
	case <-time.After(3 * time.Second):
		t.Fatal("handleConnection did not return after disconnect")
	}
	_ = client1.Close()

	// At this point, the old commandWriter should have terminated.
	// Verify by checking that we can proceed to connection 2 without
	// the old writer stealing commands.

	// Connection 2.
	client2, err := mgmt.Dial(ctx, socketPath, pwFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}

	conn2Done := make(chan error, 1)
	go func() {
		_, err := daemon.handleConnection(ctx, client2)
		conn2Done <- err
	}()

	// Give time for hold release + hold response processing.
	time.Sleep(200 * time.Millisecond)

	// Cancel context to end connection 2 cleanly.
	cancel()

	select {
	case <-conn2Done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConnection 2 did not return")
	}
	_ = client2.Close()

	// Verify connection 1 received "hold release" command.
	select {
	case cmds := <-conn1Cmds:
		found := false
		for _, c := range cmds {
			if strings.Contains(c, "hold release") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("connection 1 did not receive 'hold release', got: %v", cmds)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for conn1 commands")
	}

	// Verify connection 2 also received its own "hold release".
	select {
	case cmds := <-conn2Cmds:
		found := false
		for _, c := range cmds {
			if strings.Contains(c, "hold release") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("connection 2 did not receive 'hold release', got: %v", cmds)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for conn2 commands")
	}
}

func TestDecisionSinkForwardsKillMode(t *testing.T) {
	cmdCh := make(chan queuedCommand, 1)
	sink := decisionSink{cmdCh: cmdCh, done: make(chan struct{})}

	err := sink.Send(auth.Decision{Type: auth.DecisionKill, CID: "3", KillMode: "HALT"})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case queued := <-cmdCh:
		if queued.cmd != "client-kill 3 HALT" {
			t.Fatalf("forwarded command = %q", queued.cmd)
		}
	default:
		t.Fatal("expected forwarded command")
	}
}

func TestDaemonSinkForwardsDefaultKill(t *testing.T) {
	cmdCh := make(chan queuedCommand, 1)
	sink := DaemonSink{cmdCh: cmdCh}

	err := sink.Send(auth.Decision{Type: auth.DecisionKill, CID: "3"})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case queued := <-cmdCh:
		if queued.cmd != "client-kill 3" {
			t.Fatalf("forwarded command = %q", queued.cmd)
		}
	default:
		t.Fatal("expected forwarded command")
	}
}

func TestDaemonSinkSendAckWaitsForCommandResult(t *testing.T) {
	cmdCh := make(chan queuedCommand, 1)
	sink := DaemonSink{cmdCh: cmdCh}
	writeErr := errors.New("write failed")

	done := make(chan error, 1)
	go func() {
		done <- sink.SendAck(auth.Decision{Type: auth.DecisionAllow, CID: "3", KID: "7"})
	}()

	select {
	case queued := <-cmdCh:
		if queued.cmd != "client-auth 3 7\nEND" {
			t.Fatalf("queued command = %q", queued.cmd)
		}
		if queued.ack == nil {
			t.Fatal("expected ack channel")
		}
		queued.ack <- writeErr
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for queued command")
	}

	select {
	case err := <-done:
		if !errors.Is(err, writeErr) {
			t.Fatalf("SendAck() error = %v, want %v", err, writeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SendAck did not return after ack")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

func newLineScanner(conn net.Conn) *lineScanner {
	return &lineScanner{conn: conn}
}

type lineScanner struct {
	conn net.Conn
	buf  []byte
	text string
}

func (s *lineScanner) Scan() bool {
	_ = s.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tmp := make([]byte, 1)
	s.buf = s.buf[:0]
	for {
		n, err := s.conn.Read(tmp)
		if n > 0 {
			if tmp[0] == '\n' {
				s.text = string(s.buf)
				return true
			}
			s.buf = append(s.buf, tmp[0])
		}
		if err != nil {
			if len(s.buf) > 0 {
				s.text = string(s.buf)
				return true
			}
			return false
		}
	}
}

func (s *lineScanner) Text() string {
	return s.text
}

// TestPreservation_NoCNCrossCheckWarn verifies that daemon.Run does NOT emit
// a federation WARN log when cfg.CNCrossCheck=false.
//
// On unfixed code: no WARN is emitted (CNCrossCheck=false) — test PASSES.
// On fixed code:   WARN is only emitted when CNCrossCheck=true — test still PASSES.
//
// Property: for all daemon startups where cfg.CNCrossCheck=false, no federation
// WARN about cn-cross-check is emitted.
//
// EXPECTED OUTCOME: PASSES on unfixed code (baseline behavior to preserve).
//
// Validates: Requirements 3.7
func TestPreservation_NoCNCrossCheckWarn(t *testing.T) {
	// Capture slog output by redirecting the default logger to a buffer.
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))
	defer slog.SetDefault(slog.New(origHandler))

	// Occupy a port so daemon.Run fails fast on net.Listen (port-bind error).
	// This lets us observe whether any WARN was emitted BEFORE the bind attempt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := config.Config{
		ManagementSocket:       "/tmp/nonexistent-pres.sock",
		ManagementPasswordFile: "/tmp/nonexistent-pres-pw",
		CallbackPort:           port,
		CNCrossCheck:           false, // preservation: no WARN expected
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
		&DaemonSink{cmdCh: make(chan queuedCommand, 1)},
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

	// Preservation: when CNCrossCheck=false, no federation WARN must be emitted.
	if strings.Contains(logged, "cn-cross-check") {
		t.Errorf("Preservation FAILED: daemon.Run emitted cn-cross-check WARN when CNCrossCheck=false; logged: %q", logged)
	}
}
