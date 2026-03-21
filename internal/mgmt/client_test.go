package mgmt

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestDialNoPasswordPrompt_Hold verifies that when the management socket
// does not send a password prompt (first bytes are not "ENTER PASSWORD:"),
// the consumed bytes are prepended back so the scanner sees the full first
// line. This tests the io.MultiReader fix in authenticate().
func TestDialNoPasswordPrompt_Hold(t *testing.T) {
	socketPath := t.TempDir() + "/mgmt.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Server goroutine: send >HOLD: as the very first line (no password prompt).
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(conn, ">HOLD:Waiting for hold release\n")
		// Keep connection open until client reads.
		buf := make([]byte, 256)
		conn.Read(buf) //nolint:errcheck
	}()

	// Create a dummy password file (required by Dial, but content doesn't matter
	// since the server won't ask for a password).
	pwFile := t.TempDir() + "/pw"
	if err := writeTestFile(pwFile, "dummypassword123"); err != nil {
		t.Fatalf("write pw: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := Dial(ctx, socketPath, pwFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// The scanner must see the full >HOLD: line despite the first 15 bytes
	// having been consumed during password-prompt detection.
	scanner := client.Scanner()
	if !scanner.Scan() {
		t.Fatalf("expected scanner to return a line, got err: %v", scanner.Err())
	}
	line := scanner.Text()
	if line != ">HOLD:Waiting for hold release" {
		t.Fatalf("expected >HOLD:Waiting for hold release, got: %q", line)
	}
}

// TestDialNoPasswordPrompt_ClientEvent verifies the same io.MultiReader fix
// with a >CLIENT: event as the first line.
func TestDialNoPasswordPrompt_ClientEvent(t *testing.T) {
	socketPath := t.TempDir() + "/mgmt.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	firstLine := ">CLIENT:CONNECT,1,2"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fprintf(conn, "%s\n", firstLine)
		buf := make([]byte, 256)
		conn.Read(buf) //nolint:errcheck
	}()

	pwFile := t.TempDir() + "/pw"
	if err := writeTestFile(pwFile, "dummypassword123"); err != nil {
		t.Fatalf("write pw: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := Dial(ctx, socketPath, pwFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	scanner := client.Scanner()
	if !scanner.Scan() {
		t.Fatalf("expected scanner to return a line, got err: %v", scanner.Err())
	}
	got := scanner.Text()
	if got != firstLine {
		t.Fatalf("expected %q, got: %q", firstLine, got)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
