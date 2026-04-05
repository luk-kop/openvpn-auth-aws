package mgmt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type Client struct {
	conn    net.Conn
	scanner *bufio.Scanner
}

func Dial(ctx context.Context, socketPath, passwordFile string, maxBackoff time.Duration) (*Client, error) {
	backoff := 100 * time.Millisecond
	for {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		if err == nil {
			client := &Client{
				conn:    conn,
				scanner: bufio.NewScanner(conn),
			}
			if err := client.authenticate(passwordFile); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return client, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Client) Scanner() *bufio.Scanner {
	return c.scanner
}

func (c *Client) WriteLine(line string) error {
	_, err := fmt.Fprintf(c.conn, "%s\n", line)
	return err
}

func (c *Client) authenticate(passwordFile string) error {
	passwordBytes, err := os.ReadFile(passwordFile)
	if err != nil {
		return fmt.Errorf("read management password: %w", err)
	}
	password := strings.TrimSpace(string(passwordBytes))
	if password == "" {
		return fmt.Errorf("management password file is empty")
	}

	// Probe for password prompt (first 15 bytes)
	if err := c.conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	buf := make([]byte, 15)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return fmt.Errorf("read password prompt: %w", err)
	}
	if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear read deadline: %w", err)
	}

	if string(buf) != "ENTER PASSWORD:" {
		// No password required — the 15 bytes we consumed are part of the
		// first protocol message. Rebuild the scanner with those bytes
		// prepended so the message is not lost.
		c.scanner = bufio.NewScanner(io.MultiReader(bytes.NewReader(buf), c.conn))
		return nil
	}

	if err := c.WriteLine(password); err != nil {
		return fmt.Errorf("write management password: %w", err)
	}

	// Read SUCCESS response
	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return fmt.Errorf("read auth response: %w", err)
		}
		return fmt.Errorf("socket closed before auth response")
	}
	line := c.scanner.Text()
	if !strings.HasPrefix(line, "SUCCESS:") {
		return fmt.Errorf("management authentication failed: %s", line)
	}

	return nil
}
