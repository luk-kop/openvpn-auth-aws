// mgmt-mock simulates the OpenVPN management interface on a Unix socket.
// It accepts daemon connections, handles password auth, sends >HOLD:
// notification, and lets you send CLIENT events interactively from stdin.
//
// Usage:
//
//	go run ./cmd/mgmt-mock
//
// Then type commands like:
//
//	connect 3 john@example.com             — CLIENT:CONNECT with IV_SSO=webauth
//	connect 3 john@example.com openurl     — CLIENT:CONNECT with IV_SSO=openurl
//	connect 3 john@example.com webauth token123 — CLIENT:CONNECT with password field
//	reauth  3 john@example.com             — CLIENT:REAUTH event
//	disconnect 3                           — CLIENT:DISCONNECT event
//	sso openurl                            — change default IV_SSO for next events
//	hold                                   — send >HOLD: notification
//	quit                                   — exit
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	socketPath   = "/tmp/openvpn-mgmt.sock"
	passwordFile = "/tmp/mgmt-pw"
)

// nextKID auto-increments per CID to simulate TLS renegotiation.
var (
	cidKID   = make(map[string]int)
	cidKIDMu sync.Mutex
)

func nextKID(cid string) string {
	cidKIDMu.Lock()
	defer cidKIDMu.Unlock()
	cidKID[cid]++
	return fmt.Sprintf("%d", cidKID[cid])
}

func resetKID(cid string) {
	cidKIDMu.Lock()
	defer cidKIDMu.Unlock()
	delete(cidKID, cid)
}

func main() {
	// Read expected password, create file with default if missing.
	pwBytes, err := os.ReadFile(passwordFile)
	if os.IsNotExist(err) {
		pwBytes = []byte("test-password\n")
		if err := os.WriteFile(passwordFile, pwBytes, 0600); err != nil {
			log.Fatalf("cannot create %s: %v", passwordFile, err)
		}
		log.Printf("Created %s with default password", passwordFile)
	} else if err != nil {
		log.Fatalf("cannot read %s: %v", passwordFile, err)
	}
	expectedPw := strings.TrimSpace(string(pwBytes))
	if expectedPw == "" {
		log.Fatalf("%s is empty", passwordFile)
	}

	// Clean up stale socket.
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			log.Printf("ln.Close: %v", err)
		}
	}()
	log.Printf("Listening on %s (password from %s)", socketPath, passwordFile)

	// Default IV_SSO value for connect events — shared across reconnections.
	defaultSSO := "webauth"

	// --- Interactive prompt runs in the foreground; connections are handled in background ---
	printHelp()
	stdin := bufio.NewScanner(os.Stdin)

	// connMu guards the active conn so the stdin loop can write to it safely.
	var connMu sync.Mutex
	var activeConn net.Conn
	var disconnected atomic.Bool

	// Accept loop: re-accepts after each daemon reconnect.
	go func() {
		for {
			log.Println("Waiting for daemon to connect...")
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				return
			}
			log.Println("Daemon connected")
			disconnected.Store(false)

			connMu.Lock()
			activeConn = conn
			connMu.Unlock()

			scanner := bufio.NewScanner(conn)

			// Password handshake
			if expectedPw != "" {
				if _, err := fmt.Fprintf(conn, "ENTER PASSWORD:"); err != nil {
					log.Printf("write prompt: %v", err)
					_ = conn.Close()
					continue
				}
				if !scanner.Scan() {
					log.Println("daemon disconnected before sending password")
					_ = conn.Close()
					continue
				}
				got := scanner.Text()
				if got != expectedPw {
					_, _ = fmt.Fprintf(conn, "ERROR: bad password\r\n")
					_ = conn.Close()
					log.Printf("bad password: got %q", got)
					continue
				}
				if _, err := fmt.Fprintf(conn, "SUCCESS: password is correct\r\n"); err != nil {
					log.Printf("write success: %v", err)
					_ = conn.Close()
					continue
				}
				log.Println("Auth OK")
			}

			// Send >HOLD: notification
			_, _ = fmt.Fprintf(conn, ">HOLD:Waiting for hold release:0\r\n")
			log.Println(">> sent >HOLD: notification")

			// Read daemon responses
			for scanner.Scan() {
				line := scanner.Text()
				log.Printf("<< daemon: %s", line)

				if strings.HasPrefix(line, "client-auth ") || strings.HasPrefix(line, "client-auth-nt ") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						cid := fields[1]
						if strings.HasPrefix(line, "client-auth ") {
							for scanner.Scan() {
								inner := scanner.Text()
								log.Printf("<< daemon (auth-block): %s", inner)
								if inner == "END" {
									break
								}
							}
						}
						_, _ = fmt.Fprintf(conn, ">CLIENT:ESTABLISHED,%s\r\n", cid)
						_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,time_unix=1234567890\r\n")
						_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,END\r\n")
						_, _ = fmt.Fprintf(conn, ">CLIENT:ADDRESS,%s,10.8.0.2,1\r\n", cid)
						log.Printf(">> auto ESTABLISHED+ADDRESS cid=%s", cid)
					}
				}
			}

			disconnected.Store(true)
			connMu.Lock()
			activeConn = nil
			connMu.Unlock()
			_ = conn.Close()
			log.Println("Daemon disconnected — waiting for reconnect...")
		}
	}()

	fmt.Print("> ")
	for stdin.Scan() {
		line := strings.TrimSpace(stdin.Text())
		if line == "" {
			fmt.Print("> ")
			continue
		}

		connMu.Lock()
		conn := activeConn
		connMu.Unlock()

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		// quit/help don't need an active connection
		switch cmd {
		case "help":
			printHelp()
			fmt.Print("> ")
			continue
		case "quit", "exit":
			log.Println("Exiting")
			if conn != nil {
				_ = conn.Close()
			}
			return
		}

		if conn == nil {
			log.Println("no daemon connected yet")
			fmt.Print("> ")
			continue
		}

		switch cmd {
		case "connect":
			if len(parts) < 3 {
				log.Println("usage: connect <CID> <username> [sso] [password] [KID]")
				fmt.Print("> ")
				continue
			}
			cid := parts[1]
			username := parts[2]
			sso := defaultSSO
			password := ""
			kid := ""
			if len(parts) >= 4 {
				sso = parts[3]
			}
			if len(parts) >= 5 {
				password = parts[4]
			}
			if len(parts) >= 6 {
				kid = parts[5]
			}
			if kid == "" {
				kid = nextKID(cid)
			}
			sendConnect(conn, cid, kid, username, sso, password)

		case "reauth":
			if len(parts) < 3 {
				log.Println("usage: reauth <CID> <username> [KID]")
				fmt.Print("> ")
				continue
			}
			cid := parts[1]
			username := parts[2]
			kid := ""
			if len(parts) >= 4 {
				kid = parts[3]
			}
			if kid == "" {
				kid = nextKID(cid)
			}
			sendReauth(conn, cid, kid, username)

		case "disconnect":
			if len(parts) < 2 {
				log.Println("usage: disconnect <CID>")
				fmt.Print("> ")
				continue
			}
			cid := parts[1]
			sendDisconnect(conn, cid)
			resetKID(cid)

		case "sso":
			if len(parts) < 2 {
				log.Printf("current IV_SSO default: %s", defaultSSO)
				log.Println("usage: sso <webauth|openurl|openurl,webauth|crtext>")
				fmt.Print("> ")
				continue
			}
			defaultSSO = parts[1]
			log.Printf("IV_SSO default set to: %s", defaultSSO)

		case "hold":
			_, _ = fmt.Fprintf(conn, ">HOLD:Waiting for hold release:0\r\n")
			log.Println(">> sent >HOLD: notification")

		default:
			log.Printf("unknown command: %s (type 'help')", cmd)
		}
		fmt.Print("> ")
	}
}

func sendConnect(conn net.Conn, cid, kid, username, sso, password string) {
	_, _ = fmt.Fprintf(conn, ">CLIENT:CONNECT,%s,%s\r\n", cid, kid)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,username=%s\r\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,common_name=%s\r\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,IV_SSO=%s\r\n", sso)
	if password != "" {
		_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,password=%s\r\n", password)
	}
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,untrusted_ip=10.0.0.2\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,untrusted_port=51234\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,IV_VER=2.6.12\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,IV_PLAT=linux\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,END\r\n")
	extra := ""
	if password != "" {
		extra = fmt.Sprintf(" password=%s", password)
	}
	log.Printf(">> CONNECT cid=%s kid=%s user=%s sso=%s%s", cid, kid, username, sso, extra)
}

func sendReauth(conn net.Conn, cid, kid, username string) {
	_, _ = fmt.Fprintf(conn, ">CLIENT:REAUTH,%s,%s\r\n", cid, kid)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,username=%s\r\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,common_name=%s\r\n", username)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,IV_SSO=webauth\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,END\r\n")
	log.Printf(">> REAUTH cid=%s kid=%s user=%s", cid, kid, username)
}

func sendDisconnect(conn net.Conn, cid string) {
	_, _ = fmt.Fprintf(conn, ">CLIENT:DISCONNECT,%s\r\n", cid)
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,time_duration=120\r\n")
	_, _ = fmt.Fprintf(conn, ">CLIENT:ENV,END\r\n")
	log.Printf(">> DISCONNECT cid=%s", cid)
}

func printHelp() {
	fmt.Println(`
Commands:
  connect    <CID> <user> [sso] [password] [KID]
             — CLIENT:CONNECT event
               sso: webauth (default), openurl, openurl,webauth, crtext
               password: auth-gen-token value (omit for WebAuth flow)
               KID: auto-increments per CID if omitted

  reauth     <CID> <user> [KID]
             — CLIENT:REAUTH event (TLS renegotiation)

  disconnect <CID>
             — CLIENT:DISCONNECT event (resets KID counter)

  sso <value>  — set default IV_SSO for future connect events
  hold         — send >HOLD: notification (daemon responds with "hold release")
  help         — show this help
  quit         — close connection and exit

Examples:
  connect 1 alice@example.com                  — standard WebAuth connect
  connect 2 bob@example.com openurl            — connect with IV_SSO=openurl
  connect 1 alice@example.com webauth mytoken  — token reconnect (password field)
  reauth 1 alice@example.com                   — TLS reauth for CID=1
  disconnect 1                                 — client disconnected`)
}
