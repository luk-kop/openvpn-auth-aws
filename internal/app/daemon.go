package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/callback"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/mgmt"
)

type Daemon struct {
	cfg            config.Config
	handler        *auth.Handler
	sessions       *auth.SessionStore
	metrics        auth.Metrics
	callbackServer *callback.Server

	// cmdCh lives at daemon level so the callback server can write decisions
	// to the management socket even across reconnections.
	cmdCh chan string

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	socketConnected atomic.Bool
}

type decisionSink struct {
	cmdCh chan<- string
	done  <-chan struct{}
}

func (s decisionSink) Send(d auth.Decision) error {
	switch d.Type {
	case auth.DecisionAllow:
		return s.sendOne(mgmt.ClientAuth(d.CID, d.KID))
	case auth.DecisionAllowNT:
		return s.sendOne(mgmt.ClientAuthNT(d.CID, d.KID))
	case auth.DecisionDeny:
		return s.sendOne(mgmt.ClientDeny(d.CID, d.KID, d.Reason))
	case auth.DecisionPending:
		return s.sendOne(mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout))
	case auth.DecisionKill:
		return s.sendOne(mgmt.ClientKill(d.CID))
	}
	return nil
}

func (s decisionSink) sendOne(cmd string) error {
	select {
	case s.cmdCh <- cmd:
		return nil
	case <-s.done:
		return fmt.Errorf("command dropped: connection closed")
	}
}

// DaemonSink is the DecisionSink backed by the daemon-level cmdCh.
// It never blocks on a "done" channel — the daemon manages its own lifecycle.
type DaemonSink struct {
	CmdCh chan<- string
}

func (s DaemonSink) Send(d auth.Decision) error {
	switch d.Type {
	case auth.DecisionAllow:
		return s.trySend(mgmt.ClientAuth(d.CID, d.KID))
	case auth.DecisionAllowNT:
		return s.trySend(mgmt.ClientAuthNT(d.CID, d.KID))
	case auth.DecisionDeny:
		return s.trySend(mgmt.ClientDeny(d.CID, d.KID, d.Reason))
	case auth.DecisionPending:
		return s.trySend(mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout))
	case auth.DecisionKill:
		return s.trySend(mgmt.ClientKill(d.CID))
	}
	return nil
}

func (s DaemonSink) trySend(cmd string) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case s.CmdCh <- cmd:
		return nil
	case <-timer.C:
		slog.Warn("daemon cmdCh full, dropping command", "cmd", cmd)
		return fmt.Errorf("command dropped: channel full after 5s")
	}
}

func New(cfg config.Config, handler *auth.Handler, sessions *auth.SessionStore, callbackServer *callback.Server, metrics auth.Metrics) *Daemon {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:            cfg,
		handler:        handler,
		sessions:       sessions,
		metrics:        metrics,
		callbackServer: callbackServer,
		cmdCh:          make(chan string, 256),
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}
}

// CmdCh returns the daemon-level command channel for constructing sinks.
func (d *Daemon) CmdCh() chan string {
	return d.cmdCh
}

// SetCallbackServer sets the callback server after daemon construction.
func (d *Daemon) SetCallbackServer(srv *callback.Server) {
	d.callbackServer = srv
}

func (d *Daemon) Run(ctx context.Context) error {
	defer d.shutdownCancel()
	go d.heartbeatLoop(ctx)

	// Start callback server — bind the port synchronously so we fail fast
	// if the port is already in use or the process lacks permission.
	callbackAddr := fmt.Sprintf(":%d", d.cfg.CallbackPort)
	ln, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		return fmt.Errorf("callback server listen %s: %w", callbackAddr, err)
	}
	go func() {
		if err := d.callbackServer.Serve(ln); err != nil {
			slog.Error("callback server error", "error", err)
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		client, err := mgmt.Dial(ctx, d.cfg.ManagementSocket, d.cfg.ManagementPasswordFile, d.cfg.ReconnectMaxInterval)
		if err != nil {
			return err
		}

		d.socketConnected.Store(true)
		err = d.handleConnection(ctx, client)

		if ctx.Err() != nil {
			// Signal received — keep socket open for in-flight sessions.
			d.gracefulShutdown()
			d.socketConnected.Store(false)
			_ = client.Close()
			// Shutdown callback server
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = d.callbackServer.Shutdown(shutdownCtx)
			cancel()
			return ctx.Err()
		}

		d.socketConnected.Store(false)
		_ = client.Close()
		if err != nil {
			slog.Warn("management connection lost", "error", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
	}
}

func (d *Daemon) handleConnection(ctx context.Context, client *mgmt.Client) error {
	// connCtx is cancelled when this connection ends (normal disconnect or
	// process shutdown). The goroutine below uses it instead of the
	// process-level ctx so it does not leak across reconnections.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	// Unblock scanner.Scan() when the connection context is cancelled
	// (either process shutdown or connection lost). The read deadline
	// expires immediately, but the socket stays writable for graceful shutdown.
	go func() {
		<-connCtx.Done()
		_ = client.SetReadDeadline(time.Now())
	}()

	cmdDone := make(chan struct{})
	go func() {
		defer close(cmdDone)
		d.commandWriter(connCtx, client)
	}()

	// Send hold release immediately
	select {
	case d.cmdCh <- "hold release":
	case <-cmdDone:
		return nil
	}

	scanner := client.Scanner()
	sink := decisionSink{cmdCh: d.cmdCh, done: cmdDone}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, ">CLIENT:"):
			event, err := mgmt.ReadEvent(scanner, line)
			if err != nil {
				return err
			}
			d.handler.HandleEvent(d.shutdownCtx, event, sink)
		case strings.HasPrefix(line, ">HOLD:"):
			select {
			case d.cmdCh <- "hold release":
			case <-cmdDone:
				return nil
			}
		}
	}
	return scanner.Err()
}

func (d *Daemon) commandWriter(ctx context.Context, client *mgmt.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-d.cmdCh:
			if err := client.WriteLine(cmd); err != nil {
				slog.Error("management write failed", "error", err)
				return
			}
		}
	}
}

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	if !d.cfg.EMFMetrics || d.cfg.EMFInterval <= 0 {
		return
	}
	ticker := time.NewTicker(d.cfg.EMFInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.metrics.Heartbeat(
				d.socketConnected.Load(),
				d.sessions.Len(),
			)
		}
	}
}

// SocketConnected returns true if the management socket is currently connected.
// This is injected into the callback server for /healthz reporting.
func (d *Daemon) SocketConnected() bool {
	return d.socketConnected.Load()
}

func (d *Daemon) gracefulShutdown() {
	// Wait for in-flight REAUTH goroutines (bounded by ReauthTimeout).
	d.handler.WaitReauth()

	n := d.handler.InFlight()
	if n == 0 {
		return
	}
	slog.Info("graceful shutdown", "in_flight", n, "grace_period", d.cfg.ShutdownGracePeriod)
	deadline := time.After(d.cfg.ShutdownGracePeriod)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			slog.Warn("grace period expired", "in_flight", d.handler.InFlight())
			return
		case <-ticker.C:
			if d.handler.InFlight() == 0 {
				slog.Info("all in-flight sessions completed")
				return
			}
		}
	}
}
