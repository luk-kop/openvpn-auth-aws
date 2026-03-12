package app

import (
	"context"
	"fmt"
	"log/slog"
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

func (s decisionSink) Send(d auth.Decision) {
	switch d.Type {
	case auth.DecisionAllow:
		lines := mgmt.ClientAuth(d.CID, d.KID)
		for _, line := range lines {
			select {
			case s.cmdCh <- line:
			case <-s.done:
				return
			}
		}
	case auth.DecisionAllowNT:
		s.sendOne(mgmt.ClientAuthNT(d.CID, d.KID))
	case auth.DecisionDeny:
		s.sendOne(mgmt.ClientDeny(d.CID, d.KID, d.Reason))
	case auth.DecisionPending:
		s.sendOne(mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout))
	case auth.DecisionKill:
		s.sendOne(mgmt.ClientKill(d.CID))
	}
}

func (s decisionSink) sendOne(cmd string) {
	select {
	case s.cmdCh <- cmd:
	case <-s.done:
	}
}

// DaemonSink is the DecisionSink backed by the daemon-level cmdCh.
// It never blocks on a "done" channel — the daemon manages its own lifecycle.
type DaemonSink struct {
	CmdCh chan<- string
}

func (s DaemonSink) Send(d auth.Decision) {
	switch d.Type {
	case auth.DecisionAllow:
		lines := mgmt.ClientAuth(d.CID, d.KID)
		for _, line := range lines {
			s.trySend(line)
		}
	case auth.DecisionAllowNT:
		s.trySend(mgmt.ClientAuthNT(d.CID, d.KID))
	case auth.DecisionDeny:
		s.trySend(mgmt.ClientDeny(d.CID, d.KID, d.Reason))
	case auth.DecisionPending:
		s.trySend(mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout))
	case auth.DecisionKill:
		s.trySend(mgmt.ClientKill(d.CID))
	}
}

func (s DaemonSink) trySend(cmd string) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case s.CmdCh <- cmd:
	case <-timer.C:
		slog.Warn("daemon cmdCh full, dropping command", "cmd", cmd)
	}
}

func New(cfg config.Config, handler *auth.Handler, callbackServer *callback.Server, metrics auth.Metrics) *Daemon {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:            cfg,
		handler:        handler,
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

	// Start callback server
	callbackAddr := fmt.Sprintf(":%d", d.cfg.CallbackPort)
	go func() {
		if err := d.callbackServer.Start(callbackAddr); err != nil {
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
	// Unblock scanner.Scan() when signal fires (read deadline expires
	// immediately, but the socket stays writable for graceful shutdown).
	go func() {
		<-ctx.Done()
		_ = client.SetReadDeadline(time.Now())
	}()

	cmdDone := make(chan struct{})
	go func() {
		defer close(cmdDone)
		d.commandWriter(d.shutdownCtx, client)
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
				d.handler.InFlight(),
			)
		}
	}
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
