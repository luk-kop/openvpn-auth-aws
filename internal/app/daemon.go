package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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

const bootstrapReadTimeout = 5 * time.Second

type decisionSink struct {
	cmdCh chan<- string
	done  <-chan struct{}
}

type directDecisionSink struct {
	client *mgmt.Client
	mu     *sync.Mutex
	done   <-chan struct{}
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
		return s.sendOne(mgmt.ClientKill(d.CID, d.KillMode))
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

func (s directDecisionSink) Send(d auth.Decision) error {
	var cmd string
	switch d.Type {
	case auth.DecisionAllow:
		cmd = mgmt.ClientAuth(d.CID, d.KID)
	case auth.DecisionAllowNT:
		cmd = mgmt.ClientAuthNT(d.CID, d.KID)
	case auth.DecisionDeny:
		cmd = mgmt.ClientDeny(d.CID, d.KID, d.Reason)
	case auth.DecisionPending:
		cmd = mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout)
	case auth.DecisionKill:
		cmd = mgmt.ClientKill(d.CID, d.KillMode)
	default:
		return nil
	}

	select {
	case <-s.done:
		return fmt.Errorf("command dropped: connection closed")
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return fmt.Errorf("command dropped: connection closed")
	default:
	}
	return s.client.WriteLine(cmd)
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
		return s.trySend(mgmt.ClientKill(d.CID, d.KillMode))
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
	handler.SetLifecycleContext(shutdownCtx)
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

	if d.cfg.CNCrossCheck {
		slog.Warn("cn-cross-check is enabled: federation requires the external IdP to map its email attribute to the same value as the OpenVPN certificate CN; misconfiguration will deny all federated users with Certificate Mismatch")
	}

	go d.heartbeatLoop(ctx)

	// Start callback server — bind the port synchronously so we fail fast
	// if the port is already in use or the process lacks permission.
	callbackAddr := fmt.Sprintf(":%d", d.cfg.CallbackPort)
	ln, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		return fmt.Errorf("callback server listen %s: %w", callbackAddr, err)
	}
	cbErrCh := make(chan error, 1)
	go func() {
		if err := d.callbackServer.Serve(ln); err != nil {
			cbErrCh <- err
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Check for callback server failure before attempting to dial.
		select {
		case err := <-cbErrCh:
			return fmt.Errorf("callback server: %w", err)
		default:
		}

		client, err := mgmt.Dial(ctx, d.cfg.ManagementSocket, d.cfg.ManagementPasswordFile, d.cfg.ReconnectMaxInterval)
		if err != nil {
			return err
		}

		d.socketConnected.Store(true)
		connCancel, err := d.handleConnection(ctx, client)

		// Check for callback server failure that arrived while connected.
		select {
		case cbErr := <-cbErrCh:
			connCancel()
			d.socketConnected.Store(false)
			_ = client.Close()
			return fmt.Errorf("callback server: %w", cbErr)
		default:
		}

		if ctx.Err() != nil {
			// Signal received — drain in-flight sessions before cancelling
			// the connection context. commandWriter must stay alive until
			// gracefulShutdown completes so queued deny commands are written.
			d.gracefulShutdown()
			connCancel() // safe: drain is complete
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

// handleConnection manages a single management socket connection. It returns
// connCancel so the caller can control when connCtx is cancelled. The caller
// is responsible for calling connCancel after any post-connection work
// (e.g. gracefulShutdown) is complete.
func (d *Daemon) handleConnection(ctx context.Context, client *mgmt.Client) (context.CancelFunc, error) {
	// connCtx is cancelled when this connection ends (normal disconnect or
	// process shutdown). The goroutine below uses it instead of the
	// process-level ctx so it does not leak across reconnections.
	// NOTE: connCancel is NOT deferred here — the caller owns its lifetime
	// so that commandWriter stays alive until gracefulShutdown completes.
	connCtx, connCancel := context.WithCancel(ctx)

	// Unblock scanner.Scan() when the connection context is cancelled
	// (either process shutdown or connection lost). The read deadline
	// expires immediately, but the socket stays writable for graceful shutdown.
	go func() {
		<-connCtx.Done()
		_ = client.SetReadDeadline(time.Now())
	}()

	connMu := &sync.Mutex{}
	cmdDone := make(chan struct{})
	scanner := client.Scanner()
	sink := decisionSink{cmdCh: d.cmdCh, done: cmdDone}
	liveSink := directDecisionSink{client: client, mu: connMu, done: cmdDone}

	slog.Info("management bootstrap start")
	if err := client.SetReadDeadline(time.Now().Add(bootstrapReadTimeout)); err != nil {
		connCancel()
		return connCancel, fmt.Errorf("set bootstrap read deadline: %w", err)
	}
	snapshot, bufferedEvents, err := mgmt.BootstrapStatus(client)
	if clearErr := client.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
		connCancel()
		return connCancel, fmt.Errorf("clear bootstrap read deadline: %w", clearErr)
	}
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			err = fmt.Errorf("bootstrap status 3 timeout after %s: %w", bootstrapReadTimeout, err)
		}
		slog.Warn("management bootstrap failed", "error", err)
		connCancel()
		return connCancel, err
	}
	slog.Info("management bootstrap complete",
		"established_sessions", len(snapshot),
		"buffered_events", len(bufferedEvents),
	)

	d.handler.SetLiveSink(liveSink)
	defer d.handler.ClearLiveSink()
	d.handler.RebuildSessionTrackingFromStatus(snapshot)

	go func() {
		defer close(cmdDone)
		d.commandWriter(connCtx, client, connMu)
	}()

	for _, event := range bufferedEvents {
		d.handler.HandleEvent(d.shutdownCtx, event, sink)
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, ">CLIENT:"):
			event, err := mgmt.ReadEvent(scanner, line)
			if err != nil {
				connCancel()
				return connCancel, err
			}
			d.handler.HandleEvent(d.shutdownCtx, event, sink)
		case strings.HasPrefix(line, ">HOLD:"):
			select {
			case d.cmdCh <- "hold release":
			case <-cmdDone:
				connCancel()
				return connCancel, nil
			}
		}
	}
	connCancel()
	return connCancel, scanner.Err()
}

func (d *Daemon) commandWriter(ctx context.Context, client *mgmt.Client, mu *sync.Mutex) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-d.cmdCh:
			mu.Lock()
			err := client.WriteLine(cmd)
			mu.Unlock()
			if err != nil {
				slog.Error("management write failed", "cmd", cmd, "error", err)
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
