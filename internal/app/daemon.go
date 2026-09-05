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
	cmdCh chan queuedCommand

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	socketConnected atomic.Bool
}

const bootstrapReadTimeout = 5 * time.Second

type decisionSink struct {
	cmdCh chan<- queuedCommand
	done  <-chan struct{}
}

type queuedCommand struct {
	cmd string
	ack chan error
}

// decisionToCommand converts an auth decision to the corresponding OpenVPN
// management socket command string. Returns an empty string for unknown types.
func decisionToCommand(d auth.Decision) string {
	switch d.Type {
	case auth.DecisionAllow:
		return mgmt.ClientAuth(d.CID, d.KID)
	case auth.DecisionAllowNT:
		return mgmt.ClientAuthNT(d.CID, d.KID)
	case auth.DecisionDeny:
		return mgmt.ClientDeny(d.CID, d.KID, d.Reason)
	case auth.DecisionPending:
		return mgmt.ClientPendingAuth(d.CID, d.KID, d.URL, d.Timeout)
	case auth.DecisionKill:
		return mgmt.ClientKill(d.CID, d.KillMode)
	}
	return ""
}

func (s decisionSink) Send(d auth.Decision) error {
	cmd := decisionToCommand(d)
	if cmd == "" {
		return nil
	}
	return s.sendOne(cmd)
}

func (s decisionSink) SendAck(d auth.Decision) error {
	cmd := decisionToCommand(d)
	if cmd == "" {
		return nil
	}
	ack := make(chan error, 1)
	select {
	case s.cmdCh <- queuedCommand{cmd: cmd, ack: ack}:
	case <-s.done:
		return fmt.Errorf("command dropped: connection closed")
	}
	select {
	case err := <-ack:
		return err
	case <-s.done:
		return fmt.Errorf("command acknowledgement lost: connection closed")
	case <-time.After(bootstrapReadTimeout):
		return fmt.Errorf("command acknowledgement timed out after %s", bootstrapReadTimeout)
	}
}

func (s decisionSink) sendOne(cmd string) error {
	select {
	case s.cmdCh <- queuedCommand{cmd: cmd}:
		return nil
	case <-s.done:
		return fmt.Errorf("command dropped: connection closed")
	}
}

// DaemonSink is the DecisionSink backed by the daemon-level cmdCh.
// It never blocks on a "done" channel — the daemon manages its own lifecycle.
type DaemonSink struct {
	cmdCh chan<- queuedCommand
}

func (s DaemonSink) Send(d auth.Decision) error {
	cmd := decisionToCommand(d)
	if cmd == "" {
		return nil
	}
	return s.trySend(cmd)
}

func (s DaemonSink) SendAck(d auth.Decision) error {
	cmd := decisionToCommand(d)
	if cmd == "" {
		return nil
	}
	return s.sendAck(cmd)
}

func (s DaemonSink) trySend(cmd string) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case s.cmdCh <- queuedCommand{cmd: cmd}:
		return nil
	case <-timer.C:
		slog.Warn("daemon cmdCh full, dropping command", "cmd", cmd)
		return fmt.Errorf("command dropped: channel full after 5s")
	}
}

func (s DaemonSink) sendAck(cmd string) error {
	ack := make(chan error, 1)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case s.cmdCh <- queuedCommand{cmd: cmd, ack: ack}:
	case <-timer.C:
		slog.Warn("daemon cmdCh full, dropping command", "cmd", cmd)
		return fmt.Errorf("command dropped: channel full after 5s")
	}

	timer.Reset(5 * time.Second)
	select {
	case err := <-ack:
		return err
	case <-timer.C:
		return fmt.Errorf("command write ack timed out after 5s")
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
		cmdCh:          make(chan queuedCommand, 256),
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}
}

// Sink returns the daemon-level decision sink for callback and timeout flows.
func (d *Daemon) Sink() DaemonSink {
	return DaemonSink{cmdCh: d.cmdCh}
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
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", callbackAddr)
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
			slog.Info("management reconnecting")
			time.Sleep(500 * time.Millisecond)
			continue
		}
		slog.Info("management connection closed")
		slog.Info("management reconnecting")
	}
}

// handleConnection manages a single management socket connection. It returns
// connCancel so the caller can control when connCtx is cancelled. The caller
// is responsible for calling connCancel after any post-connection work
// (e.g. gracefulShutdown) is complete.
func (d *Daemon) handleConnection(ctx context.Context, client *mgmt.Client) (context.CancelFunc, error) {
	connCtx, connCancel := context.WithCancel(ctx)

	go func() {
		<-connCtx.Done()
		_ = client.SetReadDeadline(time.Now())
	}()

	rawLog := d.managementRawLogger()
	cmdDone := make(chan struct{})
	sink := decisionSink{cmdCh: d.cmdCh, done: cmdDone}
	notifications := make(chan readerNotification, 256)
	readErr := make(chan error, 1)
	broker := newManagementBroker(client)
	go broker.run(connCtx)
	go readManagement(connCtx, client, rawLog, broker, notifications, readErr)

	slog.Info("management bootstrap start")
	if _, err := broker.request(connCtx, "hold release"); err != nil {
		connCancel()
		return connCancel, fmt.Errorf("bootstrap hold release: %w", err)
	}
	statusResponse, err := broker.request(connCtx, "status 3")
	if err != nil {
		slog.Warn("management bootstrap failed", "error", err)
		connCancel()
		return connCancel, err
	}

	var bufferedEvents []mgmt.Event
	for draining := true; draining; {
		select {
		case notification := <-notifications:
			if notification.event != nil {
				bufferedEvents = append(bufferedEvents, *notification.event)
			}
		default:
			draining = false
		}
	}
	slog.Info("management bootstrap complete",
		"established_sessions", len(statusResponse.snapshot.Established),
		"buffered_events", len(bufferedEvents),
	)

	d.handler.SetLiveSink(sink)
	defer d.handler.ClearLiveSink()
	d.handler.SetStatusProvider(brokerStatusProvider{broker: broker})
	defer d.handler.ClearStatusProvider()
	evictions := d.handler.RebuildSessionTrackingFromSnapshot(statusResponse.snapshot)

	go func() {
		defer close(cmdDone)
		d.commandBrokerForwarder(connCtx, broker)
	}()

	for _, event := range bufferedEvents {
		d.handler.HandleEvent(d.shutdownCtx, event, sink)
	}
	sentEvictions := make(map[string]struct{}, len(evictions))
	for _, eviction := range evictions {
		if _, sent := sentEvictions[eviction.CID]; sent {
			continue
		}
		if !d.handler.ReconciledEvictionNeeded(eviction.CID) {
			continue
		}
		sentEvictions[eviction.CID] = struct{}{}
		if err := sink.SendAck(eviction); err != nil {
			slog.Warn("bootstrap eviction failed", "cid", eviction.CID, "error", err)
			snapshot, statusErr := brokerStatusProvider{broker: broker}.Status(connCtx)
			if statusErr != nil {
				connCancel()
				return connCancel, fmt.Errorf("bootstrap eviction reconciliation: %w", statusErr)
			}
			if _, present := snapshot.ClientByCID(eviction.CID); !present {
				d.handler.HandleEvent(d.shutdownCtx, mgmt.Event{Type: mgmt.EventDisconnect, CID: eviction.CID}, sink)
			}
		}
	}

	for {
		select {
		case <-connCtx.Done():
			return connCancel, connCtx.Err()
		case err := <-readErr:
			connCancel()
			return connCancel, err
		case <-broker.done:
			connCancel()
			return connCancel, broker.terminalError()
		case notification := <-notifications:
			if notification.hold {
				select {
				case d.cmdCh <- queuedCommand{cmd: "hold release"}:
				case <-cmdDone:
					connCancel()
					return connCancel, nil
				}
				continue
			}
			if notification.event != nil {
				d.handler.HandleEvent(d.shutdownCtx, *notification.event, sink)
			}
		}
	}
}

func (d *Daemon) commandBrokerForwarder(ctx context.Context, broker *managementBroker) {
	for {
		select {
		case <-ctx.Done():
			return
		case queued := <-d.cmdCh:
			response, err := broker.request(ctx, queued.cmd)
			if err == nil {
				err = response.err
			}
			if queued.ack != nil {
				queued.ack <- err
			}
			if err != nil {
				slog.Error("management command failed", "cmd", queued.cmd, "error", err)
			}
		}
	}
}

func (d *Daemon) managementRawLogger() mgmt.RawLogFunc {
	if !d.cfg.ManagementRawLog {
		return nil
	}
	return func(line string) {
		slog.Debug("MGMT_RAW", "line", redactManagementRawLine(line))
	}
}

func redactManagementRawLine(line string) string {
	line = redactEnvValue(line, ">CLIENT:ENV,password=")
	line = redactEnvValue(line, "password=")
	line = redactQueryValue(line, "state=")
	return line
}

func redactEnvValue(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return line
	}
	start := idx + len(prefix)
	end := start
	for end < len(line) {
		switch line[end] {
		case '&', ' ', '\t', '\r', '\n', '"', '\'':
			return line[:start] + "[REDACTED]" + line[end:]
		default:
			end++
		}
	}
	return line[:start] + "[REDACTED]"
}

func redactQueryValue(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return line
	}
	start := idx + len(key)
	end := start
	for end < len(line) {
		switch line[end] {
		case '&', ' ', '\t', '\r', '\n', '"', '\'':
			return line[:start] + "[REDACTED]" + line[end:]
		default:
			end++
		}
	}
	return line[:start] + "[REDACTED]"
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
