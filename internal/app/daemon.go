package app

import (
	"context"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/mgmt"
)

type Daemon struct {
	cfg     config.Config
	handler *auth.Handler
	metrics auth.Metrics

	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	socketConnected atomic.Bool
}

type decisionSink struct {
	cmdCh chan<- string
	done  <-chan struct{}
}

func (s decisionSink) Send(d auth.Decision) {
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
	default:
		return
	}
	select {
	case s.cmdCh <- cmd:
	case <-s.done:
	}
}

func New(cfg config.Config, handler *auth.Handler, metrics auth.Metrics) *Daemon {
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:            cfg,
		handler:        handler,
		metrics:        metrics,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}
}

func (d *Daemon) Run(ctx context.Context) error {
	defer d.shutdownCancel()
	go d.heartbeatLoop(ctx)

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
			return ctx.Err()
		}

		d.socketConnected.Store(false)
		_ = client.Close()
		if err != nil {
			log.Printf("management connection lost: %v", err)
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
	cmdCh := make(chan string, 256)
	go func() {
		defer close(cmdDone)
		d.commandWriter(d.shutdownCtx, client, cmdCh)
	}()

	// Send hold release immediately — required when OpenVPN is configured with
	// management-hold. OpenVPN will not accept any client connections until it
	// receives this command. Safe to send even without management-hold.
	select {
	case cmdCh <- "hold release":
	case <-cmdDone:
		return nil
	}

	scanner := client.Scanner()
	sink := decisionSink{cmdCh: cmdCh, done: cmdDone}
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
			// OpenVPN is waiting — release the hold
			select {
			case cmdCh <- "hold release":
			case <-cmdDone:
				return nil
			}
		}
	}
	return scanner.Err()
}

func (d *Daemon) commandWriter(ctx context.Context, client *mgmt.Client, cmdCh <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-cmdCh:
			if err := client.WriteLine(cmd); err != nil {
				log.Printf("management write failed: %v", err)
				return
			}
		}
	}
}

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.metrics.Heartbeat(
				d.socketConnected.Load(),
				d.handler.DynamoReachable(),
				d.handler.InFlight(),
			)
		}
	}
}

func (d *Daemon) gracefulShutdown() {
	n := d.handler.InFlight()
	if n == 0 {
		return
	}
	log.Printf("graceful shutdown: waiting for %d in-flight sessions (max %v)", n, d.cfg.ShutdownGracePeriod)
	deadline := time.After(d.cfg.ShutdownGracePeriod)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			log.Printf("grace period expired, %d sessions still in-flight", d.handler.InFlight())
			return
		case <-ticker.C:
			if d.handler.InFlight() == 0 {
				log.Printf("all in-flight sessions completed")
				return
			}
		}
	}
}
