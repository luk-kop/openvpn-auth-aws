package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"openvpn-auth-aws/internal/mgmt"
)

type responseContract int

const (
	singleLineAck responseContract = iota
	multiLineUntilEnd
)

type commandResponse struct {
	snapshot mgmt.StatusSnapshot
	err      error
}

type brokerRequest struct {
	command  string
	contract responseContract
	result   chan commandResponse
}

type readerNotification struct {
	event *mgmt.Event
	hold  bool
}

type brokerStatusProvider struct {
	broker *managementBroker
}

func (p brokerStatusProvider) Status(ctx context.Context) (mgmt.StatusSnapshot, error) {
	response, err := p.broker.request(ctx, "status 3")
	if err != nil {
		return mgmt.StatusSnapshot{}, err
	}
	return response.snapshot, nil
}

type managementBroker struct {
	client       *mgmt.Client
	requests     chan brokerRequest
	responseLine chan string
	done         chan struct{}
	finishOnce   sync.Once
	err          error
}

func newManagementBroker(client *mgmt.Client) *managementBroker {
	return &managementBroker{
		client:       client,
		requests:     make(chan brokerRequest, 256),
		responseLine: make(chan string, 256),
		done:         make(chan struct{}),
	}
}

func (b *managementBroker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			b.finish(ctx.Err())
			return
		case line := <-b.responseLine:
			b.finish(fmt.Errorf("management protocol desynchronized: unexpected response line %q", line))
			return
		case request := <-b.requests:
			response, fatal := b.execute(ctx, request)
			request.result <- response
			if fatal != nil {
				b.finish(fatal)
				return
			}
		}
	}
}

func (b *managementBroker) execute(ctx context.Context, request brokerRequest) (commandResponse, error) {
	if err := b.client.WriteLine(request.command); err != nil {
		err = fmt.Errorf("write management command: %w", err)
		return commandResponse{err: err}, err
	}

	timer := time.NewTimer(bootstrapReadTimeout)
	defer timer.Stop()
	var lines []string

	for {
		select {
		case <-ctx.Done():
			return commandResponse{err: ctx.Err()}, ctx.Err()
		case <-timer.C:
			err := fmt.Errorf("management command response timeout after %s", bootstrapReadTimeout)
			return commandResponse{err: err}, err
		case line := <-b.responseLine:
			switch request.contract {
			case singleLineAck:
				switch {
				case strings.HasPrefix(line, "SUCCESS:"):
					return commandResponse{}, nil
				case strings.HasPrefix(line, "ERROR:"):
					return commandResponse{err: fmt.Errorf("openvpn command failed: %s", line)}, nil
				default:
					err := fmt.Errorf("management protocol desynchronized: expected SUCCESS/ERROR, got %q", line)
					return commandResponse{err: err}, err
				}
			case multiLineUntilEnd:
				lines = append(lines, line)
				if line != "END" {
					continue
				}
				snapshot, err := mgmt.ParseStatusLines(lines)
				if err != nil {
					err = fmt.Errorf("parse status response: %w", err)
					return commandResponse{err: err}, err
				}
				return commandResponse{snapshot: snapshot}, nil
			default:
				err := fmt.Errorf("unknown response contract %d", request.contract)
				return commandResponse{err: err}, err
			}
		}
	}
}

func (b *managementBroker) finish(err error) {
	b.finishOnce.Do(func() {
		b.err = err
		close(b.done)
	})
}

func (b *managementBroker) terminalError() error {
	if b.err != nil {
		return b.err
	}
	return fmt.Errorf("management broker stopped")
}

func (b *managementBroker) request(ctx context.Context, command string) (commandResponse, error) {
	contract, err := commandContract(command)
	if err != nil {
		return commandResponse{}, err
	}
	result := make(chan commandResponse, 1)
	request := brokerRequest{command: command, contract: contract, result: result}
	select {
	case b.requests <- request:
	case <-b.done:
		return commandResponse{}, b.terminalError()
	case <-ctx.Done():
		return commandResponse{}, ctx.Err()
	}

	select {
	case response := <-result:
		return response, response.err
	case <-b.done:
		return commandResponse{}, b.terminalError()
	case <-ctx.Done():
		return commandResponse{}, ctx.Err()
	}
}

func commandContract(command string) (responseContract, error) {
	command = strings.TrimSpace(command)
	switch {
	case command == "status 3":
		return multiLineUntilEnd, nil
	case command == "hold release",
		strings.HasPrefix(command, "client-auth "),
		strings.HasPrefix(command, "client-auth-nt "),
		strings.HasPrefix(command, "client-deny "),
		strings.HasPrefix(command, "client-pending-auth "),
		strings.HasPrefix(command, "client-kill "):
		return singleLineAck, nil
	default:
		return 0, fmt.Errorf("management command has no registered response contract: %q", command)
	}
}

func readManagement(ctx context.Context, client *mgmt.Client, rawLog mgmt.RawLogFunc, broker *managementBroker, notifications chan<- readerNotification, readErr chan<- error) {
	scanner := client.Scanner()
	for scanner.Scan() {
		line := scanner.Text()
		if rawLog != nil {
			rawLog(line)
		}
		switch {
		case strings.HasPrefix(line, ">CLIENT:"):
			event, err := mgmt.ReadEventWithRawLog(scanner, line, rawLog)
			if err != nil {
				sendReadError(ctx, readErr, err)
				return
			}
			if event.Type == mgmt.EventIgnored {
				continue
			}
			select {
			case notifications <- readerNotification{event: &event}:
			case <-ctx.Done():
				return
			}
		case strings.HasPrefix(line, ">HOLD:"):
			select {
			case notifications <- readerNotification{hold: true}:
			case <-ctx.Done():
				return
			}
		case strings.HasPrefix(line, ">"):
			slog.Debug("management async notification ignored", "line", line)
		default:
			select {
			case broker.responseLine <- line:
			case <-ctx.Done():
				return
			}
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		sendReadError(ctx, readErr, err)
		return
	}
	sendReadError(ctx, readErr, fmt.Errorf("management socket closed"))
}

func sendReadError(ctx context.Context, readErr chan<- error, err error) {
	select {
	case readErr <- err:
	case <-ctx.Done():
	}
}
