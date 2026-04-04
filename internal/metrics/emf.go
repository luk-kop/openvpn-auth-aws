package metrics

import (
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"
)

type Emitter struct {
	mu         sync.Mutex
	w          io.Writer
	instanceID string
}

func NewEmitter(w io.Writer, instanceID string) *Emitter {
	return &Emitter{w: w, instanceID: instanceID}
}

func (e *Emitter) Heartbeat(socketConnected bool, storedSessions int) {
	e.emit(map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "VPNAuth",
				"Dimensions": [][]string{{"InstanceId"}},
				"Metrics": []any{
					map[string]any{"Name": "SocketConnected", "Unit": "None"},
					map[string]any{"Name": "StoredSessions", "Unit": "Count"},
				},
			}},
		},
		"InstanceId":      e.instanceID,
		"SocketConnected": boolToInt(socketConnected),
		"StoredSessions":  storedSessions,
	})
}

func (e *Emitter) AuthAttempt(reason string)      { e.counter("AuthAttempt", reason) }
func (e *Emitter) AuthSuccess()                   { e.counter("AuthSuccess", "") }
func (e *Emitter) AuthDenied(reason string)       { e.counter("AuthDenied", reason) }
func (e *Emitter) ReauthSuccess()                 { e.counter("ReauthSuccess", "") }
func (e *Emitter) ReauthDenied(reason string)     { e.counter("ReauthDenied", reason) }
func (e *Emitter) ReauthCacheHit()                { e.counter("ReauthCacheHit", "") }
func (e *Emitter) CallbackReceived()              { e.counter("CallbackReceived", "") }
func (e *Emitter) CallbackRejected(reason string) { e.counter("CallbackRejected", reason) }
func (e *Emitter) TokenExchangeError(reason string) {
	e.counter("TokenExchangeError", reason)
}
func (e *Emitter) SessionExpired(reason string) { e.counter("SessionExpired", reason) }

func (e *Emitter) counter(name, reason string) {
	dims := [][]string{{"InstanceId"}}
	payload := map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "VPNAuth",
				"Dimensions": dims,
				"Metrics":    []any{map[string]any{"Name": name, "Unit": "Count"}},
			}},
		},
		"InstanceId": e.instanceID,
		name:         1,
	}
	if reason != "" {
		dims[0] = []string{"InstanceId", "Reason"}
		payload["_aws"] = map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "VPNAuth",
				"Dimensions": dims,
				"Metrics":    []any{map[string]any{"Name": name, "Unit": "Count"}},
			}},
		}
		payload["Reason"] = reason
	}
	e.emit(payload)
}

func (e *Emitter) emit(payload map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	enc := json.NewEncoder(e.w)
	if err := enc.Encode(payload); err != nil {
		slog.Warn("emf: encode failed", "error", err)
	}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
