package metrics

import (
	"encoding/json"
	"io"
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

func (e *Emitter) Heartbeat(socketConnected bool, dynamoReachable bool, inFlight int) {
	e.emit(map[string]any{
		"_aws": map[string]any{
			"Timestamp": time.Now().UnixMilli(),
			"CloudWatchMetrics": []any{map[string]any{
				"Namespace":  "VPNAuth",
				"Dimensions": [][]string{{"InstanceId"}},
				"Metrics": []any{
					map[string]any{"Name": "SocketConnected", "Unit": "None"},
					map[string]any{"Name": "DynamoDBReachable", "Unit": "None"},
					map[string]any{"Name": "InFlightSessions", "Unit": "Count"},
				},
			}},
		},
		"InstanceId":        e.instanceID,
		"SocketConnected":   boolToInt(socketConnected),
		"DynamoDBReachable": boolToInt(dynamoReachable),
		"InFlightSessions":  inFlight,
	})
}

func (e *Emitter) AuthAttempt(reason string) { e.counter("AuthAttempt", reason) }
func (e *Emitter) AuthSuccess()              { e.counter("AuthSuccess", "") }
func (e *Emitter) AuthDenied(reason string)  { e.counter("AuthDenied", reason) }
func (e *Emitter) ReauthSuccess()            { e.counter("ReauthSuccess", "") }
func (e *Emitter) ReauthDenied(reason string) {
	e.counter("ReauthDenied", reason)
}
func (e *Emitter) ReauthCacheHit() { e.counter("ReauthCacheHit", "") }

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
	_ = enc.Encode(payload)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
