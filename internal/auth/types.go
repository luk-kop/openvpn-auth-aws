package auth

import (
	"context"
	"time"
)

type Status string

const (
	StatusPending    Status = "PENDING"
	StatusProcessing Status = "PROCESSING"
	StatusSuccess    Status = "SUCCESS"
	StatusFailed     Status = "FAILED"
)

type PendingSession struct {
	State         string
	Nonce         string
	CommonName    string
	CID           string
	KID           string
	Username      string
	CNCrossCheck  bool
	RequiredGroup string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type SessionStore interface {
	PutPending(context.Context, PendingSession) error
	GetStatus(context.Context, string) (StatusResult, error)
}

type StatusResult struct {
	Status    Status
	AuthToken string // HMAC signature for verification
}

type IdentityResult struct {
	Exists       bool
	Enabled      bool
	InGroup      bool
	CheckedAt    time.Time
	FailureCause string
}

type IdentityChecker interface {
	CheckUser(context.Context, string, string, bool) (IdentityResult, error)
}

type StateSigner interface {
	Sign(string) string
}

type Metrics interface {
	Heartbeat(socketConnected bool, dynamoReachable bool, inFlight int)
	AuthAttempt(reason string)
	AuthSuccess()
	AuthDenied(reason string)
	ReauthSuccess()
	ReauthDenied(reason string)
	ReauthCacheHit()
}

type DecisionType int

const (
	DecisionAllow   DecisionType = iota // CONNECT success → client-auth
	DecisionAllowNT                     // REAUTH success → client-auth-nt
	DecisionDeny                        // any denial → client-deny
	DecisionPending                     // WebAuth started → client-pending-auth
)

type Decision struct {
	Type    DecisionType
	CID     string
	KID     string
	Reason  string // DecisionDeny
	URL     string // DecisionPending
	Timeout int    // DecisionPending, seconds
}

type DecisionSink interface {
	Send(Decision)
}
