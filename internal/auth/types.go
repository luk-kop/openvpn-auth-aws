package auth

import (
	"context"
	"time"
)

type SessionStatus int

const (
	SessionPending SessionStatus = iota
	SessionProcessing
	SessionDone
	SessionFailed
)

type PendingSession struct {
	SessionID     string
	CodeVerifier  string
	Nonce         string
	CommonName    string
	CID           string
	KID           string
	Username      string
	CNCrossCheck  bool
	RequiredGroup string
	Status        SessionStatus
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type CallbackRequest struct {
	Code      string `json:"code"`
	SessionID string `json:"session_id"`
	Timestamp int64  `json:"ts"`
}

type TokenExchanger interface {
	Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (*IDTokenClaims, error)
}

type IDTokenClaims struct {
	Email  string
	Nonce  string
	Groups []string
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
	Sign(data string) string
	Verify(data, mac string) bool
}

type Metrics interface {
	Heartbeat(socketConnected bool, inFlight int)
	AuthAttempt(reason string)
	AuthSuccess()
	AuthDenied(reason string)
	ReauthSuccess()
	ReauthDenied(reason string)
	ReauthCacheHit()
	CallbackReceived()
	TokenExchangeError(reason string)
}

type DecisionType int

const (
	DecisionAllow   DecisionType = iota // CONNECT success → client-auth
	DecisionAllowNT                     // REAUTH success → client-auth-nt
	DecisionDeny                        // any denial → client-deny
	DecisionPending                     // WebAuth started → client-pending-auth
	DecisionKill                        // kill established session → client-kill
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
