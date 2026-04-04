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

// ALBClaims holds the parsed claims from the ALB-signed x-amzn-oidc-data JWT.
type ALBClaims struct {
	Sub             string `json:"sub"`
	Email           string `json:"email"`
	Exp             int64  `json:"exp"`
	Iss             string `json:"iss"`
	CognitoUsername string `json:"cognito:username"`
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
	Heartbeat(socketConnected bool, storedSessions int)
	AuthAttempt(reason string)
	AuthSuccess()
	AuthDenied(reason string)
	ReauthSuccess()
	ReauthDenied(reason string)
	ReauthCacheHit()
	CallbackReceived()
	CallbackRejected(reason string)
	TokenExchangeError(reason string)
	SessionExpired(reason string)
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
	Send(Decision) error
}

// AuthSuccessTracker is notified when the callback flow successfully sends
// client-auth for a CID. Implemented by *Handler.
type AuthSuccessTracker interface {
	MarkAuthenticated(cid, cognitoUsername string)
}
