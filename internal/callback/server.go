package callback

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"openvpn-auth-aws/internal/auth"
	"openvpn-auth-aws/internal/cognito"
	"openvpn-auth-aws/internal/config"
)

// GroupsChecker is a minimal interface for resolving Cognito group membership.
// Implemented by *cognito.Checker in production.
type GroupsChecker interface {
	CheckUser(ctx context.Context, username, requiredGroup string, checkGroups bool) (auth.IdentityResult, error)
}

// albJWTHeader holds the fields we need from the ALB JWT header.
type albJWTHeader struct {
	Kid    string `json:"kid"`
	Signer string `json:"signer"`
}

// albJWTClaims extends ALBClaims with the raw groups list from JWT claims.
type albJWTClaims struct {
	auth.ALBClaims
	Groups []string
}

// healthzResponse is the JSON body returned by GET /healthz.
type healthzResponse struct {
	Status         string `json:"status"`
	MgmtConnected  bool   `json:"mgmt_connected"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	StoredSessions int    `json:"stored_sessions"`
}

// Server is the HTTP callback server for the v2 ALB flow.
type Server struct {
	sessions *auth.SessionStore
	signer   auth.StateSigner
	sink     auth.DecisionSink
	tracker  auth.AuthSuccessTracker
	cfg      config.Config
	metrics  auth.Metrics
	identity GroupsChecker
	tmpl     *template.Template

	// ALB validation
	hostname            string
	albARN              string
	albPublicKeyBaseURL string
	// keyCache stores ALB ECDSA public keys by kid. Unbounded by design:
	// entries are added only after a successful fetch from the AWS public-key
	// endpoint, so growth is naturally limited to the small number of keys
	// AWS actually serves for a given ALB region.
	keyCache      map[string]*ecdsa.PublicKey
	keyCacheMu    sync.RWMutex
	mgmtConnected func() bool
	startTime     time.Time

	server *http.Server
}

// NewServer constructs a Server. mgmtConnected is a closure injected by the
// daemon to report management socket connectivity for /healthz.
func NewServer(
	sessions *auth.SessionStore,
	signer auth.StateSigner,
	sink auth.DecisionSink,
	tracker auth.AuthSuccessTracker,
	cfg config.Config,
	metrics auth.Metrics,
	identity GroupsChecker,
	mgmtConnected func() bool,
) (*Server, error) {
	tmpl, err := loadTemplates(cfg.TemplatesDir)
	if err != nil {
		return nil, fmt.Errorf("callback server: %w", err)
	}
	hostname, _ := os.Hostname()
	albKeyBaseURL := cfg.ALBPublicKeyBaseURL
	if albKeyBaseURL == "" {
		albKeyBaseURL = cognito.DefaultALBPublicKeyBaseURL(cfg.AWSRegion)
	}
	return &Server{
		sessions:            sessions,
		signer:              signer,
		sink:                sink,
		tracker:             tracker,
		cfg:                 cfg,
		metrics:             metrics,
		identity:            identity,
		tmpl:                tmpl,
		hostname:            hostname,
		albARN:              cfg.ALBARN,
		albPublicKeyBaseURL: albKeyBaseURL,
		keyCache:            make(map[string]*ecdsa.PublicKey),
		mgmtConnected:       mgmtConnected,
		startTime:           time.Now(),
	}, nil
}

// Handler returns the HTTP mux for the callback server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback/{path...}", s.handleCallback)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return mux
}

// handleCallback processes GET /callback/{path...} requests forwarded by ALB
// after Cognito authentication.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	s.metrics.CallbackReceived()

	// Step 1: Extract and verify state blob.
	stateParam := r.URL.Query().Get("state")
	if stateParam == "" {
		s.metrics.CallbackRejected("missing_state")
		s.renderError(w, http.StatusBadRequest, "Session Error", "Authentication state is missing or invalid.", "")
		return
	}

	payload, err := auth.DecodeState(stateParam, s.signer)
	if err != nil {
		slog.Info("callback: invalid state", "error", err)
		s.metrics.CallbackRejected("invalid_state")
		s.renderError(w, http.StatusBadRequest, "Session Error", "Authentication state is missing or invalid.", "")
		return
	}

	// Step 2: Transition session from PENDING → PROCESSING.
	sess, err := s.sessions.TryProcess(payload.SID)
	if err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) {
			slog.Info("callback: session not found", "sid", payload.SID)
			s.metrics.CallbackRejected("session_not_found")
			s.renderError(w, http.StatusNotFound, "Session Expired", "Your session has expired.\nPlease try connecting again.", payload.SID)
		} else {
			slog.Info("callback: session not pending", "sid", payload.SID)
			s.metrics.CallbackRejected("session_not_pending")
			s.renderError(w, http.StatusConflict, "Session Error", "This session has already been processed.", payload.SID)
		}
		return
	}

	// Step 3: Read ALB JWT header.
	oidcData := r.Header.Get("x-amzn-oidc-data")
	if oidcData == "" {
		slog.Warn("callback: missing x-amzn-oidc-data header", "sid", sess.SessionID)
		s.denySession(sess, "missing oidc header")
		s.metrics.CallbackRejected("missing_oidc_header")
		s.renderError(w, http.StatusForbidden, "Authentication Failed", "Identity verification failed.", sess.SessionID)
		return
	}

	// Step 4: Parse JWT header to extract kid and signer.
	jwtHeader, err := parseJWTHeader(oidcData)
	if err != nil {
		slog.Warn("callback: failed to parse JWT header", "sid", sess.SessionID, "error", err)
		s.denySession(sess, "invalid jwt header")
		s.metrics.CallbackRejected("invalid_jwt_header")
		s.renderError(w, http.StatusForbidden, "Authentication Failed", "Identity verification failed.", sess.SessionID)
		return
	}

	// Steps 5–6: If ALBARN is set, validate JWT signature.
	var claims albJWTClaims
	if s.albARN != "" {
		pubKey, err := s.getOrFetchKey(r.Context(), jwtHeader.Kid)
		if err != nil {
			slog.Error("callback: failed to fetch ALB public key",
				"kid", jwtHeader.Kid, "error", err)
			// Retryable failure: reset to pending so ALB can retry.
			// TryProcess moved it to processing, so we reset it back.
			s.sessions.MarkPending(sess.SessionID)
			s.metrics.CallbackRejected("public_key_fetch_failed")
			s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Please try again in a moment.", sess.SessionID)
			return
		}

		baseClaims, groups, err := validateALBJWT(oidcData, pubKey, s.albARN, jwtHeader.Signer, s.cfg.CognitoIssuerURL, s.cfg.CognitoGroupsClaims)
		if err != nil {
			slog.Warn("callback: ALB JWT validation failed",
				"sid", sess.SessionID, "error", err)
			s.denySession(sess, "jwt validation failed")
			s.metrics.CallbackRejected("jwt_validation_failed")
			s.renderError(w, http.StatusForbidden, "Authentication Failed", "Identity verification failed.", sess.SessionID)
			return
		}
		claims.ALBClaims = baseClaims
		claims.Groups = groups
	} else {
		// Dev mode: skip signature validation, just parse claims.
		slog.Warn("callback: JWT signature validation SKIPPED (no --alb-arn configured)", "sid", sess.SessionID)
		baseClaims, groups, parseErr := parseJWTClaimsUnsafe(oidcData)
		if parseErr != nil {
			slog.Warn("callback: failed to parse JWT claims (dev mode)",
				"sid", sess.SessionID, "error", parseErr)
			s.denySession(sess, "invalid jwt claims")
			s.metrics.CallbackRejected("invalid_jwt_claims")
			s.renderError(w, http.StatusForbidden, "Authentication Failed", "Identity verification failed.", sess.SessionID)
			return
		}
		claims.ALBClaims = baseClaims
		claims.Groups = groups
	}

	// Step 7: CN cross-check.
	if sess.CNCrossCheck && sess.CommonName != "" {
		if !strings.EqualFold(claims.Email, sess.CommonName) {
			slog.Warn("callback: CN cross-check failed",
				"sid", sess.SessionID,
				"cn", sess.CommonName,
				"email", claims.Email)
			s.denySession(sess, "cn mismatch")
			s.metrics.CallbackRejected("cn_mismatch")
			s.renderError(w, http.StatusForbidden, "Certificate Mismatch", "Your certificate CN does not match your identity.", sess.SessionID)
			return
		}
	}

	// Step 8: Group resolution.
	if sess.RequiredGroup != "" {
		inGroup, err := s.checkGroup(r.Context(), sess, claims)
		if err != nil {
			slog.Error("callback: group check error",
				"sid", sess.SessionID, "error", err)
			s.denySession(sess, "group check error")
			s.metrics.CallbackRejected("group_check_error")
			s.renderError(w, http.StatusForbidden, "Authorization Error", "Authorization could not be verified. Please try again.", sess.SessionID)
			return
		}
		if !inGroup {
			slog.Warn("callback: user not in required group",
				"sid", sess.SessionID,
				"group", sess.RequiredGroup,
				"email", claims.Email)
			s.denySession(sess, "not in required group")
			s.metrics.CallbackRejected("group_denied")
			s.renderError(w, http.StatusForbidden, "Access Denied", "You are not a member of the required group.", sess.SessionID)
			return
		}
	}

	// Step 9: All checks passed — send allow decision first, only then mark done.
	if err := s.sink.Send(auth.Decision{
		Type: auth.DecisionAllow,
		CID:  sess.CID,
		KID:  sess.KID,
	}); err != nil {
		slog.Error("callback: failed to send auth decision", "sid", sess.SessionID, "error", err)
		s.sessions.MarkFailed(sess.SessionID)
		s.metrics.CallbackRejected("send_failed")
		s.renderError(w, http.StatusServiceUnavailable, "Service Unavailable", "Failed to authorize VPN session. Please try again.", sess.SessionID)
		return
	}
	if s.tracker != nil {
		s.tracker.MarkAuthenticated(sess.CID, claims.CognitoUsername)
	}
	s.sessions.MarkDone(sess.SessionID)
	s.metrics.AuthSuccess()
	slog.Info("callback: auth success", "sid", sess.SessionID, "email", claims.Email)
	s.renderSuccess(w, claims.Email, sess.SessionID)
}

// handleHealthz returns the daemon health status for ALB target group health checks.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	connected := s.mgmtConnected()
	uptime := int64(time.Since(s.startTime).Seconds())
	storedSessions := s.sessions.Len()

	resp := healthzResponse{
		MgmtConnected:  connected,
		UptimeSeconds:  uptime,
		StoredSessions: storedSessions,
	}

	if connected {
		resp.Status = "ok"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	} else {
		resp.Status = "degraded"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// denySession marks the session as failed and sends client-deny.
func (s *Server) denySession(sess *auth.PendingSession, reason string) {
	s.sessions.MarkFailed(sess.SessionID)
	if err := s.sink.Send(auth.Decision{
		Type:   auth.DecisionDeny,
		CID:    sess.CID,
		KID:    sess.KID,
		Reason: reason,
	}); err != nil {
		slog.Warn("callback: failed to send deny decision", "sid", sess.SessionID, "error", err)
	}
	s.metrics.AuthDenied(reason)
}

// getOrFetchKey returns the cached public key for kid, fetching it if not cached.
func (s *Server) getOrFetchKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	s.keyCacheMu.RLock()
	key, ok := s.keyCache[kid]
	s.keyCacheMu.RUnlock()
	if ok {
		return key, nil
	}

	key, err := cognito.FetchALBPublicKey(ctx, s.albPublicKeyBaseURL, kid)
	if err != nil {
		return nil, err
	}

	s.keyCacheMu.Lock()
	s.keyCache[kid] = key
	s.keyCacheMu.Unlock()
	return key, nil
}

// decodeBase64URL decodes a base64url segment, tolerating padding (ALB JWTs
// use base64url WITH padding, unlike standard JWTs).
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// parseJWTHeader parses the header segment of a JWT (without verifying signature).
func parseJWTHeader(tokenStr string) (albJWTHeader, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return albJWTHeader{}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return albJWTHeader{}, fmt.Errorf("decode JWT header: %w", err)
	}

	var h albJWTHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return albJWTHeader{}, fmt.Errorf("unmarshal JWT header: %w", err)
	}
	return h, nil
}

// validateALBJWT verifies the ALB JWT signature, exp, iss, and signer field.
// It returns the base claims and, if extractGroups is true, the "cognito:groups"
// claim from the already-parsed token (avoiding a second decode pass).
func validateALBJWT(tokenStr string, pubKey *ecdsa.PublicKey, expectedARN, signerField, expectedIssuer string, extractGroups bool) (auth.ALBClaims, []string, error) {
	// Verify signer field from header matches expected ALB ARN.
	if signerField != expectedARN {
		return auth.ALBClaims{}, nil, fmt.Errorf("signer mismatch: got %q, want %q", signerField, expectedARN)
	}

	// Parse and verify the JWT using golang-jwt/jwt/v5.
	// ALB JWTs use base64url WITH padding; WithPaddingAllowed() tells the parser to accept it.
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	}, jwt.WithExpirationRequired(), jwt.WithPaddingAllowed())
	if err != nil {
		return auth.ALBClaims{}, nil, fmt.Errorf("jwt validation: %w", err)
	}

	mapClaims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || !token.Valid {
		return auth.ALBClaims{}, nil, fmt.Errorf("invalid jwt claims")
	}

	claims, err := extractALBClaims(mapClaims)
	if err != nil {
		return auth.ALBClaims{}, nil, err
	}

	if expectedIssuer != "" && claims.Iss != expectedIssuer {
		return auth.ALBClaims{}, nil, fmt.Errorf("iss mismatch: got %q, want %q", claims.Iss, expectedIssuer)
	}

	var groups []string
	if extractGroups {
		groups = extractGroupsFromRaw(map[string]interface{}(*mapClaims))
	}

	return claims, groups, nil
}

// parseJWTClaimsUnsafe parses JWT claims without signature verification (dev mode).
// Expiry (exp) is intentionally not checked — dev/test tokens use alg:none and
// may carry synthetic or omitted exp values. In production the ALB JWT path
// (validateALBJWT) enforces expiry via jwt.WithExpirationRequired().
// Returns the ALBClaims and any groups found in the "cognito:groups" claim.
func parseJWTClaimsUnsafe(tokenStr string) (auth.ALBClaims, []string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return auth.ALBClaims{}, nil, fmt.Errorf("invalid JWT format")
	}

	claimsBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return auth.ALBClaims{}, nil, fmt.Errorf("decode JWT claims: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &raw); err != nil {
		return auth.ALBClaims{}, nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	mc := jwt.MapClaims(raw)
	claims, err := extractALBClaims(&mc)
	if err != nil {
		return auth.ALBClaims{}, nil, err
	}
	groups := extractGroupsFromRaw(raw)
	return claims, groups, nil
}

// extractGroupsFromRaw reads the "cognito:groups" array from a raw claims map.
func extractGroupsFromRaw(raw map[string]interface{}) []string {
	v, ok := raw["cognito:groups"]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			groups = append(groups, s)
		}
	}
	return groups
}

// extractALBClaims pulls typed fields from a MapClaims.
func extractALBClaims(mc *jwt.MapClaims) (auth.ALBClaims, error) {
	raw := map[string]interface{}(*mc)

	email, _ := raw["email"].(string)
	sub, _ := raw["sub"].(string)
	iss, _ := raw["iss"].(string)
	cognitoUsername, _ := raw["cognito:username"].(string)

	if email == "" {
		return auth.ALBClaims{}, fmt.Errorf("missing or empty email claim")
	}

	var exp int64
	switch v := raw["exp"].(type) {
	case float64:
		exp = int64(v)
	case json.Number:
		n, _ := v.Int64()
		exp = n
	}

	return auth.ALBClaims{
		Sub:             sub,
		Email:           email,
		Exp:             exp,
		Iss:             iss,
		CognitoUsername: cognitoUsername,
	}, nil
}

// checkGroup resolves group membership either from JWT claims or via Cognito API.
func (s *Server) checkGroup(ctx context.Context, sess *auth.PendingSession, claims albJWTClaims) (bool, error) {
	if s.cfg.CognitoGroupsClaims {
		// Read groups directly from JWT claims.
		for _, g := range claims.Groups {
			if g == sess.RequiredGroup {
				return true, nil
			}
		}
		return false, nil
	}

	if s.identity == nil {
		return false, fmt.Errorf("no identity checker configured")
	}

	// Use CognitoUsername (cognito:username claim) — AdminGetUser requires the
	// actual Cognito username. For native users this is their email; for federated
	// users it is "{ProviderName}_{identifier}". Sub (UUID) only works for native
	// users and fails with UserNotFoundException for federated accounts.
	result, err := s.identity.CheckUser(ctx, claims.CognitoUsername, sess.RequiredGroup, true)
	if err != nil {
		return false, err
	}
	if !result.Enabled {
		return false, fmt.Errorf("user disabled or unconfirmed")
	}
	return result.InGroup, nil
}

// Start starts the HTTP server on the given address.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	slog.Info("callback server listening", "addr", addr)
	return s.Serve(ln)
}

// Serve accepts connections on the given listener. The caller is responsible
// for binding the port (e.g. via net.Listen) so that bind errors are detected
// synchronously before the daemon enters the event loop.
func (s *Server) Serve(ln net.Listener) error {
	s.server = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	if err := s.server.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}
