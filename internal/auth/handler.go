package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/mgmt"
)

// MaxWebAuthURLLen is the maximum URL length that OpenVPN CE clients can
// receive via the INFOMSG management interface buffer. The client allocates
// 256 bytes (alloc_buf_gc(256) in src/openvpn/push.c). The full INFOMSG line
// includes "WEB_AUTH::" (10 bytes) wrapping, the "OPEN_URL:" prefix (9 bytes),
// and a null terminator, so the practical limit for the URL itself is
// 256 - 10 - 9 - 1 = 236 bytes. We use 229 as a conservative limit to
// account for any additional framing overhead across OpenVPN versions.
// If exceeded, the client silently drops the message and the browser never opens.
const MaxWebAuthURLLen = 229

// sessionExpiry tracks the start time and cancellation handle for an
// established session's max-duration timer.
type sessionExpiry struct {
	connectedAt time.Time
	cancel      context.CancelFunc
}

type Handler struct {
	cfg      config.Config
	sessions *SessionStore
	identity IdentityChecker
	signer   StateSigner
	metrics  Metrics
	cache    *ReauthCache

	// timeoutSink is the daemon-level DecisionSink used by authTimeout
	// goroutines. Unlike the per-connection sink passed to HandleEvent,
	// this sink survives management socket reconnections so that timeout
	// denials can be delivered on the new connection.
	timeoutSink  DecisionSink
	lifecycleCtx context.Context

	mu            sync.Mutex
	inFlight      map[string]context.CancelFunc // CID → cancel
	cidToSID      map[string]string             // CID → session ID
	cidToCN       map[string]string             // CID → common_name (for cleanup)
	cidToKID      map[string]string             // CID → KID (for client-deny on eviction)
	cnToActiveCID map[string]string             // common_name → CID (one active session per user)
	cidToExpiry   map[string]*sessionExpiry     // CID → expiry state (established sessions with max-session-duration)
	promoted      map[string]struct{}           // CIDs that passed callback auth but haven't received ESTABLISHED yet
	liveSink      DecisionSink

	cidToCognitoUsername map[string]string // CID → cognito:username (for federated reauth)

	reauthWG sync.WaitGroup
}

func NewHandler(cfg config.Config, sessions *SessionStore, identity IdentityChecker, signer StateSigner, metrics Metrics) *Handler {
	var cache *ReauthCache
	if cfg.ReauthCache {
		cache = NewReauthCache(cfg.RenegInterval + 10*time.Minute)
	}

	return &Handler{
		cfg:                  cfg,
		sessions:             sessions,
		identity:             identity,
		signer:               signer,
		metrics:              metrics,
		cache:                cache,
		inFlight:             make(map[string]context.CancelFunc),
		cidToSID:             make(map[string]string),
		cidToCN:              make(map[string]string),
		cidToKID:             make(map[string]string),
		cnToActiveCID:        make(map[string]string),
		cidToExpiry:          make(map[string]*sessionExpiry),
		promoted:             make(map[string]struct{}),
		cidToCognitoUsername: make(map[string]string),
	}
}

// SetTimeoutSink sets the daemon-level sink used by authTimeout goroutines.
// Must be called before any events are handled.
func (h *Handler) SetTimeoutSink(sink DecisionSink) {
	h.timeoutSink = sink
}

// SetLifecycleContext sets the long-lived daemon context used by session-expiry
// timers. Must be called before any auth-success promotions happen.
func (h *Handler) SetLifecycleContext(ctx context.Context) {
	h.lifecycleCtx = ctx
}

// SetLiveSink sets the sink for connection-bound actions that must never be
// replayed after a management reconnect (for example hard-expiry client-kill).
func (h *Handler) SetLiveSink(sink DecisionSink) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.liveSink = sink
}

func (h *Handler) ClearLiveSink() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.liveSink = nil
}

func (h *Handler) InFlight() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.inFlight)
}

// WaitReauth blocks until all in-flight REAUTH goroutines complete.
func (h *Handler) WaitReauth() {
	h.reauthWG.Wait()
}

func (h *Handler) HandleEvent(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	switch event.Type {
	case mgmt.EventConnect:
		h.handleConnect(ctx, event, sink)
	case mgmt.EventReauth:
		h.reauthWG.Go(func() {
			h.handleReauth(ctx, event, sink)
		})
	case mgmt.EventDisconnect:
		slog.Info("disconnect", "cid", event.CID)
		h.handleDisconnect(event)
	case mgmt.EventEstablished:
		slog.Info("established", "cid", event.CID)
		h.promoteSession(event.CID)
		h.onEstablished(event.CID)
	}
}

func (h *Handler) handleConnect(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	sso := strings.ToLower(event.Env["IV_SSO"])
	if !strings.Contains(sso, "webauth") && !strings.Contains(sso, "openurl") {
		h.metrics.AuthDenied("no_webauth")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "client does not support WebAuth"})
		return
	}
	if event.CommonName() == "" {
		slog.Warn("connect denied", "cid", event.CID, "reason", "missing common name")
		h.metrics.AuthDenied("missing_common_name")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
		return
	}

	slog.Info("connect", "cid", event.CID, "kid", event.KID, "cn", event.CommonName())

	// Enforce one active session per user: if a session already exists for this
	// common name (e.g. DISCONNECT was lost), evict it and deny/kill it on the
	// management interface so OpenVPN drops the stale connection immediately.
	if h.cfg.SingleSessionPerUser {
		h.mu.Lock()
		existingCID, active := h.cnToActiveCID[event.CommonName()]
		h.mu.Unlock()
		if active && existingCID != event.CID {
			if d, evicted := h.evictSession(existingCID); evicted {
				action := "client-deny"
				if d.Type == DecisionKill {
					action = "client-kill"
				}
				slog.Info("evict", "cn", event.CommonName(), "old_cid", existingCID, "new_cid", event.CID, "action", action)
				sendOrLog(sink, d)
			}
		}
	}

	sessionID, err := generateRandomToken(16)
	if err != nil {
		h.metrics.AuthDenied("internal_error")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "internal error"})
		return
	}

	now := time.Now().UTC()
	session := &PendingSession{
		SessionID:     sessionID,
		CommonName:    event.CommonName(),
		CID:           event.CID,
		KID:           event.KID,
		Username:      event.Username(),
		CNCrossCheck:  h.cfg.CNCrossCheck,
		RequiredGroup: h.cfg.RequiredGroup,
		Status:        SessionPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(2 * h.cfg.HandWindow),
	}
	stateBlob := EncodeState(StatePayload{
		SID: sessionID,
		IAT: now.Unix(),
		EXP: now.Add(h.cfg.AuthTimeout).Unix(),
	}, h.signer)

	sep := "?"
	if strings.Contains(h.cfg.CallbackURL, "?") {
		sep = "&"
	}
	authURL := fmt.Sprintf("%s%sstate=%s", strings.TrimRight(h.cfg.CallbackURL, "/"), sep, stateBlob)

	// OpenVPN CE clients silently drop WEB_AUTH URLs exceeding the INFOMSG
	// buffer limit — fail loudly here instead.
	// MaxWebAuthURLLen already accounts for all protocol framing (WEB_AUTH::,
	// OPEN_URL: prefix, null terminator), so compare against the raw URL length.
	if len(authURL) > MaxWebAuthURLLen {
		slog.Error("WEB_AUTH URL exceeds OpenVPN CE INFOMSG limit",
			"url_len", len(authURL), "max", MaxWebAuthURLLen,
			"cid", event.CID, "cn", event.CommonName())
		h.metrics.AuthDenied("url_too_long")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "auth URL too long"})
		return
	}

	h.sessions.Put(session)

	slog.Info("connect pending auth", "cid", event.CID, "cn", event.CommonName(), "timeout", h.cfg.AuthTimeout)
	h.metrics.AuthAttempt("")
	timeout := int(h.cfg.HandWindow.Seconds())
	sendOrLog(sink, Decision{
		Type:    DecisionPending,
		CID:     event.CID,
		KID:     event.KID,
		URL:     authURL,
		Timeout: timeout,
	})

	// Timeout goroutine: deny + cleanup if callback doesn't arrive in time.
	// Use the daemon-level timeoutSink so denials survive socket reconnections.
	tSink := h.timeoutSink
	if tSink == nil {
		tSink = sink // fallback for tests
	}
	timeoutCtx, cancel := context.WithCancel(ctx)
	h.setInFlight(event.CID, sessionID, event.CommonName(), event.KID, cancel)
	go h.authTimeout(timeoutCtx, session, tSink)
}

func (h *Handler) authTimeout(ctx context.Context, session *PendingSession, sink DecisionSink) {
	defer h.clearInFlight(session.CID)

	timer := time.NewTimer(h.cfg.AuthTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		// Only deny if session is still PENDING (not already processed by callback)
		_, err := h.sessions.TryProcess(session.SessionID)
		if err != nil {
			// Already processed or gone — nothing to do
			return
		}
		h.sessions.MarkFailed(session.SessionID)
		slog.Warn("connect auth timeout", "cid", session.CID, "cn", session.CommonName)
		h.metrics.AuthDenied("timeout")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: session.CID, KID: session.KID, Reason: "auth timeout"})
	}
}

func (h *Handler) handleReauth(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	h.mu.Lock()
	lookup, ok := h.cidToCognitoUsername[event.CID]
	h.mu.Unlock()
	if !ok || lookup == "" {
		lookup = event.CommonName()
	}
	if lookup == "" {
		slog.Warn("reauth denied", "cid", event.CID, "reason", "missing common name")
		h.metrics.ReauthDenied("missing_common_name")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
		return
	}

	slog.Info("reauth", "cid", event.CID, "cn", lookup)

	// Session duration backstop — deny if session exceeded max duration.
	// Must be checked before skip-reauth, cache, and Cognito to prevent bypasses.
	if h.cfg.MaxSessionDuration > 0 {
		// exp is a snapshot pointer: replaceExpiryState always creates a new
		// *sessionExpiry rather than mutating the existing one, so reading
		// exp.connectedAt after releasing the lock is safe — the pointer is
		// stable even if the map entry is replaced concurrently.
		h.mu.Lock()
		exp, tracked := h.cidToExpiry[event.CID]
		h.mu.Unlock()
		if !tracked {
			slog.Warn("reauth denied: session tracking lost", "cid", event.CID, "cn", lookup)
			h.metrics.ReauthDenied("session_untracked")
			sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "session revalidation required; reconnect"})
			return
		}
		if time.Since(exp.connectedAt) > h.cfg.MaxSessionDuration {
			slog.Warn("reauth denied: session expired", "cid", event.CID, "cn", lookup,
				"connected_at", exp.connectedAt, "max_duration", h.cfg.MaxSessionDuration)
			h.metrics.SessionExpired("reauth_backstop")
			sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "session expired"})
			return
		}
	}

	if h.cfg.CognitoSkipReauth {
		slog.Info("reauth allowed (skip-reauth)", "cid", event.CID, "cn", lookup)
		h.metrics.ReauthSuccess()
		sendOrLog(sink, Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, h.cfg.ReauthTimeout)
	defer cancel()

	result, err := h.identity.CheckUser(checkCtx, lookup, h.cfg.RequiredGroup, h.cfg.CheckGroupsOnReauth)
	if err == nil {
		if h.cache != nil {
			h.cache.Put(lookup, result)
		}
		h.finishReauth(event, result, sink)
		return
	}

	if h.cache != nil {
		if cached, ok := h.cache.Get(lookup); ok && cached.Exists && cached.Enabled && (!h.cfg.CheckGroupsOnReauth || cached.InGroup) {
			slog.Info("reauth allowed", "cid", event.CID, "cn", lookup, "source", "cache", "cognito_error", err)
			h.metrics.ReauthCacheHit()
			sendOrLog(sink, Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
			return
		}
	}

	slog.Warn("reauth denied", "cid", event.CID, "cn", lookup, "reason", "cognito unavailable", "error", err)
	h.metrics.ReauthDenied("cognito_error")
	sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "cognito unavailable"})
}

func (h *Handler) finishReauth(event mgmt.Event, result IdentityResult, sink DecisionSink) {
	if !result.Exists {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "user not found")
		h.metrics.ReauthDenied("user_not_found")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user not found"})
		return
	}
	if !result.Enabled {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "user disabled")
		h.metrics.ReauthDenied("user_disabled")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user disabled"})
		return
	}
	if h.cfg.CheckGroupsOnReauth && !result.InGroup {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "group denied", "group", h.cfg.RequiredGroup)
		h.metrics.ReauthDenied("group_denied")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: fmt.Sprintf("not in required group: %s", h.cfg.RequiredGroup)})
		return
	}
	slog.Info("reauth allowed", "cid", event.CID, "cn", event.CommonName())
	h.metrics.ReauthSuccess()
	sendOrLog(sink, Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
}

// evictSession forcibly removes a session for a CID.
// For in-flight sessions (pending auth) it cancels the goroutine and returns
// DecisionDeny so the caller can send client-deny.
// For established sessions (auth already done) it returns DecisionKill so the
// caller can send client-kill.
// Returns the decision type and whether an eviction actually happened.
func (h *Handler) evictSession(cid string) (Decision, bool) {
	h.mu.Lock()
	cancel, inFlight := h.inFlight[cid]
	sid := h.cidToSID[cid]
	cn := h.cidToCN[cid]
	kid := h.cidToKID[cid]
	exp := h.cidToExpiry[cid]
	// Clean up all tracking for this CID.
	delete(h.inFlight, cid)
	delete(h.cidToSID, cid)
	delete(h.cidToCN, cid)
	delete(h.cidToKID, cid)
	delete(h.cidToExpiry, cid)
	delete(h.promoted, cid)
	delete(h.cidToCognitoUsername, cid)
	if cn != "" && h.cnToActiveCID[cn] == cid {
		delete(h.cnToActiveCID, cn)
	}
	h.mu.Unlock()

	if inFlight {
		cancel()
	}
	if exp != nil {
		exp.cancel()
	}
	if sid != "" {
		h.sessions.Delete(sid)
	}

	// Nothing tracked at all — nothing to evict.
	if !inFlight && cn == "" {
		return Decision{}, false
	}

	if inFlight {
		// Still pending auth — use client-deny (requires KID).
		return Decision{Type: DecisionDeny, CID: cid, KID: kid, Reason: "replaced by new connection"}, true
	}
	// Already established — use client-kill (no KID needed).
	return Decision{Type: DecisionKill, CID: cid}, true
}

func (h *Handler) handleDisconnect(event mgmt.Event) {
	h.mu.Lock()
	cancel, ok := h.inFlight[event.CID]
	sid := h.cidToSID[event.CID]
	cn := h.cidToCN[event.CID]
	exp := h.cidToExpiry[event.CID]
	delete(h.inFlight, event.CID)
	delete(h.cidToSID, event.CID)
	delete(h.cidToCN, event.CID)
	delete(h.cidToKID, event.CID)
	delete(h.cidToExpiry, event.CID)
	delete(h.promoted, event.CID)
	delete(h.cidToCognitoUsername, event.CID)
	if cn != "" && h.cnToActiveCID[cn] == event.CID {
		delete(h.cnToActiveCID, cn)
	}
	h.mu.Unlock()
	if ok {
		cancel()
	}
	if exp != nil {
		exp.cancel()
	}
	if sid != "" {
		h.sessions.Delete(sid)
	}
}

// promoteSession transitions a CID out of the pending-auth (inFlight) state.
// It cancels the auth-timeout goroutine, removes the pending session from the
// store, and marks the CID as promoted so that RebuildSessionTrackingFromStatus
// preserves its tracking across management reconnects.
//
// It does NOT start the expiry timer — that is deferred to onEstablished, which
// anchors the timer to OpenVPN's actual connected time rather than callback time.
//
// CN→CID tracking is kept so single-session-per-user eviction still works
// until DISCONNECT cleans it up.
//
// Called from both MarkAuthenticated (callback success) and EventEstablished.
// The second call is idempotent: inFlight[cid] is already deleted so the
// !ok early return fires.
func (h *Handler) promoteSession(cid string) {
	h.mu.Lock()
	cancel, ok := h.inFlight[cid]
	sid := h.cidToSID[cid]
	if ok {
		delete(h.inFlight, cid)
		delete(h.cidToSID, cid)
		h.promoted[cid] = struct{}{} // track until ESTABLISHED arrives
		// Keep cidToCN and cnToActiveCID — session is established, not gone.
	}
	h.mu.Unlock()
	if !ok {
		return // stray/duplicate ESTABLISHED for unknown CID — nothing to promote
	}
	cancel()
	if sid != "" {
		h.sessions.Delete(sid)
	}
}

// onEstablished is called when CLIENT:ESTABLISHED arrives. It clears the
// promoted marker and starts the expiry timer anchored to time.Now() (the
// actual establishment time, not the earlier callback time).
//
// Only CIDs that were callback-promoted (in the promoted set) get a new timer.
// CIDs already restored from a status snapshot during reconnect bootstrap
// already have a snapshot-anchored timer — a duplicate ESTABLISHED must not
// reset it, as that would extend --max-session-duration.
func (h *Handler) onEstablished(cid string) {
	h.mu.Lock()
	_, wasPromoted := h.promoted[cid]
	delete(h.promoted, cid)
	h.mu.Unlock()

	if !wasPromoted {
		return
	}

	if h.cfg.MaxSessionDuration > 0 {
		h.startExpiryTimer(cid, time.Now())
	}
}

// MarkAuthenticated is called after callback success sends client-auth. It
// promotes the CID out of in-flight state so the auth-timeout goroutine stops.
// The expiry timer is NOT started here — it waits for CLIENT:ESTABLISHED to
// anchor to the actual connected time.
//
// # Race window (M19 / Requirements 2.8)
//
// The callback server calls sink.Send(DecisionAllow) before calling
// MarkAuthenticated. sink.Send only enqueues the allow command to cmdCh — it
// does NOT guarantee the command was written to the OpenVPN management socket.
// If the socket drops between enqueue and write, the CID is added to the
// promoted set here but OpenVPN never receives the client-auth command, so the
// client is never established. The CID then remains in the promoted set
// indefinitely with no timeout, creating a stale tracking entry.
//
// # Self-healing path
//
// When SingleSessionPerUser=true, the stale promoted entry is evicted
// automatically on the next CLIENT:CONNECT for the same CN: handleConnect
// calls evictSession, which removes the CID from promoted, cidToCN, cidToKID,
// and cnToActiveCID. The leak is therefore bounded to at most one entry per CN
// at any given time.
//
// # Acceptance criteria (option b from Requirements 2.8)
//
// This race window is accepted as-is for three reasons:
//
//	(a) Management socket drops during an active auth flow are rare in practice;
//	    the socket is a local Unix domain socket on the same host.
//	(b) The self-healing path above bounds the leak to one stale entry per CN,
//	    so the impact on memory and session-enforcement correctness is minimal.
//	(c) A proper fix — a write-acknowledgement channel between the callback
//	    flow and the management command writer — would require significant
//	    restructuring of the command pipeline and is not justified by the
//	    low probability and bounded impact of the race.
func (h *Handler) MarkAuthenticated(cid, cognitoUsername string) {
	h.mu.Lock()
	if cognitoUsername != "" {
		h.cidToCognitoUsername[cid] = cognitoUsername
	}
	h.mu.Unlock()
	h.promoteSession(cid)
}

func (h *Handler) setInFlight(cid, sid, cn, kid string, cancel context.CancelFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight[cid] = cancel
	h.cidToSID[cid] = sid
	h.cidToCN[cid] = cn
	h.cidToKID[cid] = kid
	if h.cfg.SingleSessionPerUser {
		h.cnToActiveCID[cn] = cid
	}
}

// isPromoted reports whether the CID has been promoted via MarkAuthenticated
// but has not yet received CLIENT:ESTABLISHED. Caller must hold h.mu.
func (h *Handler) isPromoted(cid string) bool {
	_, ok := h.promoted[cid]
	return ok
}

func (h *Handler) clearInFlight(cid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.inFlight, cid)
	delete(h.cidToSID, cid)
	// Leave cidToCN, cidToKID, cnToActiveCID — DISCONNECT will clean those up.
}

func (h *Handler) startExpiryTimer(cid string, connectedAt time.Time) {
	expiryCtx := h.replaceExpiryState(cid, connectedAt)
	remaining := time.Until(connectedAt.Add(h.cfg.MaxSessionDuration))
	if remaining < 0 {
		remaining = 0
	}
	go h.sessionExpiryTimer(expiryCtx, cid, remaining)
}

func (h *Handler) replaceExpiryState(cid string, connectedAt time.Time) context.Context {
	// Safety net: SetLifecycleContext must be called before any promotions
	// (enforced by daemon setup in app.go). This fallback prevents a nil-context
	// panic but means expiry timers would not be cancelled on graceful shutdown.
	baseCtx := h.lifecycleCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	expiryCtx, expiryCancel := context.WithCancel(baseCtx)

	h.mu.Lock()
	if existing := h.cidToExpiry[cid]; existing != nil {
		existing.cancel()
	}
	h.cidToExpiry[cid] = &sessionExpiry{
		connectedAt: connectedAt,
		cancel:      expiryCancel,
	}
	h.mu.Unlock()
	return expiryCtx
}

// RebuildSessionTrackingFromStatus rebuilds active-session tracking from a fresh
// management status snapshot after reconnect or restart.
// RebuildSessionTrackingFromStatus reconciles in-memory session tracking maps
// against the current management socket status snapshot. It is called on every
// management socket reconnect (reconnect-bootstrap sweep).
//
// L1 mitigation (accepted, option b): if a CLIENT:DISCONNECT event is lost
// during a management socket reconnect, the corresponding entries in cidToCN,
// cidToKID, and cnToActiveCID would otherwise persist indefinitely. This sweep
// provides bounded cleanup: any CID that is not in the live status snapshot AND
// is not currently in-flight (inFlight) AND has not been promoted (promoted) is
// removed from all three maps. Because the daemon reconnects to the management
// socket whenever the connection drops — the same event that can cause a
// DISCONNECT to be lost — this sweep fires at exactly the right moment to
// reclaim stale entries. No additional periodic reaper is required.
func (h *Handler) RebuildSessionTrackingFromStatus(sessions []mgmt.EstablishedSession) {
	snapshot := make(map[string]mgmt.EstablishedSession, len(sessions))
	for _, sess := range sessions {
		snapshot[sess.CID] = sess
	}

	h.mu.Lock()
	// Deleting from a map during range is safe in Go (spec-guaranteed).
	for cid, exp := range h.cidToExpiry {
		if _, ok := snapshot[cid]; !ok {
			exp.cancel()
			delete(h.cidToExpiry, cid)
		}
	}
	if h.cfg.SingleSessionPerUser {
		for cn, cid := range h.cnToActiveCID {
			if _, ok := snapshot[cid]; !ok && h.inFlight[cid] == nil && !h.isPromoted(cid) {
				delete(h.cnToActiveCID, cn)
			}
		}
	}
	for cid, cn := range h.cidToCN {
		if _, ok := snapshot[cid]; !ok && h.inFlight[cid] == nil && !h.isPromoted(cid) {
			delete(h.cidToCN, cid)
			delete(h.cidToKID, cid)
			if h.cfg.SingleSessionPerUser && h.cnToActiveCID[cn] == cid {
				delete(h.cnToActiveCID, cn)
			}
		}
	}
	// Clean promoted markers for CIDs that appear in the snapshot — they are
	// fully established now and will get fresh expiry timers below.
	for _, sess := range sessions {
		delete(h.promoted, sess.CID)
	}
	h.mu.Unlock()

	for _, sess := range sessions {
		h.mu.Lock()
		h.cidToCN[sess.CID] = sess.CommonName
		if h.cfg.SingleSessionPerUser {
			h.cnToActiveCID[sess.CommonName] = sess.CID
		}
		h.mu.Unlock()

		if h.cfg.MaxSessionDuration > 0 {
			if time.Since(sess.ConnectedAt) >= h.cfg.MaxSessionDuration {
				h.replaceExpiryState(sess.CID, sess.ConnectedAt)
				h.killExpiredSession(sess.CID, sess.CommonName, sess.ConnectedAt)
				continue
			}
			h.startExpiryTimer(sess.CID, sess.ConnectedAt)
		}
	}
}

func (h *Handler) sessionExpiryTimer(ctx context.Context, cid string, remaining time.Duration) {
	// No defer clearExpiry here: if client-kill fails (e.g. socket disconnected),
	// the cidToExpiry entry must remain so the reauth backstop can still catch
	// the expired session. Cleanup happens in handleDisconnect or evictSession.

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		h.mu.Lock()
		exp, ok := h.cidToExpiry[cid]
		cn := h.cidToCN[cid]
		h.mu.Unlock()
		if !ok {
			return
		}
		h.killExpiredSession(cid, cn, exp.connectedAt)
	}
}

func (h *Handler) killExpiredSession(cid, cn string, connectedAt time.Time) {
	h.mu.Lock()
	sink := h.liveSink
	h.mu.Unlock()

	slog.Warn("session expired", "cid", cid, "cn", cn,
		"connected_at", connectedAt,
		"duration", time.Since(connectedAt))
	h.metrics.SessionExpired("hard_timer")
	if sink == nil {
		slog.Warn("session expired while management disconnected; waiting for reconnect or reauth", "cid", cid, "cn", cn)
		return
	}
	// A concurrent DISCONNECT can win after the lock is released but before
	// client-kill is written. That race is acceptable: avoiding I/O under the
	// mutex is more important, and OpenVPN tolerates kill requests for a CID
	// that has already gone away.
	sendOrLog(sink, Decision{Type: DecisionKill, CID: cid})
}

// sendOrLog sends a decision and logs a warning if the send fails.
// Used for handler-internal decisions (deny, pending, kill) where the
// caller cannot recover from a send failure.
func sendOrLog(sink DecisionSink, d Decision) {
	if err := sink.Send(d); err != nil {
		slog.Warn("failed to send decision", "type", d.Type, "cid", d.CID, "error", err)
	}
}

func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
