package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
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

// cidState holds all per-connection tracking state for a single CID.
// It is stored as a pointer in Handler.cids so that partial updates
// (e.g. clearing cancel/sid in clearInFlight while keeping cn/kid for
// a later DISCONNECT) are possible without re-inserting into the map.
type cidState struct {
	cancel            context.CancelFunc // non-nil while pending auth (in-flight)
	sid               string             // session ID while in-flight
	cn                string             // common_name
	identity          string             // normalized ownership identity
	kid               string             // KID (for client-deny on eviction)
	connectAt         time.Time          // original CLIENT:CONNECT time
	expiry            *sessionExpiry     // non-nil when established with max-session-duration
	promoted          bool               // passed callback but not yet ESTABLISHED
	promotedCancel    context.CancelFunc // establishment deadline/re-check cancellation
	established       bool               // confirmed by event or status
	evictionRequested bool               // replacement kill sent; retain until confirmed gone
	cognitoUsername   string             // for federated reauth
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

	mu                   sync.Mutex
	cids                 map[string]*cidState // CID → per-connection state
	identityToActiveCID  map[string]string    // normalized identity → established active CID
	identityToAttemptCID map[string]string    // normalized identity → pending/processing/promoted CID
	liveSink             DecisionSink
	statusProvider       StatusProvider
	promotedRecheckDelay time.Duration

	reauthWG sync.WaitGroup
}

type StatusProvider interface {
	Status(context.Context) (mgmt.StatusSnapshot, error)
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
		cids:                 make(map[string]*cidState),
		identityToActiveCID:  make(map[string]string),
		identityToAttemptCID: make(map[string]string),
		promotedRecheckDelay: 5 * time.Second,
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

func (h *Handler) SetStatusProvider(provider StatusProvider) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statusProvider = provider
}

func (h *Handler) ClearStatusProvider() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statusProvider = nil
}

func (h *Handler) InFlight() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, st := range h.cids {
		if st.cancel != nil {
			count++
		}
	}
	return count
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
		slog.Warn("connect denied", "cid", event.CID, "kid", event.KID, "cn", event.CommonName(), "reason", "client does not support WebAuth", "iv_sso", event.Env["IV_SSO"])
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
	identity, err := NormalizeIdentity(event.CommonName())
	if err != nil {
		slog.Warn("connect denied", "cid", event.CID, "cn", event.CommonName(), "reason", "invalid identity", "error", err)
		h.metrics.AuthDenied("invalid_identity")
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "invalid identity"})
		return
	}

	guiVer := event.Env["IV_GUI_VER"]
	if guiVer == "" {
		guiVer = event.Env["IV_UI_VER"]
	}
	slog.Info("connect", "cid", event.CID, "kid", event.KID, "cn", event.CommonName(),
		"ip", event.Env["untrusted_ip"],
		"port", event.Env["untrusted_port"],
		"hwaddr", event.Env["IV_HWADDR"],
		"plat", event.Env["IV_PLAT"],
		"plat_ver", event.Env["IV_PLAT_VER"],
		"ver", event.Env["IV_VER"],
		"gui_ver", guiVer,
		"ssl", event.Env["IV_SSL"],
	)

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

	timeoutCtx, cancel := context.WithCancel(ctx)
	var superseded *cidState
	var oldAttemptCID string
	var supersededCancel context.CancelFunc
	h.mu.Lock()
	if existingCID := h.identityToAttemptCID[identity]; existingCID != "" {
		if existingCID == event.CID {
			h.mu.Unlock()
			cancel()
			slog.Info("duplicate connect ignored", "cid", event.CID, "identity", identity)
			return
		}
		existing := h.cids[existingCID]
		switch {
		case existing == nil:
			delete(h.identityToAttemptCID, identity)
		case existing.promoted:
			provider := h.statusProvider
			h.mu.Unlock()
			cancel()
			if provider != nil {
				snapshot, statusErr := provider.Status(ctx)
				if statusErr == nil {
					client, present := snapshot.ClientByCID(existingCID)
					if !present {
						h.cleanupPromoted(existingCID)
						h.handleConnect(ctx, event, sink)
						return
					}
					if client.Established {
						h.establishCID(existingCID, client.ConnectedAt, true)
					}
				} else {
					slog.Warn("promoted conflict status failed", "cid", existingCID, "error", statusErr)
				}
			}
			h.metrics.AuthDenied("auth_in_progress")
			sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "authentication already in progress; retry connection"})
			return
		case existing.cancel != nil:
			if _, supersedeErr := h.sessions.SupersedePending(existing.sid); supersedeErr != nil {
				h.mu.Unlock()
				cancel()
				h.metrics.AuthDenied("auth_in_progress")
				sendOrLog(sink, Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "authentication already in progress; retry connection"})
				return
			}
			superseded = existing
			oldAttemptCID = existingCID
			supersededCancel = existing.cancel
			existing.cancel = nil
			existing.sid = ""
		default:
			delete(h.identityToAttemptCID, identity)
		}
	}
	h.sessions.Put(session)
	h.cids[event.CID] = &cidState{
		cancel:    cancel,
		sid:       sessionID,
		cn:        event.CommonName(),
		identity:  identity,
		kid:       event.KID,
		connectAt: now,
	}
	h.identityToAttemptCID[identity] = event.CID
	h.mu.Unlock()

	if superseded != nil {
		supersededCancel()
		slog.Info("pending attempt superseded", "identity", identity, "old_cid", oldAttemptCID, "new_cid", event.CID)
		sendOrLog(sink, Decision{Type: DecisionDeny, CID: oldAttemptCID, KID: superseded.kid, Reason: "replaced by new connection"})
	}

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
	var lookup string
	if st := h.cids[event.CID]; st != nil {
		lookup = st.cognitoUsername
	}
	h.mu.Unlock()
	if lookup == "" {
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
		var exp *sessionExpiry
		if st := h.cids[event.CID]; st != nil {
			exp = st.expiry
		}
		h.mu.Unlock()
		if exp == nil {
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

	result, err := h.identity.CheckUser(checkCtx, lookup, h.cfg.RequiredGroup, h.cfg.CheckRequiredGroupOnReauth)
	if err == nil {
		if h.cache != nil {
			h.cache.Put(lookup, result)
		}
		h.finishReauth(event, result, sink)
		return
	}

	if h.cache != nil {
		if cached, ok := h.cache.Get(lookup); ok && cached.Exists && cached.Enabled && (!h.cfg.CheckRequiredGroupOnReauth || cached.InGroup) {
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
	if h.cfg.CheckRequiredGroupOnReauth && !result.InGroup {
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
	st := h.cids[cid]
	delete(h.cids, cid)
	if st != nil && h.identityToActiveCID[st.identity] == cid {
		delete(h.identityToActiveCID, st.identity)
	}
	if st != nil && h.identityToAttemptCID[st.identity] == cid {
		delete(h.identityToAttemptCID, st.identity)
	}
	h.mu.Unlock()

	if st == nil {
		return Decision{}, false
	}

	inFlight := st.cancel != nil
	if inFlight {
		st.cancel()
	}
	if st.expiry != nil {
		st.expiry.cancel()
	}
	if st.promotedCancel != nil {
		st.promotedCancel()
	}
	if st.sid != "" {
		h.sessions.Delete(st.sid)
	}

	// Nothing tracked at all — nothing to evict.
	if !inFlight && st.cn == "" {
		return Decision{}, false
	}

	if inFlight {
		// Still pending auth — use client-deny (requires KID).
		return Decision{Type: DecisionDeny, CID: cid, KID: st.kid, Reason: "replaced by new connection"}, true
	}
	// Already established — use client-kill (no KID needed).
	return Decision{Type: DecisionKill, CID: cid, KillMode: "HALT"}, true
}

func (h *Handler) handleDisconnect(event mgmt.Event) {
	h.mu.Lock()
	st := h.cids[event.CID]
	delete(h.cids, event.CID)
	if st != nil && h.identityToActiveCID[st.identity] == event.CID {
		delete(h.identityToActiveCID, st.identity)
	}
	if st != nil && h.identityToAttemptCID[st.identity] == event.CID {
		delete(h.identityToAttemptCID, st.identity)
	}
	h.mu.Unlock()
	if st == nil {
		return
	}
	if st.cancel != nil {
		st.cancel()
	}
	if st.expiry != nil {
		st.expiry.cancel()
	}
	if st.promotedCancel != nil {
		st.promotedCancel()
	}
	if st.sid != "" {
		h.sessions.Delete(st.sid)
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
// CN→CID tracking is kept until DISCONNECT cleans it up.
//
// Called from both MarkAuthenticated (callback success) and EventEstablished.
// The second call is idempotent: st.cancel == nil means already promoted, so
// the early return fires.
func (h *Handler) promoteSession(cid string) {
	h.mu.Lock()
	st := h.cids[cid]
	if st == nil || st.cancel == nil {
		h.mu.Unlock()
		return // stray/duplicate ESTABLISHED or already promoted — nothing to do
	}
	cancel := st.cancel
	sid := st.sid
	connectAt := st.connectAt
	if connectAt.IsZero() {
		connectAt = time.Now().UTC()
		st.connectAt = connectAt
	}
	baseCtx := h.lifecycleCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	promotedCtx, promotedCancel := context.WithCancel(baseCtx)
	st.cancel = nil // no longer in-flight
	st.sid = ""
	st.promoted = true // track until ESTABLISHED arrives
	st.promotedCancel = promotedCancel
	h.mu.Unlock()

	cancel()
	if sid != "" {
		h.sessions.Delete(sid)
	}
	go h.waitForPromotedDeadline(promotedCtx, cid, connectAt.Add(h.cfg.HandWindow))
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
	h.establishCID(cid, time.Now(), false)
}

func (h *Handler) establishCID(cid string, connectedAt time.Time, authoritativeSnapshot bool) {
	h.mu.Lock()
	st := h.cids[cid]
	wasPromoted := st != nil && st.promoted
	if st == nil {
		h.mu.Unlock()
		return
	}
	wasEstablished := st.established
	st.promoted = false
	st.established = true
	if st.promotedCancel != nil {
		st.promotedCancel()
		st.promotedCancel = nil
	}
	if h.identityToAttemptCID[st.identity] == cid {
		delete(h.identityToAttemptCID, st.identity)
	}
	oldCID := h.identityToActiveCID[st.identity]
	h.identityToActiveCID[st.identity] = cid
	if oldCID != "" && oldCID != cid {
		if oldState := h.cids[oldCID]; oldState != nil {
			oldState.evictionRequested = true
			if oldState.expiry != nil {
				oldState.expiry.cancel()
				oldState.expiry = nil
			}
		}
	}
	sink := h.liveSink
	h.mu.Unlock()

	if h.cfg.MaxSessionDuration > 0 && (wasPromoted || authoritativeSnapshot) && !wasEstablished {
		h.startExpiryTimer(cid, connectedAt)
	}

	if oldCID != "" && oldCID != cid {
		if sink == nil {
			slog.Warn("active replacement established while management sink unavailable", "identity", st.identity, "old_cid", oldCID, "new_cid", cid)
			return
		}
		slog.Info("active eviction requested", "identity", st.identity, "old_cid", oldCID, "new_cid", cid)
		h.killReplacedActive(oldCID, cid, st.identity, sink)
	}
}

func (h *Handler) killReplacedActive(oldCID, newCID, identity string, sink DecisionSink) {
	decision := Decision{Type: DecisionKill, CID: oldCID, KillMode: "HALT"}
	var err error
	if ackSink, ok := sink.(AckDecisionSink); ok {
		err = ackSink.SendAck(decision)
	} else {
		err = sink.Send(decision)
	}
	if err == nil {
		return
	}

	slog.Warn("active eviction command failed", "identity", identity, "old_cid", oldCID, "new_cid", newCID, "error", err)
	h.mu.Lock()
	provider := h.statusProvider
	h.mu.Unlock()
	if provider == nil {
		return
	}
	snapshot, statusErr := provider.Status(context.Background())
	if statusErr != nil {
		slog.Warn("active eviction reconciliation failed", "identity", identity, "old_cid", oldCID, "error", statusErr)
		return
	}
	if _, present := snapshot.ClientByCID(oldCID); !present {
		h.handleDisconnect(mgmt.Event{Type: mgmt.EventDisconnect, CID: oldCID})
	}
}

func (h *Handler) waitForPromotedDeadline(ctx context.Context, cid string, deadline time.Time) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	client, outcome := h.reconcilePromoted(ctx, cid)
	if outcome != "pending" {
		return
	}

	grace := time.NewTimer(h.promotedRecheckDelay)
	defer grace.Stop()
	select {
	case <-ctx.Done():
		return
	case <-grace.C:
	}

	client, outcome = h.reconcilePromoted(ctx, cid)
	if outcome != "pending" {
		return
	}
	h.killStalledPromoted(ctx, cid, client.CommonName)
}

func (h *Handler) reconcilePromoted(ctx context.Context, cid string) (mgmt.StatusClient, string) {
	h.mu.Lock()
	provider := h.statusProvider
	h.mu.Unlock()
	if provider == nil {
		return mgmt.StatusClient{}, "unavailable"
	}
	snapshot, err := provider.Status(ctx)
	if err != nil {
		slog.Warn("promoted reconciliation failed", "cid", cid, "error", err)
		return mgmt.StatusClient{}, "unavailable"
	}
	client, present := snapshot.ClientByCID(cid)
	if !present {
		h.cleanupPromoted(cid)
		slog.Info("promoted reconciled absent", "cid", cid)
		return mgmt.StatusClient{}, "absent"
	}
	if client.Established {
		h.establishCID(cid, client.ConnectedAt, true)
		slog.Info("promoted reconciled established", "cid", cid)
		return client, "established"
	}
	return client, "pending"
}

func (h *Handler) cleanupPromoted(cid string) {
	h.mu.Lock()
	st := h.cids[cid]
	if st == nil || !st.promoted {
		h.mu.Unlock()
		return
	}
	delete(h.cids, cid)
	if h.identityToAttemptCID[st.identity] == cid {
		delete(h.identityToAttemptCID, st.identity)
	}
	if st.promotedCancel != nil {
		st.promotedCancel()
	}
	h.mu.Unlock()
}

func (h *Handler) killStalledPromoted(ctx context.Context, cid, cn string) {
	h.mu.Lock()
	st := h.cids[cid]
	sink := h.liveSink
	stillPromoted := st != nil && st.promoted
	h.mu.Unlock()
	if !stillPromoted || sink == nil {
		return
	}
	decision := Decision{Type: DecisionKill, CID: cid, KillMode: "HALT"}
	var err error
	if ackSink, ok := sink.(AckDecisionSink); ok {
		err = ackSink.SendAck(decision)
	} else {
		err = sink.Send(decision)
	}
	if err == nil {
		slog.Warn("stalled promoted kill accepted", "cid", cid, "cn", cn)
		return
	}
	slog.Warn("stalled promoted kill failed", "cid", cid, "cn", cn, "error", err)
	_, _ = h.reconcilePromoted(ctx, cid)
}

// MarkAuthenticated is called after callback success writes client-auth to the
// management socket. It promotes the CID out of in-flight state so the
// auth-timeout goroutine stops. The expiry timer is NOT started here — it waits
// for CLIENT:ESTABLISHED to anchor to the actual connected time.
func (h *Handler) MarkAuthenticated(cid, cognitoUsername string) {
	if cognitoUsername != "" {
		h.mu.Lock()
		if st := h.cids[cid]; st != nil {
			st.cognitoUsername = cognitoUsername
		}
		h.mu.Unlock()
	}
	h.promoteSession(cid)
}

func (h *Handler) clearInFlight(cid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if st := h.cids[cid]; st != nil {
		st.cancel = nil
		st.sid = ""
		if !st.promoted && h.identityToAttemptCID[st.identity] == cid {
			delete(h.identityToAttemptCID, st.identity)
		}
	}
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
	st := h.cids[cid]
	if st == nil {
		// CID already gone (e.g. disconnect raced with timer start); cancel
		// the context we just created so it doesn't leak.
		h.mu.Unlock()
		expiryCancel()
		return expiryCtx
	}
	if st.expiry != nil {
		st.expiry.cancel()
	}
	st.expiry = &sessionExpiry{connectedAt: connectedAt, cancel: expiryCancel}
	h.mu.Unlock()
	return expiryCtx
}

// RebuildSessionTrackingFromStatus reconciles in-memory session tracking against
// the current management socket status snapshot. It is called on every
// management socket reconnect (reconnect-bootstrap sweep).
//
// L1 mitigation (accepted, option b): if a CLIENT:DISCONNECT event is lost
// during a management socket reconnect, the corresponding cidState entry would
// otherwise persist indefinitely. This sweep provides bounded cleanup: any CID
// that is not in the live status snapshot AND is not currently in-flight AND has
// not been promoted is removed from the CID and active-identity indexes. Because the daemon
// reconnects to the management socket whenever the connection drops — the same
// event that can cause a DISCONNECT to be lost — this sweep fires at exactly the
// right moment to reclaim stale entries. No additional periodic reaper is required.
func (h *Handler) RebuildSessionTrackingFromStatus(sessions []mgmt.EstablishedSession) {
	snapshot := mgmt.StatusSnapshot{Established: sessions}
	for _, session := range sessions {
		snapshot.Clients = append(snapshot.Clients, mgmt.StatusClient{
			CID: session.CID, CommonName: session.CommonName,
			ConnectedAt: session.ConnectedAt, Established: true,
		})
	}
	_ = h.RebuildSessionTrackingFromSnapshot(snapshot)
}

// RebuildSessionTrackingFromSnapshot applies an authoritative status snapshot
// and returns duplicate/expired evictions for the caller to send after buffered
// events have been replayed.
func (h *Handler) RebuildSessionTrackingFromSnapshot(snapshot mgmt.StatusSnapshot) []Decision {
	present := make(map[string]mgmt.StatusClient, len(snapshot.Clients))
	for _, client := range snapshot.Clients {
		present[client.CID] = client
	}

	h.mu.Lock()
	for cid, st := range h.cids {
		if _, ok := present[cid]; ok {
			continue
		}
		if st.cancel != nil {
			st.cancel()
		}
		if st.expiry != nil {
			st.expiry.cancel()
		}
		if st.promotedCancel != nil {
			st.promotedCancel()
		}
		if st.sid != "" {
			h.sessions.Delete(st.sid)
		}
		if h.identityToActiveCID[st.identity] == cid {
			delete(h.identityToActiveCID, st.identity)
		}
		if h.identityToAttemptCID[st.identity] == cid {
			delete(h.identityToAttemptCID, st.identity)
		}
		delete(h.cids, cid)
	}

	winners := make(map[string]mgmt.EstablishedSession)
	var evictions []Decision
	for _, session := range snapshot.Established {
		identity, err := NormalizeIdentity(session.CommonName)
		if err != nil {
			slog.Warn("status session has invalid identity", "cid", session.CID, "cn", session.CommonName, "error", err)
			continue
		}
		st := h.cids[session.CID]
		if st == nil {
			st = &cidState{}
			h.cids[session.CID] = st
		}
		st.cn = session.CommonName
		st.identity = identity
		st.promoted = false
		st.established = true
		if h.identityToAttemptCID[identity] == session.CID {
			delete(h.identityToAttemptCID, identity)
		}

		winner, exists := winners[identity]
		if !exists || newerStatusSession(session, winner) {
			if exists {
				if oldState := h.cids[winner.CID]; oldState != nil {
					oldState.evictionRequested = true
				}
				evictions = append(evictions, Decision{Type: DecisionKill, CID: winner.CID, KillMode: "HALT"})
			}
			winners[identity] = session
		} else {
			st.evictionRequested = true
			evictions = append(evictions, Decision{Type: DecisionKill, CID: session.CID, KillMode: "HALT"})
		}
	}
	for identity, winner := range winners {
		h.identityToActiveCID[identity] = winner.CID
	}
	h.mu.Unlock()

	for _, session := range snapshot.Established {
		if h.cfg.MaxSessionDuration <= 0 {
			continue
		}
		if time.Since(session.ConnectedAt) >= h.cfg.MaxSessionDuration {
			h.replaceExpiryState(session.CID, session.ConnectedAt)
			h.mu.Lock()
			if st := h.cids[session.CID]; st != nil {
				st.evictionRequested = true
			}
			h.mu.Unlock()
			evictions = append(evictions, Decision{Type: DecisionKill, CID: session.CID, KillMode: "HALT"})
			continue
		}
		h.startExpiryTimer(session.CID, session.ConnectedAt)
	}
	return evictions
}

// ReconciledEvictionNeeded revalidates a snapshot-derived eviction after
// buffered management events have been replayed.
func (h *Handler) ReconciledEvictionNeeded(cid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.cids[cid]
	return st != nil && st.evictionRequested
}

func newerStatusSession(candidate, current mgmt.EstablishedSession) bool {
	if !candidate.ConnectedAt.Equal(current.ConnectedAt) {
		return candidate.ConnectedAt.After(current.ConnectedAt)
	}
	candidateCID, candidateErr := strconv.ParseUint(candidate.CID, 10, 64)
	currentCID, currentErr := strconv.ParseUint(current.CID, 10, 64)
	if candidateErr == nil && currentErr == nil {
		return candidateCID > currentCID
	}
	return candidate.CID > current.CID
}

func (h *Handler) sessionExpiryTimer(ctx context.Context, cid string, remaining time.Duration) {
	// No defer clearExpiry here: if client-kill fails (e.g. socket disconnected),
	// the expiry entry in cids must remain so the reauth backstop can still catch
	// the expired session. Cleanup happens in handleDisconnect or evictSession.

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		h.mu.Lock()
		st := h.cids[cid]
		var exp *sessionExpiry
		var cn string
		if st != nil {
			exp = st.expiry
			cn = st.cn
		}
		h.mu.Unlock()
		if exp == nil {
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
