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
// 256 bytes (alloc_buf_gc(256) in src/openvpn/push.c), of which ~9 bytes
// are consumed by the "OPEN_URL:" prefix, leaving ~247 bytes for the URL.
// However, the full INFOMSG line includes "WEB_AUTH::" (10 bytes) wrapping,
// so the practical limit for the URL itself is ~229 bytes. If exceeded, the
// client silently drops the message and the browser never opens.
const MaxWebAuthURLLen = 229

type Handler struct {
	cfg      config.Config
	sessions *SessionStore
	identity IdentityChecker
	signer   StateSigner
	metrics  Metrics
	cache    *ReauthCache

	mu            sync.Mutex
	inFlight      map[string]context.CancelFunc // CID → cancel
	cidToSID      map[string]string             // CID → session ID
	cidToCN       map[string]string             // CID → common_name (for cleanup)
	cidToKID      map[string]string             // CID → KID (for client-deny on eviction)
	cnToActiveCID map[string]string             // common_name → CID (one active session per user)

	reauthWG sync.WaitGroup
}

func NewHandler(cfg config.Config, sessions *SessionStore, identity IdentityChecker, signer StateSigner, metrics Metrics) *Handler {
	var cache *ReauthCache
	if cfg.ReauthCache {
		cache = NewReauthCache(cfg.RenegInterval + 10*time.Minute)
	}

	return &Handler{
		cfg:           cfg,
		sessions:      sessions,
		identity:      identity,
		signer:        signer,
		metrics:       metrics,
		cache:         cache,
		inFlight:      make(map[string]context.CancelFunc),
		cidToSID:      make(map[string]string),
		cidToCN:       make(map[string]string),
		cidToKID:      make(map[string]string),
		cnToActiveCID: make(map[string]string),
	}
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
		h.cancelSession(event.CID)
	}
}

func (h *Handler) handleConnect(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	sso := strings.ToLower(event.Env["IV_SSO"])
	if !strings.Contains(sso, "webauth") && !strings.Contains(sso, "openurl") {
		h.metrics.AuthDenied("no_webauth")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "client does not support WebAuth"})
		return
	}
	if event.CommonName() == "" {
		slog.Warn("connect denied", "cid", event.CID, "reason", "missing common name")
		h.metrics.AuthDenied("missing_common_name")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
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
				sink.Send(d)
			}
		}
	}

	sessionID, err := generateRandomToken(16)
	if err != nil {
		h.metrics.AuthDenied("internal_error")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "internal error"})
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
	h.sessions.Put(session)

	stateBlob := EncodeState(StatePayload{
		SID: sessionID,
		IAT: now.Unix(),
		EXP: now.Add(h.cfg.AuthTimeout).Unix(),
	}, h.signer)

	authURL := fmt.Sprintf("%s?state=%s", strings.TrimRight(h.cfg.CallbackURL, "/"), stateBlob)

	// OpenVPN CE clients silently drop WEB_AUTH URLs exceeding the INFOMSG
	// buffer limit — fail loudly here instead.
	webAuthLen := len("OPEN_URL:") + len(authURL)
	if webAuthLen > MaxWebAuthURLLen {
		slog.Error("WEB_AUTH URL exceeds OpenVPN CE INFOMSG limit",
			"url_len", webAuthLen, "max", MaxWebAuthURLLen,
			"cid", event.CID, "cn", event.CommonName())
		h.metrics.AuthDenied("url_too_long")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "auth URL too long"})
		return
	}

	slog.Info("connect pending auth", "cid", event.CID, "cn", event.CommonName(), "timeout", h.cfg.AuthTimeout)
	h.metrics.AuthAttempt("")
	timeout := int(h.cfg.HandWindow.Seconds())
	sink.Send(Decision{
		Type:    DecisionPending,
		CID:     event.CID,
		KID:     event.KID,
		URL:     authURL,
		Timeout: timeout,
	})

	// Timeout goroutine: deny + cleanup if callback doesn't arrive in time
	timeoutCtx, cancel := context.WithCancel(ctx)
	h.setInFlight(event.CID, sessionID, event.CommonName(), event.KID, cancel)
	go h.authTimeout(timeoutCtx, session, sink)
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
		sink.Send(Decision{Type: DecisionDeny, CID: session.CID, KID: session.KID, Reason: "auth timeout"})
	}
}

func (h *Handler) handleReauth(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	lookup := event.CommonName()
	if lookup == "" {
		slog.Warn("reauth denied", "cid", event.CID, "reason", "missing common name")
		h.metrics.ReauthDenied("missing_common_name")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
		return
	}

	slog.Info("reauth", "cid", event.CID, "cn", lookup)
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
			sink.Send(Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
			return
		}
	}

	slog.Warn("reauth denied", "cid", event.CID, "cn", lookup, "reason", "cognito unavailable", "error", err)
	h.metrics.ReauthDenied("cognito_error")
	sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "cognito unavailable"})
}

func (h *Handler) finishReauth(event mgmt.Event, result IdentityResult, sink DecisionSink) {
	if !result.Exists {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "user not found")
		h.metrics.ReauthDenied("user_not_found")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user not found"})
		return
	}
	if !result.Enabled {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "user disabled")
		h.metrics.ReauthDenied("user_disabled")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user disabled"})
		return
	}
	if h.cfg.CheckGroupsOnReauth && !result.InGroup {
		slog.Warn("reauth denied", "cid", event.CID, "cn", event.CommonName(), "reason", "group denied", "group", h.cfg.RequiredGroup)
		h.metrics.ReauthDenied("group_denied")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: fmt.Sprintf("not in required group: %s", h.cfg.RequiredGroup)})
		return
	}
	slog.Info("reauth allowed", "cid", event.CID, "cn", event.CommonName())
	h.metrics.ReauthSuccess()
	sink.Send(Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
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
	// Clean up all tracking for this CID.
	delete(h.inFlight, cid)
	delete(h.cidToSID, cid)
	delete(h.cidToCN, cid)
	delete(h.cidToKID, cid)
	if cn != "" && h.cnToActiveCID[cn] == cid {
		delete(h.cnToActiveCID, cn)
	}
	h.mu.Unlock()

	if inFlight {
		cancel()
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
	delete(h.inFlight, event.CID)
	delete(h.cidToSID, event.CID)
	delete(h.cidToCN, event.CID)
	delete(h.cidToKID, event.CID)
	if cn != "" && h.cnToActiveCID[cn] == event.CID {
		delete(h.cnToActiveCID, cn)
	}
	h.mu.Unlock()
	if ok {
		cancel()
	}
	if sid != "" {
		h.sessions.Delete(sid)
	}
}

// cancelSession cancels the timeout goroutine for a CID and removes the
// session record from the store. Used when CLIENT:ESTABLISHED confirms the
// auth completed — the PKCE/nonce data is no longer needed.
// CN→CID tracking is kept so single-session-per-user eviction still works
// until DISCONNECT cleans it up.
func (h *Handler) cancelSession(cid string) {
	h.mu.Lock()
	cancel, ok := h.inFlight[cid]
	sid := h.cidToSID[cid]
	if ok {
		delete(h.inFlight, cid)
		delete(h.cidToSID, cid)
		// Keep cidToCN and cnToActiveCID — session is established, not gone.
	}
	h.mu.Unlock()
	if ok {
		cancel()
	}
	if sid != "" {
		h.sessions.Delete(sid)
	}
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

func (h *Handler) clearInFlight(cid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.inFlight, cid)
	delete(h.cidToSID, cid)
	// Leave cidToCN, cidToKID, cnToActiveCID — DISCONNECT will clean those up.
}

func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
