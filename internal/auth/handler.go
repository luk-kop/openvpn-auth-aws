package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"openvpn-auth-aws/internal/config"
	"openvpn-auth-aws/internal/mgmt"
)

type Handler struct {
	cfg      config.Config
	store    SessionStore
	identity IdentityChecker
	signer   StateSigner
	metrics  Metrics
	cache    *ReauthCache

	mu       sync.Mutex
	inFlight map[string]context.CancelFunc

	dynamoOK atomic.Bool
}

func NewHandler(cfg config.Config, store SessionStore, identity IdentityChecker, signer StateSigner, metrics Metrics) *Handler {
	var cache *ReauthCache
	if cfg.ReauthCache {
		cache = NewReauthCache(cfg.RenegInterval + 10*time.Minute)
	}
	h := &Handler{
		cfg:      cfg,
		store:    store,
		identity: identity,
		signer:   signer,
		metrics:  metrics,
		cache:    cache,
		inFlight: make(map[string]context.CancelFunc),
	}
	h.dynamoOK.Store(true)
	return h
}

func (h *Handler) InFlight() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.inFlight)
}

func (h *Handler) DynamoReachable() bool {
	return h.dynamoOK.Load()
}

func (h *Handler) HandleEvent(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	switch event.Type {
	case mgmt.EventConnect:
		h.handleConnect(ctx, event, sink)
	case mgmt.EventReauth:
		go h.handleReauth(ctx, event, sink)
	case mgmt.EventDisconnect:
		h.handleDisconnect(event)
	}
}

func (h *Handler) handleConnect(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	if !strings.EqualFold(event.Env["IV_SSO"], "webauth") {
		h.metrics.AuthDenied("no_webauth")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "client does not support WebAuth"})
		return
	}
	if event.CommonName() == "" {
		h.metrics.AuthDenied("missing_common_name")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
		return
	}

	state, err := randomToken()
	if err != nil {
		h.metrics.AuthDenied("internal_error")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "internal error"})
		return
	}
	nonce, err := randomToken()
	if err != nil {
		h.metrics.AuthDenied("internal_error")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "internal error"})
		return
	}

	session := PendingSession{
		State:         state,
		Nonce:         nonce,
		CommonName:    event.CommonName(),
		CID:           event.CID,
		KID:           event.KID,
		Username:      event.Username(),
		CNCrossCheck:  h.cfg.CNCrossCheck,
		RequiredGroup: h.cfg.RequiredGroup,
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(2 * h.cfg.HandWindow),
	}
	if err := h.store.PutPending(ctx, session); err != nil {
		h.dynamoOK.Store(false)
		h.metrics.AuthDenied("store_error")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "session store unavailable"})
		return
	}

	authURL := buildAuthURL(h.cfg.APIGatewayURL, state, h.signer.Sign(state))
	h.metrics.AuthAttempt("")
	sink.Send(Decision{
		Type:    DecisionPending,
		CID:     event.CID,
		KID:     event.KID,
		URL:     authURL,
		Timeout: int(h.cfg.HandWindow.Seconds()),
	})

	pollCtx, cancel := context.WithCancel(ctx)
	h.setInFlight(event.CID, cancel)
	go h.pollSession(pollCtx, session, sink)
}

func (h *Handler) handleReauth(ctx context.Context, event mgmt.Event, sink DecisionSink) {
	lookup := event.CommonName()
	if lookup == "" {
		h.metrics.ReauthDenied("missing_common_name")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "missing common name"})
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
			h.metrics.ReauthCacheHit()
			sink.Send(Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
			return
		}
	}

	h.metrics.ReauthDenied("cognito_error")
	sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "cognito unavailable"})
}

func (h *Handler) finishReauth(event mgmt.Event, result IdentityResult, sink DecisionSink) {
	if !result.Exists {
		h.metrics.ReauthDenied("user_not_found")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user not found"})
		return
	}
	if !result.Enabled {
		h.metrics.ReauthDenied("user_disabled")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: "user disabled"})
		return
	}
	if h.cfg.CheckGroupsOnReauth && !result.InGroup {
		h.metrics.ReauthDenied("group_denied")
		sink.Send(Decision{Type: DecisionDeny, CID: event.CID, KID: event.KID, Reason: fmt.Sprintf("not in required group: %s", h.cfg.RequiredGroup)})
		return
	}
	h.metrics.ReauthSuccess()
	sink.Send(Decision{Type: DecisionAllowNT, CID: event.CID, KID: event.KID})
}

func (h *Handler) handleDisconnect(event mgmt.Event) {
	h.mu.Lock()
	cancel, ok := h.inFlight[event.CID]
	if ok {
		delete(h.inFlight, event.CID)
	}
	h.mu.Unlock()
	if ok {
		cancel()
	}
}

func (h *Handler) setInFlight(cid string, cancel context.CancelFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight[cid] = cancel
}

func (h *Handler) clearInFlight(cid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.inFlight, cid)
}

func buildAuthURL(baseURL, state, sig string) string {
	u, _ := url.Parse(strings.TrimRight(baseURL, "/") + "/auth")
	q := u.Query()
	q.Set("state", state)
	q.Set("sig", sig)
	u.RawQuery = q.Encode()
	return u.String()
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
