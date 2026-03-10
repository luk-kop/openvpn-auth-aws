package auth

import (
	"context"
	"time"
)

func (h *Handler) pollSession(ctx context.Context, session PendingSession, sink DecisionSink) {
	defer h.clearInFlight(session.CID)

	ticker := time.NewTicker(h.cfg.PollInterval)
	defer ticker.Stop()

	timeout := time.NewTimer(h.cfg.HandWindow)
	defer timeout.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timeout.C:
			h.metrics.AuthDenied("timeout")
			sink.Send(Decision{Type: DecisionDeny, CID: session.CID, KID: session.KID, Reason: "auth timeout"})
			return
		case <-ticker.C:
			result, err := h.store.GetStatus(ctx, session.State)
			if err != nil {
				h.dynamoOK.Store(false)
				continue
			}
			h.dynamoOK.Store(true)

			// Verify auth_token for SUCCESS/FAILED status
			if result.Status == StatusSuccess || result.Status == StatusFailed {
				if !h.verifyAuthToken(session.State, string(result.Status), result.AuthToken) {
					h.metrics.AuthDenied("invalid_auth_token")
					sink.Send(Decision{Type: DecisionDeny, CID: session.CID, KID: session.KID, Reason: "auth verification failed"})
					return
				}
			}

			switch result.Status {
			case StatusSuccess:
				h.metrics.AuthSuccess()
				sink.Send(Decision{Type: DecisionAllow, CID: session.CID, KID: session.KID})
				return
			case StatusFailed:
				h.metrics.AuthDenied("auth_failed")
				sink.Send(Decision{Type: DecisionDeny, CID: session.CID, KID: session.KID, Reason: "auth failed"})
				return
			}
		}
	}
}

func (h *Handler) verifyAuthToken(state, status, authToken string) bool {
	if authToken == "" {
		return false
	}
	expected := h.signer.Sign(state + "|" + status)
	return expected == authToken
}
