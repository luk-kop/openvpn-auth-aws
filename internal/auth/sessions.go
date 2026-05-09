package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrSessionNotFound   = errors.New("session not found")
	ErrSessionNotPending = errors.New("session not pending")
)

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*PendingSession
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*PendingSession),
	}
}

func (s *SessionStore) Put(session *PendingSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = session
}

// TryProcess atomically transitions a session from PENDING to PROCESSING.
// Returns the session on success, or an error if not found (404) or not PENDING (409).
func (s *SessionStore) TryProcess(sessionID string) (*PendingSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.Status != SessionPending {
		return nil, fmt.Errorf("%w: status %d", ErrSessionNotPending, sess.Status)
	}
	sess.Status = SessionProcessing
	return sess, nil
}

func (s *SessionStore) MarkDone(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.Status = SessionDone
	}
}

func (s *SessionStore) MarkFailed(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.Status = SessionFailed
	}
}

// MarkPending resets a session back to PENDING (e.g. after a retryable failure).
func (s *SessionStore) MarkPending(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		sess.Status = SessionPending
	}
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// StartReaper runs a goroutine that periodically removes expired sessions.
func (s *SessionStore) StartReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reap()
			}
		}
	}()
}

func (s *SessionStore) reap() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}
