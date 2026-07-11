package auth

import (
	"errors"
	"testing"
	"time"
)

func TestSessionStorePutAndProcess(t *testing.T) {
	store := NewSessionStore()
	sess := &PendingSession{
		SessionID: "sid-1",
		Status:    SessionPending,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	store.Put(sess)

	if store.Len() != 1 {
		t.Fatalf("expected 1 session, got %d", store.Len())
	}

	got, err := store.TryProcess("sid-1")
	if err != nil {
		t.Fatalf("TryProcess: %v", err)
	}
	if got.SessionID != "sid-1" {
		t.Fatalf("expected session id sid-1, got %s", got.SessionID)
	}
}

func TestSessionStoreTryProcessNotFound(t *testing.T) {
	store := NewSessionStore()
	_, err := store.TryProcess("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestSessionStoreTryProcessNotPending(t *testing.T) {
	store := NewSessionStore()
	sess := &PendingSession{
		SessionID: "sid-1",
		Status:    SessionPending,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	store.Put(sess)

	// First call succeeds (PENDING → PROCESSING)
	_, err := store.TryProcess("sid-1")
	if err != nil {
		t.Fatalf("first TryProcess: %v", err)
	}

	// Second call fails (already PROCESSING)
	_, err = store.TryProcess("sid-1")
	if err == nil {
		t.Fatal("expected error for non-pending session")
	}
}

func TestSessionStoreSupersedePendingRacesProcessing(t *testing.T) {
	store := NewSessionStore()
	store.Put(&PendingSession{SessionID: "sid", Status: SessionPending})

	if _, err := store.SupersedePending("sid"); err != nil {
		t.Fatalf("SupersedePending: %v", err)
	}
	if _, err := store.TryProcess("sid"); !errors.Is(err, ErrSessionNotPending) {
		t.Fatalf("TryProcess after supersede error = %v, want ErrSessionNotPending", err)
	}

	store.Put(&PendingSession{SessionID: "processing", Status: SessionPending})
	if _, err := store.TryProcess("processing"); err != nil {
		t.Fatalf("TryProcess: %v", err)
	}
	if _, err := store.SupersedePending("processing"); !errors.Is(err, ErrSessionNotPending) {
		t.Fatalf("SupersedePending after processing error = %v, want ErrSessionNotPending", err)
	}
}

func TestSessionStoreMarkDoneAndDelete(t *testing.T) {
	store := NewSessionStore()
	sess := &PendingSession{
		SessionID: "sid-1",
		Status:    SessionPending,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	store.Put(sess)
	store.MarkDone("sid-1")
	store.Delete("sid-1")

	if store.Len() != 0 {
		t.Fatalf("expected 0 sessions, got %d", store.Len())
	}
}

func TestSessionStoreReap(t *testing.T) {
	store := NewSessionStore()
	store.Put(&PendingSession{
		SessionID: "expired",
		Status:    SessionPending,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	store.Put(&PendingSession{
		SessionID: "active",
		Status:    SessionPending,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	store.reap()

	if store.Len() != 1 {
		t.Fatalf("expected 1 session after reap, got %d", store.Len())
	}
}
