package hankoadk

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sharedSessionFixture struct {
	mu   sync.Mutex
	rows map[string]StoredSession
}

func (s *sharedSessionFixture) Create(_ context.Context, scope string, value StoredSession) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope + value.ID
	if _, ok := s.rows[key]; ok {
		return false, nil
	}
	s.rows[key] = value
	return true, nil
}
func (s *sharedSessionFixture) Read(_ context.Context, scope, id string) (*StoredSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.rows[scope+id]
	if !ok {
		return nil, nil
	}
	return &value, nil
}
func (s *sharedSessionFixture) Replace(_ context.Context, scope, revision string, value StoredSession) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := scope + value.ID
	old, ok := s.rows[key]
	if !ok || old.Revision != revision {
		return false, nil
	}
	s.rows[key] = value
	return true, nil
}
func (s *sharedSessionFixture) Remove(_ context.Context, scope, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, scope+id)
	return nil
}
func sessionTestOptions() (SessionManagerOptions, *atomic.Int64, *atomic.Int64) {
	clock := new(atomic.Int64)
	clock.Store(1000)
	exchanges := new(atomic.Int64)
	options := SessionManagerOptions{Client: ClientConfig{Issuer: "https://auth.example.test/realms/example", ClientID: "web"}, Audience: "api", Secret: strings.Repeat("s", 32), Store: &sharedSessionFixture{rows: map[string]StoredSession{}}, Now: func() time.Time { return time.Unix(clock.Load(), 0) },
		Verify: func(_ context.Context, _ string) (*Principal, error) {
			return &Principal{Issuer: "https://auth.example.test/realms/example", Subject: "alice", Audiences: []string{"api"}}, nil
		},
		Refresh: func(_ context.Context, tokens SessionTokens) (SessionTokens, error) {
			exchanges.Add(1)
			time.Sleep(15 * time.Millisecond)
			tokens.AccessToken = "renewed-private"
			tokens.RefreshToken = "rotated-private"
			tokens.ExpiresAt = 3000
			return tokens, nil
		}}
	return options, clock, exchanges
}
func newSessionManager(t *testing.T, options SessionManagerOptions) *SessionManager {
	t.Helper()
	m, err := NewSessionManager(options)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func createTestSession(t *testing.T, m *SessionManager) *Session {
	t.Helper()
	s, err := m.Create(context.Background(), SessionTokens{AccessToken: "access-private", RefreshToken: "refresh-private", LogoutToken: "logout-private", ExpiresAt: 2000})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestSharedSessionConcurrentRenewalAndRestart(t *testing.T) {
	options, clock, exchanges := sessionTestOptions()
	a := newSessionManager(t, options)
	session := createTestSession(t, a)
	store := options.Store.(*sharedSessionFixture)
	for _, row := range store.rows {
		if strings.Contains(row.Sealed, "private") {
			t.Fatal("plaintext credentials in stored session")
		}
	}
	clock.Store(1990)
	b := newSessionManager(t, options)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			m := a
			if i%2 == 0 {
				m = b
			}
			result, err := m.Read(context.Background(), session.ID)
			if err != nil || result.Tokens.RefreshToken != "rotated-private" {
				t.Errorf("shared renewal failed: %v", err)
			}
		})
	}
	wg.Wait()
	if exchanges.Load() != 1 {
		t.Fatalf("expected one consuming exchange, got %d", exchanges.Load())
	}
	restarted := newSessionManager(t, options)
	if _, err := restarted.Read(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Revoke(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Read(context.Background(), session.ID); err == nil {
		t.Fatal("revoked session survived")
	}
}
func TestSharedSessionLogoutFencesRenewal(t *testing.T) {
	options, clock, _ := sessionTestOptions()
	started := make(chan struct{})
	release := make(chan struct{})
	options.Refresh = func(_ context.Context, tokens SessionTokens) (SessionTokens, error) {
		close(started)
		<-release
		tokens.ExpiresAt = 3000
		return tokens, nil
	}
	m := newSessionManager(t, options)
	session := createTestSession(t, m)
	clock.Store(1990)
	finished := make(chan error, 1)
	go func() { _, err := m.Read(context.Background(), session.ID); finished <- err }()
	<-started
	if err := newSessionManager(t, options).Revoke(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("late renewal restored logout")
	}
	if len(options.Store.(*sharedSessionFixture).rows) != 0 {
		t.Fatal("revoked row recreated")
	}
}
func TestSharedSessionUnknownRefreshNeverReplayed(t *testing.T) {
	options, clock, calls := sessionTestOptions()
	options.Refresh = func(context.Context, SessionTokens) (SessionTokens, error) {
		calls.Add(1)
		return SessionTokens{}, errors.New("raw-provider-secret")
	}
	m := newSessionManager(t, options)
	session := createTestSession(t, m)
	clock.Store(1990)
	for range 3 {
		_, err := newSessionManager(t, options).Read(context.Background(), session.ID)
		if err == nil || strings.Contains(err.Error(), "raw-provider-secret") {
			t.Fatal("unsafe refresh result")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("unknown exchange replayed")
	}
}
func TestSharedSessionCrashAndIsolation(t *testing.T) {
	options, clock, calls := sessionTestOptions()
	m := newSessionManager(t, options)
	session := createTestSession(t, m)
	other := options
	other.Client.ClientID = "other"
	if _, err := newSessionManager(t, other).Read(context.Background(), session.ID); err == nil {
		t.Fatal("cross-client session accepted")
	}
	other = options
	other.Secret = strings.Repeat("x", 32)
	if _, err := newSessionManager(t, other).Read(context.Background(), session.ID); err == nil {
		t.Fatal("wrong key accepted")
	}
	store := options.Store.(*sharedSessionFixture)
	for key, row := range store.rows {
		row.LeaseUntil = 1001_000
		store.rows[key] = row
	}
	clock.Store(1002)
	_, err := m.Read(context.Background(), session.ID)
	var failure *SessionError
	if !errors.As(err, &failure) || failure.Category != SessionRefreshUnknown || calls.Load() != 0 {
		t.Fatal("crashed owner was replaced")
	}
}
