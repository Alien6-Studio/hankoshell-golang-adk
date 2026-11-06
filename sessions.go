package hankoadk

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// StoredSession is encrypted state. Store operations must be atomic.
type StoredSession struct {
	ID         string
	Revision   string
	ExpiresAt  int64
	LeaseUntil int64
	Sealed     string
}

// SessionStore must never upsert a missing row during Replace: deletion is revocation.
type SessionStore interface {
	Create(context.Context, string, StoredSession) (bool, error)
	Read(context.Context, string, string) (*StoredSession, error)
	Replace(context.Context, string, string, StoredSession) (bool, error)
	Remove(context.Context, string, string) error
}

// SessionTokens stay server-side. ExpiresAt is Unix seconds, not milliseconds.
type SessionTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	LogoutToken  string `json:"logoutToken,omitempty"`
	ExpiresAt    int64  `json:"expiresAt"`
}

// SessionFailure is a safe allowlisted session outcome.
type SessionFailure string

const (
	SessionExpired         SessionFailure = "session_expired"
	SessionUnavailable     SessionFailure = "session_unavailable"
	SessionRefreshRejected SessionFailure = "refresh_rejected"
	SessionRefreshUnknown  SessionFailure = "refresh_outcome_unknown"
	SessionInvalidToken    SessionFailure = "invalid_token"
)

// SessionError never wraps credential-bearing provider or database errors.
type SessionError struct {
	Category       SessionFailure        `json:"category"`
	RefreshFailure *OAuth2RefreshFailure `json:"refresh_failure,omitempty"`
}

func (e *SessionError) Error() string { return fmt.Sprintf("Hanko session failed (%s)", e.Category) }

// Session is the server-only view of an authoritative shared session.
type Session struct {
	ID        string
	ExpiresAt time.Time
	Tokens    SessionTokens
	Principal *Principal
}

// SessionManagerOptions separates shared persistence from token verification and renewal.
type SessionManagerOptions struct {
	Client        ClientConfig
	Audience      string
	Secret        string
	Store         SessionStore
	Verify        func(context.Context, string) (*Principal, error)
	Refresh       func(context.Context, SessionTokens) (SessionTokens, error)
	MaxAge        time.Duration
	RenewalMargin time.Duration
	Lease         time.Duration
	Wait          time.Duration
	Now           func() time.Time
}

// SessionManager is safe to reconstruct on each request or after a restart.
type SessionManager struct {
	options SessionManagerOptions
	scope   string
	cipher  cipher.AEAD
}
type sessionEnvelope struct {
	Tokens  SessionTokens `json:"tokens"`
	Subject string        `json:"subject"`
}

var sessionIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// NewSessionManager creates encrypted shared sessions; no process-local fallback exists.
func NewSessionManager(options SessionManagerOptions) (*SessionManager, error) {
	client, err := NormalizeClientConfig(options.Client)
	if err != nil {
		return nil, err
	}
	options.Client = client
	if options.Audience == "" || len(options.Secret) < 32 || options.Store == nil || options.Verify == nil || options.Refresh == nil {
		return nil, fmt.Errorf("Hanko sessions require an audience, secret, store, verifier and refresher")
	}
	if options.MaxAge == 0 {
		options.MaxAge = 8 * time.Hour
	}
	if options.RenewalMargin == 0 {
		options.RenewalMargin = 30 * time.Second
	}
	if options.Lease == 0 {
		options.Lease = 30 * time.Second
	}
	if options.Wait == 0 {
		options.Wait = 5 * time.Second
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxAge < time.Minute || options.MaxAge > 30*24*time.Hour || options.RenewalMargin < 0 || options.RenewalMargin > 5*time.Minute || options.Lease < time.Second || options.Lease > 2*time.Minute || options.Wait < time.Millisecond || options.Wait > 30*time.Second {
		return nil, fmt.Errorf("invalid Hanko session limits")
	}
	data, _ := json.Marshal([]string{client.Issuer, client.ClientID, options.Audience})
	hash := sha256.Sum256(data)
	scope := hex.EncodeToString(hash[:])
	key, err := hkdf.Key(sha256.New, []byte(options.Secret), []byte(scope), "hanko-session-v1", 32)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize Hanko session encryption")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize Hanko session encryption")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize Hanko session encryption")
	}
	return &SessionManager{options: options, scope: scope, cipher: aead}, nil
}
func sessionRandom() string { return base64.RawURLEncoding.EncodeToString(randomSessionBytes(32)) }
func randomSessionBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic("system random source unavailable")
	}
	return value
}
func (m *SessionManager) seal(id string, value sessionEnvelope) string {
	data, _ := json.Marshal(value)
	iv := randomSessionBytes(m.cipher.NonceSize())
	sealed := m.cipher.Seal(nil, iv, data, []byte(m.scope+":"+id))
	// v1 wire layout also used by the TypeScript ADK: nonce, tag, ciphertext.
	tag := sealed[len(sealed)-m.cipher.Overhead():]
	return base64.RawURLEncoding.EncodeToString(append(append(iv, tag...), sealed[:len(sealed)-m.cipher.Overhead()]...))
}
func (m *SessionManager) open(row StoredSession) (sessionEnvelope, error) {
	var value sessionEnvelope
	data, err := base64.RawURLEncoding.DecodeString(row.Sealed)
	if err != nil || len(data) < 28 || len(data) > 256_000 {
		return value, &SessionError{Category: SessionUnavailable}
	}
	sealed := append(append([]byte(nil), data[28:]...), data[12:28]...)
	plain, err := m.cipher.Open(nil, data[:12], sealed, []byte(m.scope+":"+row.ID))
	if err != nil || json.Unmarshal(plain, &value) != nil || value.Subject == "" || !validSessionTokens(value.Tokens) {
		return value, &SessionError{Category: SessionUnavailable}
	}
	return value, nil
}
func validSessionTokens(tokens SessionTokens) bool {
	return tokens.AccessToken != "" && len(tokens.AccessToken) <= 128_000 && len(tokens.RefreshToken) <= 128_000 && len(tokens.LogoutToken) <= 128_000 && tokens.ExpiresAt > 0
}
func (m *SessionManager) verified(ctx context.Context, tokens SessionTokens, subject string) (*Principal, error) {
	if !validSessionTokens(tokens) || tokens.ExpiresAt <= m.options.Now().Unix() {
		return nil, &SessionError{Category: SessionInvalidToken}
	}
	p, err := m.options.Verify(ctx, tokens.AccessToken)
	if err != nil || p == nil || p.Issuer != m.options.Client.Issuer || p.Subject == "" || !slices.Contains(p.Audiences, m.options.Audience) || (subject != "" && p.Subject != subject) {
		return nil, &SessionError{Category: SessionInvalidToken}
	}
	return p, nil
}

// Create starts a new session after authenticating the provider's access token.
func (m *SessionManager) Create(ctx context.Context, tokens SessionTokens) (*Session, error) {
	p, err := m.verified(ctx, tokens, "")
	if err != nil {
		return nil, err
	}
	row := StoredSession{ID: sessionRandom(), Revision: sessionRandom(), ExpiresAt: m.options.Now().Add(m.options.MaxAge).UnixMilli()}
	row.Sealed = m.seal(row.ID, sessionEnvelope{tokens, p.Subject})
	ok, err := m.options.Store.Create(ctx, m.scope, row)
	if err != nil || !ok {
		return nil, &SessionError{Category: SessionUnavailable}
	}
	return &Session{row.ID, time.UnixMilli(row.ExpiresAt), tokens, p}, nil
}

// Revoke fences refresh completion on all replicas by removing the shared row.
func (m *SessionManager) Revoke(ctx context.Context, id string) error {
	if !sessionIdentifier.MatchString(id) {
		return nil
	}
	if m.options.Store.Remove(ctx, m.scope, id) != nil {
		return &SessionError{Category: SessionUnavailable}
	}
	return nil
}

// Read renews a session under a shared compare-and-swap lease. A crashed owner
// is never replaced by another consuming exchange, even after its lease expires.
func (m *SessionManager) Read(ctx context.Context, id string) (*Session, error) {
	if !sessionIdentifier.MatchString(id) {
		return nil, &SessionError{Category: SessionExpired}
	}
	deadline := time.Now().Add(m.options.Wait)
	for time.Now().Before(deadline) {
		row, err := m.options.Store.Read(ctx, m.scope, id)
		if err != nil {
			return nil, &SessionError{Category: SessionUnavailable}
		}
		if row == nil || row.ExpiresAt <= m.options.Now().UnixMilli() {
			if err := m.Revoke(ctx, id); err != nil {
				return nil, err
			}
			return nil, &SessionError{Category: SessionExpired}
		}
		envelope, err := m.open(*row)
		if err != nil {
			return nil, err
		}
		if row.LeaseUntil != 0 {
			if row.LeaseUntil <= m.options.Now().UnixMilli() {
				if err := m.Revoke(ctx, id); err != nil {
					return nil, err
				}
				return nil, &SessionError{Category: SessionRefreshUnknown}
			}
			select {
			case <-ctx.Done():
				return nil, &SessionError{Category: SessionUnavailable}
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		if envelope.Tokens.ExpiresAt*1000 > m.options.Now().Add(m.options.RenewalMargin).UnixMilli() {
			p, err := m.verified(ctx, envelope.Tokens, envelope.Subject)
			if err != nil {
				return nil, err
			}
			return &Session{id, time.UnixMilli(row.ExpiresAt), envelope.Tokens, p}, nil
		}
		claimed := *row
		claimed.Revision = sessionRandom()
		claimed.LeaseUntil = m.options.Now().Add(m.options.Lease).UnixMilli()
		ok, err := m.options.Store.Replace(ctx, m.scope, row.Revision, claimed)
		if err != nil {
			return nil, &SessionError{Category: SessionUnavailable}
		}
		if !ok {
			continue
		}
		exchangeCtx, cancel := context.WithTimeout(ctx, m.options.Lease)
		tokens, refreshErr := m.options.Refresh(exchangeCtx, envelope.Tokens)
		cancel()
		var p *Principal
		if refreshErr == nil {
			p, refreshErr = m.verified(ctx, tokens, envelope.Subject)
		}
		if refreshErr != nil {
			// Do not trust Retryable on arbitrary wrapped provider failures. A consuming
			// POST may have happened. Revocation is the safe default.
			if err := m.Revoke(context.WithoutCancel(ctx), id); err != nil {
				return nil, err
			}
			var invalid *SessionError
			if errors.As(refreshErr, &invalid) {
				return nil, invalid
			}
			var oauthFailure *OAuth2RefreshFailure
			if errors.As(refreshErr, &oauthFailure) {
				safe := ClassifyOAuth2RefreshError(refreshErr)
				category := SessionRefreshRejected
				if safe.Category == OAuth2RefreshOutcomeUnknown || safe.Category == OAuth2RefreshProviderUnavailable {
					category = SessionRefreshUnknown
				}
				return nil, &SessionError{Category: category, RefreshFailure: safe}
			}
			return nil, &SessionError{Category: SessionRefreshUnknown}
		}
		next := *row
		next.Revision = sessionRandom()
		next.LeaseUntil = 0
		next.Sealed = m.seal(id, sessionEnvelope{tokens, envelope.Subject})
		if claimed.LeaseUntil <= m.options.Now().UnixMilli() || row.ExpiresAt <= m.options.Now().UnixMilli() {
			_ = m.Revoke(context.WithoutCancel(ctx), id)
			return nil, &SessionError{Category: SessionExpired}
		}
		ok, err = m.options.Store.Replace(ctx, m.scope, claimed.Revision, next)
		if err != nil {
			return nil, &SessionError{Category: SessionUnavailable}
		}
		if !ok {
			return nil, &SessionError{Category: SessionExpired}
		}
		return &Session{id, time.UnixMilli(row.ExpiresAt), tokens, p}, nil
	}
	return nil, &SessionError{Category: SessionUnavailable}
}

// OAuth2SessionRefresher adapts an existing discovered OAuth config. The shared
// session manager, rather than a token-source cache, owns the consuming request.
func OAuth2SessionRefresher(config *oauth2.Config) func(context.Context, SessionTokens) (SessionTokens, error) {
	return func(ctx context.Context, tokens SessionTokens) (SessionTokens, error) {
		if config == nil || tokens.RefreshToken == "" {
			return SessionTokens{}, &OAuth2RefreshFailure{Category: OAuth2RefreshClientConfig}
		}
		configured := *config
		// Prevent OAuth auto-detection from retrying the grant with another auth style.
		configured.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		refreshed, err := configured.TokenSource(ctx, &oauth2.Token{RefreshToken: tokens.RefreshToken, Expiry: time.Unix(1, 0)}).Token()
		if err != nil {
			return SessionTokens{}, ClassifyOAuth2RefreshError(err)
		}
		if refreshed == nil || refreshed.AccessToken == "" || refreshed.Expiry.IsZero() {
			return SessionTokens{}, &OAuth2RefreshFailure{Category: OAuth2RefreshInvalidResponse}
		}
		tokens.AccessToken = refreshed.AccessToken
		tokens.ExpiresAt = refreshed.Expiry.Unix()
		if refreshed.RefreshToken != "" {
			tokens.RefreshToken = refreshed.RefreshToken
		}
		if hint, ok := refreshed.Extra("id_token").(string); ok && hint != "" {
			tokens.LogoutToken = hint
		}
		return tokens, nil
	}
}
