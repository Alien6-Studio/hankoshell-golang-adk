package hankoadk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func oauthSessionFixture(t *testing.T, tokenHandler http.HandlerFunc) (*oauth2.Config, context.Context) {
	t.Helper()
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token"})
			return
		}
		tokenHandler(w, r)
	}))
	t.Cleanup(server.Close)
	issuer = server.URL
	options := &DiscoveryOptions{HTTPClient: &http.Client{Timeout: time.Second}}
	ctx := WithOAuth2HTTPClient(context.Background(), options)
	config, err := NewOAuth2Config(ctx, ClientConfig{Issuer: issuer, ClientID: "fixture-app", ClientSecret: "private-client-fixture"}, "http://127.0.0.1:9231/callback", nil, options)
	if err != nil {
		t.Fatal("cannot initialize synthetic OAuth session")
	}
	return config, ctx
}

func expiredOAuthToken() *oauth2.Token {
	return &oauth2.Token{AccessToken: "expired-fixture", RefreshToken: "single-use-fixture", Expiry: time.Now().Add(-time.Hour)}
}

func TestOAuthConfigNeverProbesAnotherAuthStyleAfterFailedRefresh(t *testing.T) {
	for _, mode := range []string{"invalid_grant", "server_error", "lost_response"} {
		t.Run(mode, func(t *testing.T) {
			var posts atomic.Int32
			config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != "fixture-app" || r.PostForm.Get("client_secret") != "private-client-fixture" || r.PostForm.Get("refresh_token") != "single-use-fixture" || r.Header.Get("Authorization") != "" {
					t.Error("refresh did not use the configured form authentication")
				}
				if mode == "lost_response" {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error("cannot simulate a lost response")
						return
					}
					_ = connection.Close()
					return
				}
				status := http.StatusBadRequest
				if mode == "server_error" {
					status = http.StatusServiceUnavailable
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": mode, "error_description": "private-provider-sentinel"})
			})
			if config.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
				t.Fatal("consuming refresh would use automatic authentication probing")
			}
			if _, err := config.TokenSource(ctx, expiredOAuthToken()).Token(); err == nil {
				t.Fatal("expected a fixture refresh failure")
			}
			if posts.Load() != 1 {
				t.Fatalf("one refresh call submitted %d consuming requests", posts.Load())
			}
		})
	}
}

func TestGuardedOAuthSourceSharesRotationsAndReturnsIsolatedTokenValues(t *testing.T) {
	var posts atomic.Int32
	config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error("invalid fixture form")
		}
		count := posts.Add(1)
		if r.PostForm.Get("refresh_token") != "single-use-fixture" {
			t.Error("initial refresh lineage changed")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "renewed-fixture", "refresh_token": fmt.Sprintf("rotated-%d", count), "token_type": "Bearer", "expires_in": 300})
	})
	source := GuardOAuth2TokenSource(config.TokenSource(ctx, expiredOAuthToken()))
	const callers = 8
	results := make([]*oauth2.Token, callers)
	var group sync.WaitGroup
	for i := range results {
		group.Go(func() {
			var err error
			results[i], err = source.Token()
			if err != nil {
				t.Error("synthetic refresh unexpectedly failed")
			}
		})
	}
	group.Wait()
	if posts.Load() != 1 {
		t.Fatalf("shared session submitted %d refresh grants", posts.Load())
	}
	for _, result := range results {
		if result == nil || result.AccessToken != "renewed-fixture" || result.RefreshToken != "rotated-1" {
			t.Fatal("shared callers did not receive the rotated credentials")
		}
	}
	results[0].AccessToken = "caller-modified"
	results[0].RefreshToken = "caller-modified"
	results[0].Expiry = time.Time{}
	next, err := source.Token()
	if err != nil || next.AccessToken != "renewed-fixture" || next.RefreshToken != "rotated-1" || next.Expiry.IsZero() || results[1].AccessToken != "renewed-fixture" {
		t.Fatal("a caller modified the session owner's shared token")
	}
}

func TestGuardedOAuthSourceLatchesAmbiguousFailureForWaitingCallers(t *testing.T) {
	var posts atomic.Int32
	config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable","error_description":"private-provider-sentinel"}`))
	})
	source := GuardOAuth2TokenSource(config.TokenSource(ctx, expiredOAuthToken()))
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			token, err := source.Token()
			failure, ok := err.(*OAuth2RefreshFailure)
			if token != nil || !ok || failure.Category != OAuth2RefreshProviderUnavailable || failure.Retryable || strings.Contains(err.Error(), "sentinel") {
				t.Error("refresh failure was retried or leaked provider data")
			}
		})
	}
	group.Wait()
	_, err := source.Token()
	if posts.Load() != 1 || err == nil {
		t.Fatalf("failed session submitted %d refresh grants", posts.Load())
	}
	// Returned error values are copies; caller edits cannot reopen the latch.
	failure := err.(*OAuth2RefreshFailure)
	failure.Category = OAuth2RefreshRejectedGrant
	_, nextError := source.Token()
	if nextError.(*OAuth2RefreshFailure).Category != OAuth2RefreshProviderUnavailable {
		t.Fatal("a caller modified the retained failure state")
	}
}

func TestGuardedOAuthSourceUsesRotatedTokenForNextRefresh(t *testing.T) {
	var posts atomic.Int32
	config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error("invalid fixture refresh form")
		}
		count := posts.Add(1)
		want, lifetime := "single-use-fixture", 1
		if count == 2 {
			want, lifetime = "rotated-1", 300
		}
		if r.PostForm.Get("refresh_token") != want {
			t.Error("next refresh reused an already consumed credential")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("access-%d", count), "refresh_token": fmt.Sprintf("rotated-%d", count), "token_type": "Bearer", "expires_in": lifetime})
	})
	source := GuardOAuth2TokenSource(config.TokenSource(ctx, expiredOAuthToken()))
	first, err := source.Token()
	if err != nil || first.RefreshToken != "rotated-1" {
		t.Fatal("initial rotation failed")
	}
	// One second is inside x/oauth2's normal early-renewal margin, avoiding sleep.
	second, err := source.Token()
	if err != nil || second.AccessToken != "access-2" || second.RefreshToken != "rotated-2" {
		t.Fatal("subsequent rotation failed")
	}
	third, err := source.Token()
	if err != nil || third.AccessToken != second.AccessToken || posts.Load() != 2 {
		t.Fatal("current rotated token was not reused")
	}
}

func TestGuardedOAuthSourceRejectsInvalidSourcesAndResults(t *testing.T) {
	for _, source := range []oauth2.TokenSource{nil, oauth2.StaticTokenSource(nil), oauth2.StaticTokenSource(&oauth2.Token{})} {
		guard := GuardOAuth2TokenSource(source)
		token, err := guard.Token()
		failure, ok := err.(*OAuth2RefreshFailure)
		if token != nil || !ok || failure.Retryable {
			t.Fatal("invalid source result did not fail closed")
		}
	}
}

func TestRawOAuthSourceDoesNotLatchFailureAcrossSeparateCalls(t *testing.T) {
	var posts atomic.Int32
	config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
	})
	source := config.TokenSource(ctx, expiredOAuthToken())
	_, _ = source.Token()
	_, _ = source.Token()
	if posts.Load() != 2 {
		t.Fatal("standard source behavior changed; reassess the guard's contract")
	}
}

func TestRefreshDiagnosticsNeverRetainProviderResponseOrErrorText(t *testing.T) {
	for _, fixture := range []struct {
		status int
		code   string
		want   OAuth2RefreshFailureCategory
	}{
		{400, "invalid_grant", OAuth2RefreshRejectedGrant},
		{400, "invalid_client", OAuth2RefreshClientConfig},
		{401, "private-code-sentinel", OAuth2RefreshClientConfig},
		{503, "temporarily_unavailable", OAuth2RefreshProviderUnavailable},
		{429, "rate_limit", OAuth2RefreshProviderUnavailable},
		{200, "private-code-sentinel", OAuth2RefreshInvalidResponse},
		{400, "private-code-sentinel", OAuth2RefreshOutcomeUnknown},
	} {
		raw := fmt.Errorf("private-wrapper-sentinel: %w", &oauth2.RetrieveError{
			Response: &http.Response{StatusCode: fixture.status, Header: http.Header{"Authorization": {"private-header-sentinel"}}},
			Body:     []byte("private-body-sentinel"), ErrorCode: fixture.code, ErrorDescription: "private-description-sentinel",
		})
		failure := ClassifyOAuth2RefreshError(raw)
		data, _ := json.Marshal(failure)
		if failure.Category != fixture.want || failure.HTTPStatus != fixture.status || failure.Retryable || strings.Contains(failure.Error(), "sentinel") || strings.Contains(string(data), "sentinel") {
			t.Fatal("diagnostic classification changed or leaked private material")
		}
		var recovered *oauth2.RetrieveError
		if errors.As(failure, &recovered) {
			t.Fatal("sanitized failure retained the raw provider error")
		}
		if reclassified := ClassifyOAuth2RefreshError(failure); *reclassified != *failure || reclassified == failure {
			t.Fatal("safe classification lost metadata or returned mutable shared state")
		}
	}
	if ClassifyOAuth2RefreshError(nil) != nil {
		t.Fatal("nil error became failure")
	}
	if failure := ClassifyOAuth2RefreshError(errors.New("private-network-sentinel")); failure.Category != OAuth2RefreshOutcomeUnknown || failure.Retryable || strings.Contains(failure.Error(), "sentinel") {
		t.Fatal("ambiguous transport error was not reduced safely")
	}
	if failure := ClassifyOAuth2RefreshError(&OAuth2RefreshFailure{Category: "private-category-sentinel", HTTPStatus: 999, Retryable: true}); failure.Category != OAuth2RefreshOutcomeUnknown || failure.HTTPStatus != 0 || failure.Retryable || strings.Contains(failure.Error(), "sentinel") {
		t.Fatal("untrusted classification fields were not normalized")
	}
}

func TestOAuthContextBoundsTokenRequestsAndRefusesRedirects(t *testing.T) {
	var redirected atomic.Int32
	config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/must-not-follow" {
			redirected.Add(1)
		}
		http.Redirect(w, r, "/must-not-follow", http.StatusTemporaryRedirect)
	})
	client := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client.Timeout != time.Second {
		t.Fatal("the caller's finite timeout was lost")
	}
	if _, err := config.TokenSource(ctx, expiredOAuthToken()).Token(); err == nil || redirected.Load() != 0 {
		t.Fatal("token request followed a redirect")
	}
	defaultClient := WithOAuth2HTTPClient(context.Background(), nil).Value(oauth2.HTTPClient).(*http.Client)
	if defaultClient.Timeout != defaultHTTPTimeout {
		t.Fatal("default token requests are not bounded")
	}
}

func TestOAuthContextAppliesTimeoutAndBodyLimitDuringRefresh(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		config, ctx := oauthSessionFixture(t, func(_ http.ResponseWriter, _ *http.Request) {
			<-release
		})
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ctx = WithOAuth2HTTPClient(ctx, &DiscoveryOptions{HTTPClient: &http.Client{Timeout: 20 * time.Millisecond}})
		started := time.Now()
		if _, err := config.TokenSource(ctx, expiredOAuthToken()).Token(); err == nil {
			t.Fatal("stalled refresh escaped the HTTP timeout")
		}
		if time.Since(started) > 2*time.Second {
			t.Fatal("refresh waited for the context safety deadline instead of the HTTP timeout")
		}
	})
	t.Run("body limit", func(t *testing.T) {
		config, ctx := oauthSessionFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": strings.Repeat("x", maxDiscoveryDocumentBytes+1), "token_type": "Bearer", "expires_in": 300})
		})
		token, err := GuardOAuth2TokenSource(config.TokenSource(ctx, expiredOAuthToken())).Token()
		if token != nil || err == nil {
			t.Fatal("oversized refresh response was accepted")
		}
		if _, ok := err.(*OAuth2RefreshFailure); !ok {
			t.Fatal("oversized response escaped as an unsafe provider error")
		}
	})
}
