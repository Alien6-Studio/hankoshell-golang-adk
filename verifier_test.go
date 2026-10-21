package hankoadk

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifierAcceptsOnlyConfiguredIssuerAudienceAndAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, response, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
		case "/jwks":
			writeJSON(t, response, map[string]any{"keys": []any{rsaJWK(&key.PublicKey)}})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	issuer = server.URL

	verifier, err := NewVerifier(context.Background(), ResourceServerConfig{
		Issuer: issuer, Audience: "trunx-api",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"hanko_token_use": "access",
		"iss":             issuer, "sub": "user-123", "aud": "trunx-api",
		"email": "user@example.test", "iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	token := signJWT(t, key, "RS256", claims)
	principal, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Issuer != issuer || principal.Subject != "user-123" || principal.Email != "user@example.test" {
		t.Fatalf("unexpected principal: %#v", principal)
	}

	wrongAudience := signJWT(t, key, "RS256", map[string]any{
		"iss": issuer, "sub": "user-123", "aud": "other-api", "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), wrongAudience); err == nil {
		t.Fatal("expected wrong audience to fail")
	}
	wrongAlgorithm := signJWT(t, key, "HS256", claims)
	if _, err := verifier.Verify(context.Background(), wrongAlgorithm); err == nil {
		t.Fatal("expected wrong algorithm to fail")
	}
}

func TestDiscoveryRejectsIssuerSubstitution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(t, response, map[string]any{
			"issuer": "https://attacker.example.test", "jwks_uri": "https://attacker.example.test/jwks",
		})
	}))
	defer server.Close()
	if _, err := Discover(context.Background(), server.URL, nil); err == nil || !strings.Contains(err.Error(), "issuer does not match") {
		t.Fatalf("expected issuer substitution error, got %v", err)
	}
}

func TestDiscoveryRejectsRedirectAndBadStatus(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "/other", http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := Discover(context.Background(), redirect.URL, nil); err == nil || !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}

	unavailable := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unavailable.Close()
	if _, err := Discover(context.Background(), unavailable.URL, nil); err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("expected discovery status error, got %v", err)
	}
}

func TestMetadataEndpointValidationFailsClosed(t *testing.T) {
	issuer := "https://auth.example.test/realms/demo"
	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "missing", endpoint: ""},
		{name: "relative", endpoint: "/jwks"},
		{name: "credentials", endpoint: "https://user@auth.example.test/jwks"},
		{name: "protocol", endpoint: "http://auth.example.test/jwks"},
		{name: "origin", endpoint: "https://attacker.example.test/jwks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateMetadataEndpoint(test.endpoint, "jwks_uri", issuer, nil); err == nil {
				t.Fatalf("expected %s endpoint to fail", test.name)
			}
		})
	}
}

func TestVerifierRejectsUninitializedAndMissingSubject(t *testing.T) {
	var verifier *Verifier
	if _, err := verifier.Verify(context.Background(), "token"); err == nil {
		t.Fatal("expected an uninitialized verifier to fail")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/jwks" {
			writeJSON(t, response, map[string]any{"keys": []any{rsaJWK(&key.PublicKey)}})
			return
		}
		writeJSON(t, response, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	}))
	defer server.Close()
	issuer = server.URL
	verifier, err = NewVerifier(context.Background(), ResourceServerConfig{Issuer: issuer, Audience: "trunx-api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), " "); err == nil {
		t.Fatal("expected an empty token to fail")
	}
	missingSubject := signJWT(t, key, "RS256", map[string]any{
		"iss": issuer, "aud": "trunx-api", "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), missingSubject); err == nil {
		t.Fatal("expected a token without subject to fail")
	}
}

func rsaJWK(key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, algorithm string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": algorithm, "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(encoded))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s.%s", encoded, base64.RawURLEncoding.EncodeToString(signature))
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}
