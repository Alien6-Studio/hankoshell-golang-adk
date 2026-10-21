package hankoadk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewOAuth2ConfigUsesDiscoveryAndPKCE(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		})
	}))
	defer server.Close()
	issuer = server.URL

	config, err := NewOAuth2Config(context.Background(), ClientConfig{
		Issuer: issuer, ClientID: "trunx-cli",
	}, "http://127.0.0.1:9231/callback", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.Endpoint.AuthURL != issuer+"/authorize" || config.Endpoint.TokenURL != issuer+"/token" {
		t.Fatalf("unexpected endpoints: %#v", config.Endpoint)
	}
	if len(config.Scopes) != 3 || config.Scopes[0] != "openid" {
		t.Fatalf("unexpected scopes: %#v", config.Scopes)
	}

	pkce := NewPKCE()
	if len(pkce.Verifier()) < 43 {
		t.Fatal("generated PKCE verifier is too short")
	}
	if _, err := ParsePKCEVerifier(pkce.Verifier()); err != nil {
		t.Fatalf("generated verifier should parse: %v", err)
	}
	if pkce.AuthorizationOption() == nil || pkce.ExchangeOption() == nil {
		t.Fatal("PKCE options must be available for authorization and exchange")
	}
	if _, err := ParsePKCEVerifier("short"); err == nil {
		t.Fatal("expected a short PKCE verifier to fail")
	}
}

func TestNewOAuth2ConfigRejectsInsecureRedirect(t *testing.T) {
	_, err := normalizeRedirectURL("http://trunx.example.test/callback")
	if err == nil {
		t.Fatal("expected an insecure remote redirect URL to fail")
	}
}
