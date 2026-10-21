package hankoadk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestTokenClientBackendAndAgent(t *testing.T) {
	var issuer string
	var requests []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "token_endpoint": issuer + "/token"})
			return
		}
		if r.URL.Path != "/realms/shared/token" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected token request %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		requests = append(requests, r.PostForm)
		_, _ = w.Write([]byte(`{"access_token":"opaque-example-access-token","token_type":"bearer","expires_in":300,"scope":"read","issued_token_type":"` + accessTokenType + `","refresh_token":"must-not-escape","id_token":"must-not-escape"}`))
	}))
	defer server.Close()
	issuer = server.URL + "/realms/shared"
	secrets := 0
	client, err := NewTokenClient(ClientConfig{Issuer: issuer, ClientID: "example-agent"}, TokenClientOptions{ClientSecret: func(context.Context) (string, error) { secrets++; return fmt.Sprintf("rotated-%d", secrets), nil }})
	if err != nil {
		t.Fatal(err)
	}
	token, err := client.ClientCredentials(context.Background(), []string{"read", "read"})
	if err != nil || token.TokenType != "Bearer" || token.IssuedTokenType != "" {
		t.Fatalf("backend response %+v, %v", token, err)
	}
	exchanged, err := client.ExchangeToken(context.Background(), TokenExchange{SubjectToken: "subject-token", ActorToken: "actor-token", Audience: "example-api", Scopes: []string{"read"}})
	if err != nil || exchanged.IssuedTokenType != accessTokenType {
		t.Fatalf("exchange %+v, %v", exchanged, err)
	}
	want := []url.Values{
		{"grant_type": {"client_credentials"}, "scope": {"read"}, "client_id": {"example-agent"}, "client_secret": {"rotated-1"}},
		{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {"subject-token"}, "subject_token_type": {accessTokenType}, "requested_token_type": {accessTokenType}, "actor_token": {"actor-token"}, "actor_token_type": {accessTokenType}, "audience": {"example-api"}, "scope": {"read"}, "client_id": {"example-agent"}, "client_secret": {"rotated-2"}},
	}
	if !reflect.DeepEqual(requests, want) {
		t.Errorf("requests %+v, want %+v", requests, want)
	}
}

func TestTokenClientRejectsInvalidResponses(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"access_token":"token","token_type":"DPoP","expires_in":300}`, `{"access_token":"token","token_type":"Bearer","expires_in":3601}`, `{"access_token":"token","token_type":"Bearer","expires_in":0}`, `{"access_token":"token","token_type":"Bearer","expires_in":1.5}`, `{"access_token":"token","token_type":"Bearer","expires_in":300,"scope":[]}`, `{"access_token":"token","token_type":"Bearer","expires_in":300,"issued_token_type":"id_token"}`} {
		t.Run(body, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "openid-configuration") {
					_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "token_endpoint": issuer + "/token"})
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			issuer = server.URL + "/realms/shared"
			client, _ := NewTokenClient(ClientConfig{Issuer: issuer, ClientID: "agent", ClientSecret: "synthetic"}, TokenClientOptions{})
			if _, err := client.ExchangeToken(context.Background(), TokenExchange{SubjectToken: "subject", Audience: "api", Scopes: []string{"read"}}); err == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}

func TestTokenClientRejectsRedirectsAndForeignEndpoints(t *testing.T) {
	for _, mode := range []string{"issuer", "origin", "redirect", "denied", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "openid-configuration") {
					metadata := map[string]string{"issuer": issuer, "token_endpoint": issuer + "/token"}
					if mode == "issuer" {
						metadata["issuer"] = issuer + "-other"
					}
					if mode == "origin" {
						metadata["token_endpoint"] = "https://evil.example.test/token"
					}
					_ = json.NewEncoder(w).Encode(metadata)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", issuer+"/must-not-follow")
					w.WriteHeader(302)
					return
				}
				if mode == "denied" {
					w.WriteHeader(403)
					_, _ = w.Write([]byte("private provider detail"))
					return
				}
				_, _ = w.Write([]byte(strings.Repeat("x", maxDiscoveryDocumentBytes+1)))
			}))
			defer server.Close()
			issuer = server.URL + "/realms/shared"
			client, _ := NewTokenClient(ClientConfig{Issuer: issuer, ClientID: "agent", ClientSecret: "synthetic"}, TokenClientOptions{})
			if _, err := client.ClientCredentials(context.Background(), nil); err == nil || strings.Contains(err.Error(), "private provider") {
				t.Fatalf("unsafe response: %v", err)
			}
		})
	}
}

func TestTokenClientValidatesInputsBeforeSending(t *testing.T) {
	if _, err := NewTokenClient(ClientConfig{Issuer: "https://auth.example.test/realms/shared", ClientID: "agent"}, TokenClientOptions{}); err == nil {
		t.Fatal("accepted missing credentials")
	}
	client, _ := NewTokenClient(ClientConfig{Issuer: "https://auth.example.test/realms/shared", ClientID: "agent", ClientSecret: "synthetic"}, TokenClientOptions{ClientSecret: func(context.Context) (string, error) { return "", nil }})
	if _, err := client.ClientCredentials(context.Background(), nil); err == nil {
		t.Fatal("accepted empty rotated secret")
	}
	for _, scope := range []string{"", "read write", "read\nwrite", `read"write`, `read\write`, "é"} {
		if _, err := client.ClientCredentials(context.Background(), []string{scope}); err == nil {
			t.Fatalf("accepted scope %q", scope)
		}
	}
	for _, exchange := range []TokenExchange{{}, {SubjectToken: "subject", Audience: "api"}, {SubjectToken: "subject", Scopes: []string{"read"}}, {SubjectToken: "subject", Audience: "api", Scopes: []string{"read"}, ActorToken: " "}} {
		if _, err := client.ExchangeToken(context.Background(), exchange); err == nil {
			t.Fatal("accepted unbounded exchange")
		}
	}
}
