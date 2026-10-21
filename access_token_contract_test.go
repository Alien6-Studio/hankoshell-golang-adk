package hankoadk

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSecurityAccessTokenContract(t *testing.T) {
	data, err := os.ReadFile("testdata/access-token-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Now   int64          `json:"now"`
		Base  map[string]any `json:"base"`
		Cases []struct {
			Name   string         `json:"name"`
			Valid  bool           `json:"valid"`
			Claims map[string]any `json:"claims"`
			Remove []string       `json:"remove"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			writeJSON(t, w, map[string]any{"keys": []any{rsaJWK(&key.PublicKey)}})
			return
		}
		writeJSON(t, w, map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"})
	}))
	defer server.Close()
	issuer = server.URL
	v, err := NewVerifier(context.Background(), ResourceServerConfig{Issuer: issuer, Audience: "trunx-api"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A deterministic clock is wired into both the library and claim checks.
	v.now = func() time.Time { return time.Unix(contract.Now, 0) }
	for _, tc := range contract.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			claims := map[string]any{"iss": issuer}
			for k, value := range contract.Base {
				claims[k] = value
			}
			for k, value := range tc.Claims {
				claims[k] = value
			}
			for _, k := range tc.Remove {
				delete(claims, k)
			}
			principal, err := v.Verify(context.Background(), signJWT(t, key, "RS256", claims))
			if (err == nil) != tc.Valid {
				t.Fatalf("accepted=%v, want %v (err=%v)", err == nil, tc.Valid, err)
			}
			if !tc.Valid && principal != nil {
				t.Fatal("rejected token returned an identity")
			}
		})
	}
	valid := map[string]any{"iss": issuer}
	for k, value := range contract.Base {
		valid[k] = value
	}
	// A plausible, correctly shaped payload must still fail with a forged signature.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), signJWT(t, otherKey, "RS256", valid)); err == nil {
		t.Fatal("forged access token authenticated")
	}
}
