package hankoadk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPortableApplicationAccessContract(t *testing.T) {
	var cases []struct {
		Name     string
		Audience string
		ClientID string `json:"clientId"`
		Claims   map[string]any
		Denial   AccessDenial
		Roles    []string
	}
	data, err := os.ReadFile("testdata/application-access-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		t.Run(item.Name, func(t *testing.T) {
			p := &Principal{Issuer: "https://auth.example.test", Subject: "alice", Audiences: []string{"api"}, Claims: item.Claims}
			access, err := RequireApplicationAccessForClient(p, item.Audience, item.ClientID)
			if item.Denial != "" {
				var denial *ApplicationAccessError
				if !errors.As(err, &denial) || denial.Category != item.Denial {
					t.Fatalf("expected %s, got %v", item.Denial, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(access.Roles, item.Roles) {
				t.Fatalf("unexpected access: %v %v", access, err)
			}
		})
	}
}
func TestBearerHTTPAuthenticationAndAuthorization(t *testing.T) {
	p := &Principal{Issuer: "https://auth.example.test", Subject: "alice", Audiences: []string{"api"}, Claims: map[string]any{"resource_access": map[string]any{"api": map[string]any{"roles": []string{"member"}}}}}
	verify := func(_ context.Context, token string) (*Principal, error) {
		if token != "valid" {
			return nil, errors.New("provider-secret")
		}
		return p, nil
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "alice" {
			t.Error("verified principal missing")
		}
		w.WriteHeader(204)
	})
	for _, item := range []struct {
		Header string
		Role   string
		Status int
	}{{"Bearer valid", "member", 204}, {"Bearer invalid", "member", 401}, {"Bearer valid", "admin", 403}, {"", "member", 401}, {"Bearer valid extra", "member", 401}} {
		handler := BearerMiddleware(verify, func(_ context.Context, p *Principal) error {
			_, err := RequireApplicationAccess(p, "api", item.Role)
			return err
		})(next)
		r := httptest.NewRequest("GET", "https://example.test/private", nil)
		if item.Header != "" {
			r.Header.Set("Authorization", item.Header)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != item.Status || strings.Contains(w.Body.String(), "provider-secret") {
			t.Fatalf("unsafe HTTP result: %d", w.Code)
		}
		if w.Code == 403 && !strings.Contains(w.Body.String(), "required_role_missing") {
			t.Fatal("authorization explanation missing")
		}
	}
}
