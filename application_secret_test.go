package hankoadk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSharedApplicationSecretContract(t *testing.T) {
	data, err := os.ReadFile("testdata/application-secret-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []organizationContract
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, entry := range cases {
		t.Run(entry.Operation, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if r.Method != entry.Method || r.URL.Path != entry.Path || r.Header.Get("Authorization") != "Bearer current-credential" || len(body) != 0 {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(entry.Status)
				_ = json.NewEncoder(w).Encode(entry.Response)
			}))
			defer server.Close()
			client, err := NewApplicationSecretClient(server.URL, "example", []string{"example-assistant"}, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "current-credential", nil }})
			if err != nil {
				t.Fatal(err)
			}
			var clientID string
			_ = json.Unmarshal(entry.Args[0], &clientID)
			var result any
			switch entry.Operation {
			case "getApplication":
				result, err = client.GetApplication(context.Background(), clientID)
			case "rotateSecret":
				result, err = client.RotateSecret(context.Background(), clientID)
			default:
				t.Fatalf("unknown operation %s", entry.Operation)
			}
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(result)
			var normalized any
			_ = json.Unmarshal(encoded, &normalized)
			if !reflect.DeepEqual(normalized, entry.Result) || calls != 1 {
				t.Fatalf("result=%v expected=%v calls=%d", normalized, entry.Result, calls)
			}
		})
	}
}

func TestApplicationSecretClientBoundariesAndRefusals(t *testing.T) {
	credential := 0
	status := http.StatusOK
	body := `{"clientId":"example-assistant","clientSecret":"synthetic","rotatedAt":"2026-01-02T03:04:05Z"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer credential-%d", credential) {
			t.Error("stale credential")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	options := OrganizationClientOptions{AccessToken: func(context.Context) (string, error) {
		credential++
		return fmt.Sprintf("credential-%d", credential), nil
	}}
	client, err := NewApplicationSecretClient(server.URL, "example", []string{"example-assistant"}, options)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.RotateSecret(context.Background(), "example-assistant"); err != nil {
			t.Fatal(err)
		}
	}
	if credential != 2 {
		t.Fatal("credential callback not refreshed")
	}
	before := credential
	if _, err := client.RotateSecret(context.Background(), "other-app"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("other application reached: %v", err)
	}
	if _, err := client.GetApplication(context.Background(), "other-app"); err == nil {
		t.Fatal("other application read")
	}
	if credential != before {
		t.Fatal("credential resolved for a refused application")
	}
	for _, id := range []string{"", ".", "..", "x/y", "x\\y", "x\ny", " example"} {
		if _, err := NewApplicationSecretClient(server.URL, id, []string{"example-assistant"}, options); err == nil {
			t.Fatal("unsafe realm")
		}
		if _, err := NewApplicationSecretClient(server.URL, "example", []string{id}, options); err == nil {
			t.Fatal("unsafe client ID")
		}
	}
	if _, err := NewApplicationSecretClient(server.URL, "example", nil, options); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	body = "private provider detail"
	for _, status = range []int{401, 403, 404, 409, 503} {
		_, err := client.RotateSecret(context.Background(), "example-assistant")
		if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprintf("status %d", status)) || strings.Contains(err.Error(), "private") {
			t.Fatalf("refusal lost or leaked: %v", err)
		}
	}
	status = http.StatusOK
	for _, body = range []string{
		`{}`,
		`{"clientId":"other-app","clientSecret":"synthetic","rotatedAt":"2026-01-02T03:04:05Z"}`,
		`{"clientId":"example-assistant","clientSecret":"","rotatedAt":"2026-01-02T03:04:05Z"}`,
		`{"clientId":"example-assistant","clientSecret":"synthetic","rotatedAt":"not a date"}`,
	} {
		_, err := client.RotateSecret(context.Background(), "example-assistant")
		if err == nil || !strings.Contains(err.Error(), "invalid Hanko application secret response") || strings.Contains(err.Error(), "synthetic") {
			t.Fatalf("invalid secret response accepted: %v", err)
		}
	}
	body = `{"clientId":"example-assistant"}`
	if _, err := client.GetApplication(context.Background(), "example-assistant"); err == nil {
		t.Fatal("application without enabled state accepted")
	}
}
