package hankoadk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSharedIAMContract(t *testing.T) {
	var cases []struct {
		Operation string            `json:"operation"`
		Args      []json.RawMessage `json:"args"`
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Body      json.RawMessage   `json:"body"`
		Status    int               `json:"status"`
		Response  json.RawMessage   `json:"response"`
		Result    json.RawMessage   `json:"result"`
	}
	data, err := os.ReadFile("testdata/iam-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, entry := range cases {
		t.Run(entry.Operation, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != entry.Method || r.URL.EscapedPath() != entry.Path || r.Header.Get("Authorization") != "Bearer token" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
				}
				body, _ := io.ReadAll(r.Body)
				assertJSONEqual(t, body, entry.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(entry.Status)
				_, _ = w.Write(entry.Response)
			}))
			defer server.Close()
			client, err := NewIAMClient(server.URL, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "token", nil }})
			if err != nil {
				t.Fatal(err)
			}
			// Invoke the public method selected by the cross-language contract.
			method := reflect.ValueOf(client).MethodByName(strings.ToUpper(entry.Operation[:1]) + entry.Operation[1:])
			if !method.IsValid() {
				t.Fatalf("missing public method %s", entry.Operation)
			}
			args := []reflect.Value{reflect.ValueOf(context.Background())}
			for i, raw := range entry.Args {
				value := reflect.New(method.Type().In(i + 1))
				if err := json.Unmarshal(raw, value.Interface()); err != nil {
					t.Fatal(err)
				}
				args = append(args, value.Elem())
			}
			result := method.Call(args)
			if !result[len(result)-1].IsNil() {
				t.Fatal(result[len(result)-1].Interface())
			}
			if len(result) > 1 {
				encoded, err := json.Marshal(result[0].Interface())
				if err != nil {
					t.Fatal(err)
				}
				assertJSONEqual(t, encoded, entry.Result)
			}
			if calls != 1 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}

func assertJSONEqual(t *testing.T, actual, expected []byte) {
	t.Helper()
	var a, b any
	if len(actual) > 0 {
		if err := json.Unmarshal(actual, &a); err != nil {
			t.Fatal(err)
		}
	}
	if len(expected) > 0 {
		if err := json.Unmarshal(expected, &b); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("JSON got %s, want %s", actual, expected)
	}
}

func TestIAMDenialsAndPathSafety(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("private provider detail"))
		}))
		client, _ := NewIAMClient(server.URL, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "token", nil }})
		for _, err := range []error{client.AssignRole(context.Background(), "shared", "alice", "reader"), client.RemoveMember(context.Background(), "shared", "engineering", "alice")} {
			if err == nil || strings.Contains(err.Error(), "private provider") {
				t.Fatalf("invalid failure %v", err)
			}
		}
		server.Close()
	}
	client, _ := NewIAMClient("https://api.example.test", OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { t.Error("must not resolve credentials"); return "token", nil }})
	for _, value := range []string{"", ".", "..", "x/y", "x\\y", "x\ny", " shared"} {
		if _, err := client.ListUsers(context.Background(), value); err == nil {
			t.Errorf("accepted realm %q", value)
		}
		if _, err := client.GetUser(context.Background(), "shared", value); err == nil {
			t.Errorf("accepted user %q", value)
		}
		if err := client.UnassignRole(context.Background(), "shared", "alice", value); err == nil {
			t.Errorf("accepted role %q", value)
		}
		if _, err := client.GetPosition(context.Background(), "shared", value); err == nil {
			t.Errorf("accepted position %q", value)
		}
	}
}

func TestIAMEnvelopeAndFreshCallerToken(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("missing token")
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	client, _ := NewIAMClient(server.URL, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { calls++; return "token", nil }})
	if _, err := client.ListUsers(context.Background(), "shared"); err == nil {
		t.Fatal("accepted raw array")
	}
	if _, err := client.ListRoles(context.Background(), "shared"); err == nil {
		t.Fatal("accepted raw array")
	}
	if calls != 2 {
		t.Fatalf("token resolutions=%d", calls)
	}
}
