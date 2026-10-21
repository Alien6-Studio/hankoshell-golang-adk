package hankoadk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrganizationClientLifecycle(t *testing.T) {
	var position OrganizationPosition
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer short-lived-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var spec OrganizationPositionSpec
			_ = json.NewDecoder(r.Body).Decode(&spec)
			position = OrganizationPosition{ID: "pos_1", Realm: "shared", Title: spec.Title, GroupID: spec.GroupID, RoleIDs: spec.RoleIDs}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(position)
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"positions": []OrganizationPosition{position}})
		case http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewOrganizationClient(server.URL, OrganizationClientOptions{
		AccessToken: func(context.Context) (string, error) { return "short-lived-token", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreatePosition(context.Background(), "shared", OrganizationPositionSpec{Title: "R&D", GroupID: "group-1", RoleIDs: []string{"EXAMPLE_READER"}})
	if err != nil || created.ID != "pos_1" {
		t.Fatalf("CreatePosition() = %#v, %v", created, err)
	}
	positions, err := client.ListPositions(context.Background(), "shared")
	if err != nil || len(positions) != 1 {
		t.Fatalf("ListPositions() = %#v, %v", positions, err)
	}
	if err := client.UpdatePosition(context.Background(), "shared", created.ID, OrganizationPositionSpec{Title: "Research"}); err != nil {
		t.Fatal(err)
	}
	if err := client.DeletePosition(context.Background(), "shared", created.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationClientDoesNotForwardCredentialsThroughRedirects(t *testing.T) {
	forwarded := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded = true
		_, _ = w.Write([]byte(`{"positions":[]}`))
	}))
	t.Cleanup(destination.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	client, err := NewOrganizationClient(origin.URL, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "secret", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListPositions(context.Background(), "example"); err == nil || forwarded {
		t.Fatal("organization redirect was accepted or forwarded credentials")
	}
}

func TestOrganizationClientRefusesOversizedOrTrailingJSON(t *testing.T) {
	for _, body := range []string{`{"positions":[]} {}`, `{"positions":[],"padding":"` + strings.Repeat("x", maxOrganizationResponseBytes) + `"}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		client, err := NewOrganizationClient(server.URL, OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "secret", nil }})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.ListPositions(context.Background(), "example")
		server.Close()
		if err == nil {
			t.Fatal("unbounded organization response accepted")
		}
	}
}

func TestOrganizationClientRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewOrganizationClient("http://hanko.example.test", OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "token", nil }}); err == nil {
		t.Fatal("expected non-loopback HTTP API URL to fail")
	}
	if _, err := NewOrganizationClient("https://hanko.example.test", OrganizationClientOptions{}); err == nil {
		t.Fatal("expected missing token source to fail")
	}
}
