package hankoadk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestApplicationOrganizationUserSessionContract(t *testing.T) {
	const base = "/api/v1/application-organizations/realms/example/applications/product-api"
	type exchange struct{ method, path, body string }
	var calls []exchange
	credential := "current-user"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("request did not resolve the current session")
		}
		var body json.RawMessage
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		calls = append(calls, exchange{r.Method, r.URL.Path, string(body)})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/membership"):
			_, _ = w.Write([]byte(`{"subject":"user","organization":"cabinet","role":"owner","administrator":true}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/members"):
			_, _ = w.Write([]byte(`{"members":[{"id":"member","name":"Member","email":"member@example.test","role":"reader","manageable":true}],"roles":["reader","owner"],"administrator":true}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/invitations"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"invite","organization":"cabinet","email":"invitee@example.test","role":"reader","expires_at":"2026-10-24T00:00:00Z"}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":"invite","organization":"cabinet","email":"invitee@example.test","role":"reader","expires_at":"2026-10-24T00:00:00Z"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := NewApplicationOrganizationClient(server.URL, "example", "product-api", OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return credential, nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	membership, err := client.Membership(ctx)
	if err != nil || membership.Subject != "user" || !membership.Administrator || membership.Organization != "cabinet" || membership.Role != "owner" {
		t.Fatalf("membership: %+v %v", membership, err)
	}
	credential = "rotated-user"
	members, err := client.Members(ctx, "cabinet")
	if err != nil || len(members.Members) != 1 || !members.Members[0].Manageable || !members.Administrator || !reflect.DeepEqual(members.Roles, []string{"reader", "owner"}) {
		t.Fatalf("members: %+v %v", members, err)
	}
	if err := client.ChangeRole(ctx, "cabinet", "member", "reader"); err != nil {
		t.Fatal(err)
	}
	invited, err := client.Invite(ctx, "cabinet", ApplicationInvitationSpec{Email: "invitee@example.test", Role: "reader"})
	if err != nil || invited.ID != "invite" || invited.ExpiresAt != "2026-10-24T00:00:00Z" {
		t.Fatalf("invite: %+v %v", invited, err)
	}
	read, err := client.Invitation(ctx, "cabinet", "invite")
	if err != nil || read != invited {
		t.Fatalf("invitation: %+v %v", read, err)
	}
	if err := client.Accept(ctx, "cabinet", "invite"); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, "cabinet", "invite"); err != nil {
		t.Fatal(err)
	}
	expected := []exchange{
		{"GET", base + "/membership", ""}, {"GET", base + "/cabinet/members", ""},
		{"PATCH", base + "/cabinet/members/member", `{"role":"reader"}`},
		{"POST", base + "/cabinet/invitations", `{"email":"invitee@example.test","role":"reader"}`},
		{"GET", base + "/cabinet/invitations/invite", ""}, {"POST", base + "/cabinet/invitations/invite/accept", `{}`}, {"DELETE", base + "/cabinet/invitations/invite", ""},
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("contract mismatch: %+v", calls)
	}
}

func TestApplicationOrganizationRefusesInvalidInputBeforeCredentials(t *testing.T) {
	credentialCalls := 0
	options := OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { credentialCalls++; return "user", nil }}
	ctx := context.Background()
	for _, invalid := range []string{"", "..", "a/b", "a\\b", "a%2fb", "a?b", "a#b", "a b", "a\n", "é", strings.Repeat("a", 256)} {
		if _, err := NewApplicationOrganizationClient("https://auth.example.test", invalid, "product-api", options); err == nil {
			t.Errorf("accepted realm %q", invalid)
		}
		if _, err := NewApplicationOrganizationClient("https://auth.example.test", "example", invalid, options); err == nil {
			t.Errorf("accepted application %q", invalid)
		}
		client, err := NewApplicationOrganizationClient("https://auth.example.test", "example", "product-api", options)
		if err != nil {
			t.Fatal(err)
		}
		_, membersErr := client.Members(ctx, invalid)
		_, inviteErr := client.Invite(ctx, invalid, ApplicationInvitationSpec{Email: "a@example.test", Role: "reader"})
		_, readErr := client.Invitation(ctx, "cabinet", invalid)
		for _, err := range []error{membersErr, inviteErr, readErr, client.ChangeRole(ctx, "cabinet", invalid, "reader"), client.ChangeRole(ctx, "cabinet", "member", invalid), client.Accept(ctx, invalid, "invite"), client.Revoke(ctx, "cabinet", invalid)} {
			if err == nil {
				t.Errorf("accepted target %q", invalid)
			}
		}
	}
	client, _ := NewApplicationOrganizationClient("https://auth.example.test", "example", "product-api", options)
	for _, email := range []string{"", "invalid", "Member <a@example.test>", "a@localhost", "a\n@example.test", "a\u00a0@example.test", strings.Repeat("a", 321) + "@example.test"} {
		if _, err := client.Invite(ctx, "cabinet", ApplicationInvitationSpec{Email: email, Role: "reader"}); err == nil {
			t.Errorf("accepted email %q", email)
		}
	}
	if credentialCalls != 0 {
		t.Errorf("invalid inputs resolved %d credentials", credentialCalls)
	}
	if _, err := NewApplicationOrganizationClient("https://auth.example.test", "example", "product-api", OrganizationClientOptions{}); err == nil {
		t.Error("accepted missing token source")
	}
}

func TestApplicationOrganizationPreservesFailuresAndCancellation(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { targetCalls++; w.WriteHeader(200) }))
	defer target.Close()
	status := http.StatusForbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusFound {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("provider-secret-must-not-leak"))
	}))
	defer server.Close()
	client, err := NewApplicationOrganizationClient(server.URL, "example", "product-api", OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "user", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Membership(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 403") || strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("unsafe authorization failure: %v", err)
	}
	status = http.StatusFound
	if _, err = client.Membership(context.Background()); err == nil || targetCalls != 0 {
		t.Fatalf("redirect followed: calls=%d err=%v", targetCalls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Membership(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
