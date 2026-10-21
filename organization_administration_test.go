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

type organizationContract struct {
	Client    string            `json:"client"`
	Operation string            `json:"operation"`
	Args      []json.RawMessage `json:"args"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Body      any               `json:"body"`
	Status    int               `json:"status"`
	Response  any               `json:"response"`
	Result    any               `json:"result"`
}

func TestSharedOrganizationAdministrationContract(t *testing.T) {
	data, err := os.ReadFile("testdata/organization-administration.json")
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
				if r.Method != entry.Method || r.URL.Path != entry.Path || r.Header.Get("Authorization") != "Bearer current-credential" {
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
				}
				var body any
				if r.Body != nil {
					encoded, _ := io.ReadAll(r.Body)
					if len(encoded) > 0 {
						if err := json.Unmarshal(encoded, &body); err != nil {
							t.Fatal(err)
						}
					}
				}
				if !reflect.DeepEqual(body, entry.Body) {
					t.Fatalf("body mismatch: %v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(entry.Status)
				if entry.Response != nil {
					if err := json.NewEncoder(w).Encode(entry.Response); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			options := OrganizationClientOptions{AccessToken: func(context.Context) (string, error) { return "current-credential", nil }}
			client, err := NewDelegatedOrganizationClient(server.URL, "example", "product-api", "root", options)
			if err != nil {
				t.Fatal(err)
			}
			management, err := NewIAMClient(server.URL, options)
			if err != nil {
				t.Fatal(err)
			}
			result, err := callOrganizationContract(client, management, entry)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var normalized any
			if err := json.Unmarshal(encoded, &normalized); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalized, entry.Result) || calls != 1 {
				t.Fatalf("result=%v expected=%v calls=%d", normalized, entry.Result, calls)
			}
		})
	}
}

func callOrganizationContract(client *DelegatedOrganizationClient, management *IAMClient, entry organizationContract) (any, error) {
	ctx := context.Background()
	arg := func(i int) string { var value string; _ = json.Unmarshal(entry.Args[i], &value); return value }
	switch entry.Operation {
	case "listPositions":
		return client.ListPositions(ctx)
	case "listMembers":
		return client.ListMembers(ctx, arg(0))
	case "assignMember":
		return nil, client.AssignMember(ctx, arg(0), arg(1))
	case "removeMember":
		return nil, client.RemoveMember(ctx, arg(0), arg(1))
	case "createOrganizationDelegation":
		var spec OrganizationDelegationSpec
		if err := json.Unmarshal(entry.Args[1], &spec); err != nil {
			return nil, err
		}
		return management.CreateOrganizationDelegation(ctx, arg(0), spec)
	case "listOrganizationDelegations":
		return management.ListOrganizationDelegations(ctx, arg(0))
	case "revokeOrganizationDelegation":
		return nil, management.RevokeOrganizationDelegation(ctx, arg(0), arg(1))
	default:
		return nil, fmt.Errorf("unknown operation %s", entry.Operation)
	}
}

func TestDelegatedOrganizationClientBoundariesAndRefusals(t *testing.T) {
	credential := 0
	status := http.StatusNoContent
	body := ""
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
	client, err := NewDelegatedOrganizationClient(server.URL, "example", "product-api", "root", options)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AssignMember(context.Background(), "readers", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveMember(context.Background(), "readers", "alice"); err != nil {
		t.Fatal(err)
	}
	if credential != 2 {
		t.Fatal("credential callback not refreshed")
	}
	for _, status = range []int{401, 403, 404, 409, 503} {
		if err := client.RemoveMember(context.Background(), "readers", "alice"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
			t.Fatalf("refusal lost: %v", err)
		}
	}
	for _, id := range []string{"", ".", "..", "x/y", "x%2fy", "x?y", "two words", strings.Repeat("x", 256)} {
		if _, err := NewDelegatedOrganizationClient(server.URL, id, "product-api", "root", options); err == nil {
			t.Fatal("unsafe realm")
		}
		if _, err := NewDelegatedOrganizationClient(server.URL, "example", id, "root", options); err == nil {
			t.Fatal("unsafe application")
		}
		if _, err := NewDelegatedOrganizationClient(server.URL, "example", "product-api", id, options); err == nil {
			t.Fatal("unsafe root")
		}
		if err := client.AssignMember(context.Background(), id, "alice"); err == nil {
			t.Fatal("unsafe position")
		}
		if err := client.RemoveMember(context.Background(), "readers", id); err == nil {
			t.Fatal("unsafe user")
		}
	}
	status = http.StatusOK
	body = "{}"
	if _, err := client.ListPositions(context.Background()); err == nil {
		t.Fatal("missing positions envelope accepted")
	}
	if _, err := client.ListMembers(context.Background(), "readers"); err == nil {
		t.Fatal("missing members envelope accepted")
	}
	management, err := NewIAMClient(server.URL, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := management.ListOrganizationDelegations(context.Background(), "example"); err == nil {
		t.Fatal("missing delegations envelope accepted")
	}
}
