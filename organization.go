package hankoadk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxOrganizationResponseBytes = 1 << 20

// AccessTokenSource returns a short-lived Hanko access token for a management
// request. The ADK never persists or logs the returned token.
type AccessTokenSource func(context.Context) (string, error)

// OrganizationClientOptions configures product-side organization management.
type OrganizationClientOptions struct {
	HTTPClient  *http.Client
	AccessToken AccessTokenSource
}

// OrganizationClient manages Hanko org-chart positions through the supported
// API rather than coupling products to Keycloak or Hanko's database.
type OrganizationClient struct {
	apiURL      string
	httpClient  *http.Client
	accessToken AccessTokenSource
}

// OrganizationPosition is one node in a realm's organization hierarchy.
// Realm selects the issuer boundary; it is not the organization identifier.
type OrganizationPosition struct {
	ID        string   `json:"id"`
	Realm     string   `json:"realm"`
	Title     string   `json:"title"`
	ParentID  string   `json:"parent_id,omitempty"`
	GroupID   string   `json:"group_id,omitempty"`
	RoleIDs   []string `json:"role_ids"`
	CreatedAt string   `json:"created_at,omitempty"`
}

// OrganizationPositionSpec is the writable organization-node contract.
type OrganizationPositionSpec struct {
	Title    string   `json:"title"`
	ParentID string   `json:"parent_id,omitempty"`
	GroupID  string   `json:"group_id,omitempty"`
	RoleIDs  []string `json:"role_ids"`
}

// NewOrganizationClient creates a realm-neutral Hanko organization client.
func NewOrganizationClient(rawAPIURL string, options OrganizationClientOptions) (*OrganizationClient, error) {
	apiURL, err := normalizeAPIURL(rawAPIURL)
	if err != nil {
		return nil, err
	}
	if options.AccessToken == nil {
		return nil, fmt.Errorf("hanko organization access token source is required")
	}
	client := httpClient(&DiscoveryOptions{HTTPClient: options.HTTPClient})
	return &OrganizationClient{apiURL: apiURL, httpClient: client, accessToken: options.AccessToken}, nil
}

// ListPositions returns all organization nodes in realm.
func (c *OrganizationClient) ListPositions(ctx context.Context, realm string) ([]OrganizationPosition, error) {
	var response struct {
		Positions []OrganizationPosition `json:"positions"`
	}
	if err := c.request(ctx, http.MethodGet, positionCollectionPath(realm), nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Positions == nil {
		return []OrganizationPosition{}, nil
	}
	return response.Positions, nil
}

// CreatePosition creates one organization node in realm.
func (c *OrganizationClient) CreatePosition(ctx context.Context, realm string, spec OrganizationPositionSpec) (OrganizationPosition, error) {
	var position OrganizationPosition
	if err := c.request(ctx, http.MethodPost, positionCollectionPath(realm), spec, &position, http.StatusCreated); err != nil {
		return OrganizationPosition{}, err
	}
	return position, nil
}

// UpdatePosition replaces the writable attributes of one organization node.
func (c *OrganizationClient) UpdatePosition(ctx context.Context, realm, positionID string, spec OrganizationPositionSpec) error {
	return c.request(ctx, http.MethodPatch, positionPath(realm, positionID), spec, nil, http.StatusNoContent)
}

// DeletePosition deletes one organization node.
func (c *OrganizationClient) DeletePosition(ctx context.Context, realm, positionID string) error {
	return c.request(ctx, http.MethodDelete, positionPath(realm, positionID), nil, nil, http.StatusNoContent, http.StatusNotFound)
}

func (c *OrganizationClient) request(ctx context.Context, method, path string, body, output any, expected ...int) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode Hanko organization request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reader)
	if err != nil {
		return fmt.Errorf("create Hanko organization request: %w", err)
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return fmt.Errorf("resolve Hanko organization access token: %w", err)
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("hanko organization access token is empty")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("call Hanko organization API: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if !containsStatus(expected, response.StatusCode) {
		return fmt.Errorf("hanko organization API returned status %d", response.StatusCode)
	}
	if output == nil || response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOrganizationResponseBytes+1))
	if err != nil || len(data) > maxOrganizationResponseBytes {
		return fmt.Errorf("hanko organization response exceeds its limit or cannot be read")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Hanko organization response: %w", err)
	}
	return nil
}

func normalizeAPIURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("hanko API URL must be absolute")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("hanko API URL must not contain credentials, query parameters or a fragment")
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !isLoopback(parsed.Hostname())) {
		return "", fmt.Errorf("hanko API URL must use HTTPS outside loopback development")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func positionCollectionPath(realm string) string {
	return "/api/v1/realms/" + url.PathEscape(realm) + "/org/positions"
}

func positionPath(realm, positionID string) string {
	return positionCollectionPath(realm) + "/" + url.PathEscape(positionID)
}

func containsStatus(expected []int, actual int) bool {
	for _, status := range expected {
		if status == actual {
			return true
		}
	}
	return false
}
