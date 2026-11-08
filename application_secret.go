package hankoadk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ApplicationMetadata describes a Hanko application without any secret value.
type ApplicationMetadata struct {
	ClientID     string   `json:"clientId"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Enabled      bool     `json:"enabled"`
	RedirectURIs []string `json:"redirectUris"`
}

// ApplicationSecret is a one-time value: show it once, never log or persist it
// in plain text.
type ApplicationSecret struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RotatedAt    string `json:"rotatedAt"`
}

// ApplicationSecretClient rotates the secret of named confidential applications
// from a product backend. It is bound at construction to one realm and an
// allowlist of client IDs; the API still enforces the caller's authority.
type ApplicationSecretClient struct {
	client    *OrganizationClient
	realm     string
	clientIDs map[string]struct{}
}

func NewApplicationSecretClient(apiURL, realm string, clientIDs []string, options OrganizationClientOptions) (*ApplicationSecretClient, error) {
	if err := validateAPIIdentifier(realm); err != nil {
		return nil, err
	}
	if len(clientIDs) == 0 {
		return nil, fmt.Errorf("hanko application secret client needs at least one client ID")
	}
	allowed := make(map[string]struct{}, len(clientIDs))
	for _, clientID := range clientIDs {
		if err := validateAPIIdentifier(clientID); err != nil {
			return nil, err
		}
		allowed[clientID] = struct{}{}
	}
	client, err := NewOrganizationClient(apiURL, options)
	if err != nil {
		return nil, err
	}
	return &ApplicationSecretClient{client: client, realm: realm, clientIDs: allowed}, nil
}

// GetApplication returns application metadata without a secret.
func (c *ApplicationSecretClient) GetApplication(ctx context.Context, clientID string) (ApplicationMetadata, error) {
	path, err := c.path(clientID)
	if err != nil {
		return ApplicationMetadata{}, err
	}
	var response struct {
		ApplicationMetadata
		Enabled *bool `json:"enabled"`
	}
	if err := c.client.request(ctx, http.MethodGet, path, nil, &response, http.StatusOK); err != nil {
		return ApplicationMetadata{}, err
	}
	if response.ClientID != clientID || response.Enabled == nil {
		return ApplicationMetadata{}, fmt.Errorf("invalid Hanko application response")
	}
	app := response.ApplicationMetadata
	app.Enabled = *response.Enabled
	if app.RedirectURIs == nil {
		app.RedirectURIs = []string{}
	}
	return app, nil
}

// RotateSecret issues a new secret; the previous one stops working.
func (c *ApplicationSecretClient) RotateSecret(ctx context.Context, clientID string) (ApplicationSecret, error) {
	path, err := c.path(clientID)
	if err != nil {
		return ApplicationSecret{}, err
	}
	var secret ApplicationSecret
	if err := c.client.request(ctx, http.MethodPost, path+"/secret/rotate", nil, &secret, http.StatusOK); err != nil {
		return ApplicationSecret{}, err
	}
	if _, err := time.Parse(time.RFC3339Nano, secret.RotatedAt); err != nil || secret.ClientID != clientID || secret.ClientSecret == "" {
		return ApplicationSecret{}, fmt.Errorf("invalid Hanko application secret response")
	}
	return secret, nil
}

func (c *ApplicationSecretClient) path(clientID string) (string, error) {
	if _, ok := c.clientIDs[clientID]; !ok {
		return "", fmt.Errorf("hanko application is not allowed for this client")
	}
	return "/api/v1/realms/" + url.PathEscape(c.realm) + "/apps/" + url.PathEscape(clientID), nil
}
