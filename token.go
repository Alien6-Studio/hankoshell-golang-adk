package hankoadk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const accessTokenType = "urn:ietf:params:oauth:token-type:access_token"

// ClientSecretSource resolves the current server-side credential on each grant.
type ClientSecretSource func(context.Context) (string, error)

// TokenClientOptions configures backend token requests, without persisting secrets.
type TokenClientOptions struct {
	HTTPClient   *http.Client
	ClientSecret ClientSecretSource
}

// TokenSet deliberately excludes refresh tokens, ID tokens and provider extensions.
// Resource servers must independently verify AccessToken with their own audience.
type TokenSet struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// TokenExchange requests explicit scopes and audience. Bounded-delegation policy
// is enforced by the issuer, not by constructing this request.
type TokenExchange struct {
	SubjectToken string
	Audience     string
	Scopes       []string
	ActorToken   string
}

// TokenClient performs client-credentials and RFC 8693 grants through Hanko.
type TokenClient struct {
	config  ClientConfig
	options TokenClientOptions
}

// NewTokenClient validates the exact Hanko issuer and client identity.
func NewTokenClient(config ClientConfig, options TokenClientOptions) (*TokenClient, error) {
	config, err := NormalizeClientConfig(config)
	if err != nil {
		return nil, err
	}
	if config.ClientSecret == "" && options.ClientSecret == nil {
		return nil, fmt.Errorf("hanko backend grants require a client secret")
	}
	return &TokenClient{config: config, options: options}, nil
}

// ClientCredentials acquires a short-lived service identity token.
func (c *TokenClient) ClientCredentials(ctx context.Context, scopes []string) (TokenSet, error) {
	scope, err := scopeValue(scopes)
	if err != nil {
		return TokenSet{}, err
	}
	return c.request(ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}, false)
}

// ExchangeToken exchanges a subject token, optionally with an explicit actor.
func (c *TokenClient) ExchangeToken(ctx context.Context, exchange TokenExchange) (TokenSet, error) {
	if strings.TrimSpace(exchange.SubjectToken) == "" || strings.TrimSpace(exchange.Audience) == "" || len(exchange.Scopes) == 0 {
		return TokenSet{}, fmt.Errorf("hanko token exchange requires a subject token, audience and explicit scopes")
	}
	scope, err := scopeValue(exchange.Scopes)
	if err != nil {
		return TokenSet{}, err
	}
	body := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {exchange.SubjectToken}, "subject_token_type": {accessTokenType}, "requested_token_type": {accessTokenType}, "audience": {exchange.Audience}, "scope": {scope}}
	if exchange.ActorToken != "" {
		if strings.TrimSpace(exchange.ActorToken) == "" {
			return TokenSet{}, fmt.Errorf("hanko actor token is empty")
		}
		body.Set("actor_token", exchange.ActorToken)
		body.Set("actor_token_type", accessTokenType)
	}
	return c.request(ctx, body, true)
}

func (c *TokenClient) request(ctx context.Context, body url.Values, exchange bool) (TokenSet, error) {
	secret := c.config.ClientSecret
	if c.options.ClientSecret != nil {
		var err error
		secret, err = c.options.ClientSecret(ctx)
		if err != nil {
			return TokenSet{}, fmt.Errorf("resolve Hanko client secret: %w", err)
		}
	}
	if strings.TrimSpace(secret) == "" {
		return TokenSet{}, fmt.Errorf("hanko backend grants require a client secret")
	}
	options := &DiscoveryOptions{HTTPClient: c.options.HTTPClient}
	metadata, err := Discover(ctx, c.config.Issuer, options)
	if err != nil {
		return TokenSet{}, err
	}
	endpoint, err := validateMetadataEndpoint(metadata.TokenEndpoint, "token_endpoint", c.config.Issuer, options)
	if err != nil {
		return TokenSet{}, err
	}
	body.Set("client_id", c.config.ClientID)
	body.Set("client_secret", strings.TrimSpace(secret))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return TokenSet{}, fmt.Errorf("create Hanko token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := httpClient(options).Do(request)
	if err != nil {
		return TokenSet{}, fmt.Errorf("call Hanko token endpoint: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return TokenSet{}, fmt.Errorf("hanko token request returned status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryDocumentBytes+1))
	if err != nil || len(data) > maxDiscoveryDocumentBytes {
		return TokenSet{}, fmt.Errorf("hanko token response exceeds its limit or cannot be read")
	}
	var token TokenSet
	if err := json.Unmarshal(data, &token); err != nil {
		return TokenSet{}, fmt.Errorf("invalid Hanko access-token response")
	}
	// encoding/json otherwise accepts JSON null into a string as its zero value.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return TokenSet{}, fmt.Errorf("invalid Hanko access-token response")
	}
	if scope, present := fields["scope"]; present && (len(scope) == 0 || scope[0] != '"') {
		return TokenSet{}, fmt.Errorf("invalid Hanko access-token response")
	}
	if strings.TrimSpace(token.AccessToken) == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn < 1 || token.ExpiresIn > 3600 || (exchange && token.IssuedTokenType != accessTokenType) {
		return TokenSet{}, fmt.Errorf("invalid Hanko access-token response")
	}
	token.TokenType = "Bearer"
	if !exchange {
		token.IssuedTokenType = ""
	}
	return token, nil
}

func scopeValue(scopes []string) (string, error) {
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope == "" {
			return "", fmt.Errorf("invalid Hanko OAuth scope")
		}
		for _, ch := range scope {
			if ch < 33 || ch > 126 || ch == '"' || ch == '\\' {
				return "", fmt.Errorf("invalid Hanko OAuth scope")
			}
		}
		if !seen[scope] {
			unique = append(unique, scope)
			seen[scope] = true
		}
	}
	return strings.Join(unique, " "), nil
}
