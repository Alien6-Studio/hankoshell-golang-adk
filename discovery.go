package hankoadk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const maxDiscoveryDocumentBytes = 1 << 20
const defaultHTTPTimeout = 5 * time.Second

// DiscoveryOptions customizes Hanko HTTP requests while preserving the ADK's
// redirect and same-origin protections.
type DiscoveryOptions struct {
	HTTPClient *http.Client
}

// OIDCMetadata contains the Hanko endpoints consumed by the ADK.
type OIDCMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Discover loads and validates the OIDC metadata for a public Hanko issuer.
func Discover(ctx context.Context, rawIssuer string, options *DiscoveryOptions) (OIDCMetadata, error) {
	issuer, err := NormalizeIssuer(rawIssuer)
	if err != nil {
		return OIDCMetadata{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return OIDCMetadata{}, fmt.Errorf("create Hanko discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := httpClient(options).Do(request)
	if err != nil {
		return OIDCMetadata{}, fmt.Errorf("load hanko discovery: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.Request == nil || response.Request.URL.String() != request.URL.String() {
		return OIDCMetadata{}, fmt.Errorf("hanko discovery redirects are not allowed")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return OIDCMetadata{}, fmt.Errorf("hanko discovery redirects are not allowed")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return OIDCMetadata{}, fmt.Errorf("hanko discovery failed with status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryDocumentBytes+1))
	if err != nil {
		return OIDCMetadata{}, fmt.Errorf("read Hanko discovery: %w", err)
	}
	if len(body) > maxDiscoveryDocumentBytes {
		return OIDCMetadata{}, fmt.Errorf("hanko discovery document exceeds %d bytes", maxDiscoveryDocumentBytes)
	}
	var metadata OIDCMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return OIDCMetadata{}, fmt.Errorf("decode Hanko discovery: %w", err)
	}
	if metadata.Issuer != issuer {
		return OIDCMetadata{}, fmt.Errorf("hanko discovery issuer does not match the configured issuer")
	}
	return metadata, nil
}

func validateMetadataEndpoint(rawEndpoint, field, rawIssuer string, options *DiscoveryOptions) (string, error) {
	if rawEndpoint == "" {
		return "", fmt.Errorf("hanko discovery does not expose %s", field)
	}
	issuer, err := url.Parse(rawIssuer)
	if err != nil {
		return "", fmt.Errorf("parse Hanko issuer: %w", err)
	}
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil || !endpoint.IsAbs() || endpoint.Host == "" || endpoint.Opaque != "" {
		return "", fmt.Errorf("hanko discovery %s must be an absolute URL", field)
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return "", fmt.Errorf("hanko discovery %s contains forbidden URL components", field)
	}
	if endpoint.Scheme != issuer.Scheme {
		return "", fmt.Errorf("hanko discovery %s must use the issuer protocol", field)
	}
	if endpoint.Scheme+"://"+endpoint.Host != issuer.Scheme+"://"+issuer.Host {
		return "", fmt.Errorf("hanko discovery %s must use the issuer origin", field)
	}
	return endpoint.String(), nil
}

func httpClient(options *DiscoveryOptions) *http.Client {
	base := http.DefaultClient
	if options != nil && options.HTTPClient != nil {
		base = options.HTTPClient
	}
	client := *base
	if client.Timeout <= 0 {
		client.Timeout = defaultHTTPTimeout
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}
