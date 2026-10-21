package hankoadk

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
)

var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// PKCE holds an RFC 7636 verifier shared by authorization and token exchange.
type PKCE struct {
	verifier string
}

// NewPKCE generates a cryptographically random RFC 7636 verifier.
func NewPKCE() PKCE {
	return PKCE{verifier: oauth2.GenerateVerifier()}
}

// ParsePKCEVerifier validates a verifier restored by the calling application.
func ParsePKCEVerifier(verifier string) (PKCE, error) {
	if !pkceVerifierPattern.MatchString(verifier) {
		return PKCE{}, fmt.Errorf("PKCE verifier must contain 43 to 128 unreserved characters")
	}
	return PKCE{verifier: verifier}, nil
}

// Verifier returns the value that must survive until the authorization-code
// exchange.
func (p PKCE) Verifier() string {
	return p.verifier
}

// AuthorizationOption returns the S256 challenge option for AuthCodeURL.
func (p PKCE) AuthorizationOption() oauth2.AuthCodeOption {
	return oauth2.S256ChallengeOption(p.verifier)
}

// ExchangeOption returns the verifier option for Exchange.
func (p PKCE) ExchangeOption() oauth2.AuthCodeOption {
	return oauth2.VerifierOption(p.verifier)
}

// NewOAuth2Config discovers Hanko endpoints and builds an Authorization Code
// client configuration. The caller remains responsible for state validation.
func NewOAuth2Config(
	ctx context.Context,
	config ClientConfig,
	redirectURL string,
	scopes []string,
	options *DiscoveryOptions,
) (*oauth2.Config, error) {
	normalized, err := NormalizeClientConfig(config)
	if err != nil {
		return nil, err
	}
	normalizedRedirectURL, err := normalizeRedirectURL(redirectURL)
	if err != nil {
		return nil, err
	}
	metadata, err := Discover(ctx, normalized.Issuer, options)
	if err != nil {
		return nil, err
	}
	authorizationEndpoint, err := validateMetadataEndpoint(
		metadata.AuthorizationEndpoint, "authorization_endpoint", normalized.Issuer, options,
	)
	if err != nil {
		return nil, err
	}
	tokenEndpoint, err := validateMetadataEndpoint(
		metadata.TokenEndpoint, "token_endpoint", normalized.Issuer, options,
	)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &oauth2.Config{
		ClientID:     normalized.ClientID,
		ClientSecret: normalized.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorizationEndpoint,
			TokenURL: tokenEndpoint,
		},
		RedirectURL: normalizedRedirectURL,
		Scopes:      append([]string(nil), scopes...),
	}, nil
}

func normalizeRedirectURL(rawRedirectURL string) (string, error) {
	value := strings.TrimSpace(rawRedirectURL)
	redirectURL, err := url.Parse(value)
	if err != nil || !redirectURL.IsAbs() || redirectURL.Host == "" || redirectURL.Opaque != "" {
		return "", fmt.Errorf("OAuth2 redirect URL must be an absolute URL")
	}
	if redirectURL.User != nil || redirectURL.Fragment != "" {
		return "", fmt.Errorf("OAuth2 redirect URL contains forbidden URL components")
	}
	if redirectURL.Scheme != "https" && (redirectURL.Scheme != "http" || !isLoopback(redirectURL.Hostname())) {
		return "", fmt.Errorf("OAuth2 redirect URL must use HTTPS outside loopback development")
	}
	return redirectURL.String(), nil
}
