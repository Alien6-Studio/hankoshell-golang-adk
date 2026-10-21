package hankoadk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Principal is a verified Hanko identity keyed by Issuer and Subject.
type Principal struct {
	Issuer    string
	Subject   string
	Audiences []string
	Email     string
	Name      string
	Claims    map[string]any
}

// Verifier validates Hanko JWT signatures and authentication invariants.
type Verifier struct {
	verifier *oidc.IDTokenVerifier
	now      func() time.Time
}

// NewVerifier discovers the issuer JWKS endpoint and constructs a fail-closed
// RS256 verifier for the configured audience.
func NewVerifier(ctx context.Context, config ResourceServerConfig, options *DiscoveryOptions) (*Verifier, error) {
	normalized, err := NormalizeResourceServerConfig(config)
	if err != nil {
		return nil, err
	}
	metadata, err := Discover(ctx, normalized.Issuer, options)
	if err != nil {
		return nil, err
	}
	jwksURI, err := validateMetadataEndpoint(metadata.JWKSURI, "jwks_uri", normalized.Issuer, options)
	if err != nil {
		return nil, err
	}
	keySetContext := oidc.ClientContext(ctx, httpClient(options))
	keySet := oidc.NewRemoteKeySet(keySetContext, jwksURI)
	v := &Verifier{now: time.Now}
	v.verifier = oidc.NewVerifier(normalized.Issuer, keySet, &oidc.Config{
		ClientID:             normalized.Audience,
		SupportedSigningAlgs: []string{oidc.RS256},
		Now:                  func() time.Time { return v.now() },
	})
	return v, nil
}

// Verify authenticates a raw JWT and returns a principal keyed by issuer and
// subject. It does not perform product authorization.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Principal, error) {
	if v == nil || v.verifier == nil {
		return nil, fmt.Errorf("hanko verifier is not initialized")
	}
	if strings.TrimSpace(rawToken) == "" || len(rawToken) > maxAccessTokenBytes {
		return nil, fmt.Errorf("hanko token is required")
	}
	verified, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verify Hanko token: %w", err)
	}
	if strings.TrimSpace(verified.Subject) == "" {
		return nil, fmt.Errorf("hanko token does not contain a subject")
	}

	claims := make(map[string]any)
	if err := verified.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode verified Hanko claims: %w", err)
	}
	if err := validateAccessClaims(claims, v.now()); err != nil {
		return nil, err
	}
	return &Principal{
		Issuer:    verified.Issuer,
		Subject:   verified.Subject,
		Audiences: append([]string(nil), verified.Audience...),
		Email:     stringClaim(claims, "email"),
		Name:      stringClaim(claims, "name"),
		Claims:    claims,
	}, nil
}

func stringClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}
