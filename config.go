package hankoadk

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

const (
	// EnvIssuer names the public Hanko realm issuer variable.
	EnvIssuer = "HANKO_ISSUER"
	// EnvClientID names the OAuth client identifier variable.
	EnvClientID = "HANKO_CLIENT_ID"
	// EnvClientSecret names the optional confidential-client secret variable.
	EnvClientSecret = "HANKO_CLIENT_SECRET"
	// EnvAudience names the exact resource-server audience variable.
	EnvAudience = "HANKO_AUDIENCE"
)

// EnvironmentLookup resolves an environment value without coupling loaders to
// process-global state.
type EnvironmentLookup func(string) (string, bool)

// ClientConfig contains the Hanko issuer and OAuth client credentials.
type ClientConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

// ResourceServerConfig contains the issuer and audience required to verify a
// Hanko bearer token.
type ResourceServerConfig struct {
	Issuer   string
	Audience string
}

// NormalizeIssuer validates and canonicalizes a public Hanko issuer URL.
func NormalizeIssuer(rawIssuer string) (string, error) {
	value := strings.TrimSpace(rawIssuer)
	if value == "" {
		return "", fmt.Errorf("%s is required", EnvIssuer)
	}

	issuer, err := url.Parse(value)
	if err != nil || !issuer.IsAbs() || issuer.Host == "" || issuer.Opaque != "" {
		return "", fmt.Errorf("%s must be an absolute URL", EnvIssuer)
	}
	if issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return "", fmt.Errorf("%s must not contain credentials, query parameters or a fragment", EnvIssuer)
	}
	if issuer.Scheme != "https" && (issuer.Scheme != "http" || !isLoopback(issuer.Hostname())) {
		return "", fmt.Errorf("%s must use HTTPS outside loopback development", EnvIssuer)
	}

	return strings.TrimRight(issuer.String(), "/"), nil
}

// NormalizeClientConfig validates a client configuration supplied directly by
// an application.
func NormalizeClientConfig(config ClientConfig) (ClientConfig, error) {
	issuer, err := NormalizeIssuer(config.Issuer)
	if err != nil {
		return ClientConfig{}, err
	}
	clientID, err := requiredValue(config.ClientID, EnvClientID)
	if err != nil {
		return ClientConfig{}, err
	}
	return ClientConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: strings.TrimSpace(config.ClientSecret),
	}, nil
}

// NormalizeResourceServerConfig validates a resource-server configuration
// supplied directly by an application.
func NormalizeResourceServerConfig(config ResourceServerConfig) (ResourceServerConfig, error) {
	issuer, err := NormalizeIssuer(config.Issuer)
	if err != nil {
		return ResourceServerConfig{}, err
	}
	audience, err := requiredValue(config.Audience, EnvAudience)
	if err != nil {
		return ResourceServerConfig{}, err
	}
	return ResourceServerConfig{Issuer: issuer, Audience: audience}, nil
}

// LoadClientConfig loads a Hanko OAuth client configuration through lookup.
func LoadClientConfig(lookup EnvironmentLookup) (ClientConfig, error) {
	issuer, err := requiredEnvironment(lookup, EnvIssuer)
	if err != nil {
		return ClientConfig{}, err
	}
	clientID, err := requiredEnvironment(lookup, EnvClientID)
	if err != nil {
		return ClientConfig{}, err
	}
	clientSecret, _ := lookup(EnvClientSecret)
	return NormalizeClientConfig(ClientConfig{
		Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret,
	})
}

// LoadResourceServerConfig loads a Hanko resource-server configuration through
// lookup.
func LoadResourceServerConfig(lookup EnvironmentLookup) (ResourceServerConfig, error) {
	issuer, err := requiredEnvironment(lookup, EnvIssuer)
	if err != nil {
		return ResourceServerConfig{}, err
	}
	audience, err := requiredEnvironment(lookup, EnvAudience)
	if err != nil {
		return ResourceServerConfig{}, err
	}
	return NormalizeResourceServerConfig(ResourceServerConfig{Issuer: issuer, Audience: audience})
}

// ClientConfigFromEnvironment loads a Hanko OAuth client configuration from
// the current process environment.
func ClientConfigFromEnvironment() (ClientConfig, error) {
	return LoadClientConfig(os.LookupEnv)
}

// ResourceServerConfigFromEnvironment loads a Hanko resource-server
// configuration from the current process environment.
func ResourceServerConfigFromEnvironment() (ResourceServerConfig, error) {
	return LoadResourceServerConfig(os.LookupEnv)
}

func requiredEnvironment(lookup EnvironmentLookup, key string) (string, error) {
	value, _ := lookup(key)
	return requiredValue(value, key)
}

func requiredValue(value, field string) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	return normalized, nil
}

func isLoopback(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
