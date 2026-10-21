package hankoadk

import (
	"strings"
	"testing"
)

func TestNormalizeResourceServerConfig(t *testing.T) {
	config, err := NormalizeResourceServerConfig(ResourceServerConfig{
		Issuer: "https://auth.example.test/realms/demo/", Audience: " trunx-api ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Issuer != "https://auth.example.test/realms/demo" || config.Audience != "trunx-api" {
		t.Fatalf("unexpected config: %#v", config)
	}
}

func TestNormalizeIssuerRejectsInsecureRemoteIssuer(t *testing.T) {
	_, err := NormalizeIssuer("http://auth.example.test/realms/demo")
	if err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("expected HTTPS error, got %v", err)
	}
	if _, err := NormalizeIssuer("http://127.0.0.1:8080/realms/demo"); err != nil {
		t.Fatalf("loopback development issuer should be accepted: %v", err)
	}
}

func TestLoadClientConfig(t *testing.T) {
	environment := map[string]string{
		EnvIssuer: "https://auth.example.test/realms/demo", EnvClientID: "trunx-cli",
	}
	config, err := LoadClientConfig(func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientID != "trunx-cli" || config.ClientSecret != "" {
		t.Fatalf("unexpected config: %#v", config)
	}
}

func TestEnvironmentConfigLoaders(t *testing.T) {
	t.Setenv(EnvIssuer, "https://auth.example.test/realms/demo")
	t.Setenv(EnvClientID, "trunx-cli")
	t.Setenv(EnvAudience, "trunx-api")
	if _, err := ClientConfigFromEnvironment(); err != nil {
		t.Fatal(err)
	}
	config, err := ResourceServerConfigFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if config.Audience != "trunx-api" {
		t.Fatalf("unexpected audience: %q", config.Audience)
	}
}

func TestConfigRejectsMissingValues(t *testing.T) {
	emptyEnvironment := func(string) (string, bool) { return "", false }
	if _, err := LoadClientConfig(emptyEnvironment); err == nil {
		t.Fatal("expected missing client configuration to fail")
	}
	if _, err := LoadResourceServerConfig(emptyEnvironment); err == nil {
		t.Fatal("expected missing resource-server configuration to fail")
	}
	if _, err := NormalizeClientConfig(ClientConfig{Issuer: "https://auth.example.test"}); err == nil {
		t.Fatal("expected missing client ID to fail")
	}
	if _, err := NormalizeResourceServerConfig(ResourceServerConfig{Issuer: "https://auth.example.test"}); err == nil {
		t.Fatal("expected missing audience to fail")
	}
}
