package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Configuration secrets are never logged. Nothing logs a
// Config today, so this is the guard that keeps it that way: the redaction is on
// the type, not on the call sites.
func TestConfigSecretsAreRedacted(t *testing.T) {
	const secret = "SUPER-SECRET-VALUE"
	cfg := Config{
		Upstream: Upstream{
			Endpoint: "https://example.invalid", Region: "eu-central-1",
			AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: secret, SessionToken: secret,
		},
		Clients: []Client{{
			Name: "app", AccessKeyID: "AKIACLIENT",
			SecretAccessKey: secret, Buckets: []string{"b"},
		}},
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("config", "upstream", cfg.Upstream, "clients", cfg.Clients)
	if strings.Contains(buf.String(), secret) {
		t.Errorf("slog leaked a configuration secret: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "REDACTED") {
		t.Errorf("slog output carries no redaction marker: %s", buf.String())
	}

	// The formatting verbs a hurried debug line reaches for. The verb is a
	// variable so that this stays a test of every path rather than something a
	// linter rewrites into the one that already works.
	for _, verb := range []string{"%v", "%s", "%+v"} {
		for _, value := range []any{cfg.Upstream, cfg.Clients, cfg.Clients[0]} {
			if rendered := fmt.Sprintf(verb, value); strings.Contains(rendered, secret) {
				t.Errorf("%s leaked a secret: %s", verb, rendered)
			}
		}
	}
}
