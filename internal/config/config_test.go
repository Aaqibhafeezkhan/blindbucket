package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blindbucket.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

const minimal = `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  path_style: true
  access_key_id: AKID
  secret_access_key: SECRET
keys:
  keyring: keyring.json
`

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q, want the loopback default", cfg.Server.Listen)
	}
	if cfg.Keys.Provider != "file" {
		t.Errorf("provider = %q, want file", cfg.Keys.Provider)
	}
	if cfg.Crypto.Log2ChunkSize != 16 {
		t.Errorf("log2_chunk_size = %d, want 16", cfg.Crypto.Log2ChunkSize)
	}
}

// TestLoadResolvesEnvReferences covers the rule that secrets are referenced,
// never written into the file.
func TestLoadResolvesEnvReferences(t *testing.T) {
	t.Setenv("TEST_UPSTREAM_KEY", "resolved-key")
	t.Setenv("TEST_UPSTREAM_SECRET", "resolved-secret")

	cfg, err := Load(write(t, `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  access_key_id: ${TEST_UPSTREAM_KEY}
  secret_access_key: ${TEST_UPSTREAM_SECRET}
keys:
  keyring: keyring.json
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Upstream.AccessKeyID != "resolved-key" {
		t.Errorf("access_key_id = %q, want the resolved value", cfg.Upstream.AccessKeyID)
	}
	if cfg.Upstream.SecretAccessKey != "resolved-secret" {
		t.Errorf("secret_access_key = %q, want the resolved value", cfg.Upstream.SecretAccessKey)
	}
}

// TestLoadFailsOnMissingEnvReference matters because the alternative is starting
// with an empty credential and failing on every request instead.
func TestLoadFailsOnMissingEnvReference(t *testing.T) {
	_, err := Load(write(t, `
upstream:
  endpoint: http://localhost:9002
  region: us-east-1
  access_key_id: ${DEFINITELY_NOT_SET_ANYWHERE}
  secret_access_key: SECRET
keys:
  keyring: keyring.json
`))
	if err == nil {
		t.Fatal("an unset environment reference was accepted")
	}
	if !strings.Contains(err.Error(), "DEFINITELY_NOT_SET_ANYWHERE") {
		t.Errorf("error = %v, want it to name the missing variable", err)
	}
}

// TestLoadRejectsUnknownFields catches typos. A misspelled path_style would
// otherwise be ignored and every request would fail for no visible reason.
func TestLoadRejectsUnknownFields(t *testing.T) {
	_, err := Load(write(t, minimal+"\nupstrem:\n  endpoint: typo\n"))
	if err == nil {
		t.Fatal("an unknown top-level field was accepted")
	}
}

func TestValidation(t *testing.T) {
	tests := map[string]string{
		"no endpoint": `
upstream: {region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}`,
		"no region": `
upstream: {endpoint: "http://x", access_key_id: a, secret_access_key: b}
keys: {keyring: k}`,
		"no credentials": `
upstream: {endpoint: "http://x", region: r}
keys: {keyring: k}`,
		"no keyring": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {}`,
		"unsupported key provider": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {provider: vault, keyring: k}`,
		"chunk size out of range": `
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}
crypto: {log2_chunk_size: 30}`,
		"half-configured TLS": `
server: {tls: {cert_file: /tmp/c}}
upstream: {endpoint: "http://x", region: r, access_key_id: a, secret_access_key: b}
keys: {keyring: k}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Error("an invalid configuration was accepted")
			}
		})
	}
}

// TestExposesPlaintextPublicly drives the startup warning. Between client and
// proxy the body is plaintext, so a non-loopback listener without TLS is worth
// saying out loud.
func TestExposesPlaintextPublicly(t *testing.T) {
	tests := []struct {
		listen string
		tls    bool
		want   bool
	}{
		{"127.0.0.1:9000", false, false},
		{"localhost:9000", false, false},
		{"[::1]:9000", false, false},
		{"0.0.0.0:9000", false, true},
		{":9000", false, true},
		{"10.0.0.5:9000", false, true},
		{"0.0.0.0:9000", true, false},
	}
	for _, tc := range tests {
		cfg := &Config{Server: Server{Listen: tc.listen}}
		if tc.tls {
			cfg.Server.TLS = TLS{CertFile: "c", KeyFile: "k"}
		}
		if got := cfg.ExposesPlaintextPublicly(); got != tc.want {
			t.Errorf("listen=%q tls=%t: got %t, want %t", tc.listen, tc.tls, got, tc.want)
		}
	}
}
