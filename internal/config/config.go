// Package config loads and validates blindbucket's configuration file.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// Config is the whole configuration file.
type Config struct {
	Server   Server   `yaml:"server"`
	Upstream Upstream `yaml:"upstream"`
	Clients  []Client `yaml:"clients"`
	Keys     Keys     `yaml:"keys"`
	Crypto   Crypto   `yaml:"crypto"`
}

// Client is one credential the proxy accepts from its own clients.
//
// These are unrelated to the upstream credentials, which a client never sees.
// That separation is what stops a client bypassing the gateway to read
// ciphertext directly, or to write plaintext.
type Client struct {
	Name            string `yaml:"name"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	// Buckets lists the buckets this credential may use. "*" means all.
	Buckets []string `yaml:"buckets"`
}

// Server configures the S3 listener.
type Server struct {
	// Listen is the address to serve on. The default binds to loopback only:
	// between client and proxy the data is plaintext, so exposing the port
	// without TLS would undo the point of the gateway.
	Listen string `yaml:"listen"`
	TLS    TLS    `yaml:"tls"`
	// BaseDomain enables virtual-hosted-style addressing: with
	// "s3.internal.example" set, bucket.s3.internal.example addresses that
	// bucket. Empty accepts path-style only.
	BaseDomain string `yaml:"base_domain"`
	// AllowUnsignedPayload permits UNSIGNED-PAYLOAD from clients. Off by
	// default: without it the request body is covered by the signature, and
	// turning it on only makes sense behind TLS or in a sidecar, where the hop
	// between client and proxy is already trusted.
	AllowUnsignedPayload bool `yaml:"allow_unsigned_payload"`
}

// TLS configures transport security towards clients.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether a certificate was configured.
func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Upstream configures the storage provider.
type Upstream struct {
	Endpoint        string `yaml:"endpoint"`
	Region          string `yaml:"region"`
	PathStyle       bool   `yaml:"path_style"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
}

// Keys configures where key-encryption keys come from.
type Keys struct {
	// Provider selects the root-key source. Only "file" exists in this build;
	// "vault" and "awskms" arrive with M5.
	Provider string `yaml:"provider"`
	Keyring  string `yaml:"keyring"`
	// PassphraseFile holds the keyring passphrase. If empty, the passphrase is
	// read from $BLINDBUCKET_PASSPHRASE.
	PassphraseFile string `yaml:"passphrase_file"`
}

// Crypto configures the segment format.
type Crypto struct {
	// Log2ChunkSize selects the chunk size for new objects. It is also the
	// fallback when reading an object whose metadata does not record one.
	Log2ChunkSize uint8 `yaml:"log2_chunk_size"`
}

// envRef matches a ${VARIABLE} reference.
var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	//nolint:gosec // the path is a command-line argument; reading it is the point.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Server: Server{Listen: "127.0.0.1:9000"},
		Keys:   Keys{Provider: "file"},
		Crypto: Crypto{Log2ChunkSize: stream.DefaultLog2ChunkSize},
	}
	// KnownFields makes a typo in a key an error rather than a silently ignored
	// setting -- which for something like path_style would mean every request
	// failing for no visible reason.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}

	// Credentials are only ever referenced, never written in the file.
	for name, field := range map[string]*string{
		"upstream.access_key_id":     &cfg.Upstream.AccessKeyID,
		"upstream.secret_access_key": &cfg.Upstream.SecretAccessKey,
		"upstream.session_token":     &cfg.Upstream.SessionToken,
	} {
		if err := expandEnv(name, field); err != nil {
			return nil, err
		}
	}
	for i := range cfg.Clients {
		for name, field := range map[string]*string{
			"access_key_id":     &cfg.Clients[i].AccessKeyID,
			"secret_access_key": &cfg.Clients[i].SecretAccessKey,
		} {
			if err := expandEnv("clients["+strconv.Itoa(i)+"]."+name, field); err != nil {
				return nil, err
			}
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// expandEnv resolves a ${VAR} reference in place.
func expandEnv(name string, field *string) error {
	match := envRef.FindStringSubmatch(*field)
	if match == nil {
		return nil
	}
	value, ok := os.LookupEnv(match[1])
	if !ok {
		return fmt.Errorf("config: %s references $%s, which is not set", name, match[1])
	}
	*field = value
	return nil
}

func (c *Config) validate() error {
	switch {
	case c.Server.Listen == "":
		return fmt.Errorf("server.listen must not be empty")
	case c.Upstream.Endpoint == "":
		return fmt.Errorf("upstream.endpoint is required")
	case c.Upstream.Region == "":
		return fmt.Errorf("upstream.region is required")
	case c.Upstream.AccessKeyID == "" || c.Upstream.SecretAccessKey == "":
		return fmt.Errorf("upstream credentials are required")
	case len(c.Clients) == 0:
		return fmt.Errorf("at least one entry under clients is required; " +
			"the proxy does not serve unauthenticated requests")
	case c.Keys.Provider != "file":
		return fmt.Errorf("keys.provider %q is not supported in this build (only \"file\")", c.Keys.Provider)
	case c.Keys.Keyring == "":
		return fmt.Errorf("keys.keyring is required")
	}
	for i, client := range c.Clients {
		switch {
		case client.Name == "":
			return fmt.Errorf("clients[%d] has no name", i)
		case client.AccessKeyID == "":
			return fmt.Errorf("client %q has no access_key_id", client.Name)
		case client.SecretAccessKey == "":
			return fmt.Errorf("client %q has no secret_access_key", client.Name)
		case len(client.Buckets) == 0:
			// An empty list would deny everything silently, which looks like a
			// broken proxy rather than a configuration mistake.
			return fmt.Errorf("client %q lists no buckets (use \"*\" for all)", client.Name)
		}
	}
	if err := stream.ValidateLog2ChunkSize(c.Crypto.Log2ChunkSize); err != nil {
		return fmt.Errorf("crypto.log2_chunk_size: %w", err)
	}
	if (c.Server.TLS.CertFile == "") != (c.Server.TLS.KeyFile == "") {
		return fmt.Errorf("server.tls needs both cert_file and key_file, or neither")
	}
	return nil
}

// ExposesPlaintextPublicly reports whether the listener would carry plaintext
// beyond the loopback interface without TLS.
//
// Between client and proxy the body is not encrypted -- that is the entire
// point of the gateway -- so this is worth saying out loud at startup rather
// than leaving an operator to discover it.
func (c *Config) ExposesPlaintextPublicly() bool {
	if c.Server.TLS.Enabled() {
		return false
	}
	// net.SplitHostPort rather than a manual split: an IPv6 listener is written
	// "[::1]:9000", and cutting at the first colon yields "[".
	host, _, err := net.SplitHostPort(c.Server.Listen)
	switch {
	case err != nil:
		return true
	case host == "":
		// ":9000" means every interface.
		return true
	case host == "localhost":
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return true
}
