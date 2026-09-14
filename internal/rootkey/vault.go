// Package rootkey obtains the root key that unlocks a keyring.
//
// The key hierarchy (FORMAT.md §3) has always put the root key outside the
// process: Argon2id over an operator's passphrase, or a key service that holds
// the real secret and hands back only what it decrypts. This package is the
// second half of that sentence.
//
// It is deliberately a *startup* path. A source is asked once, when the process
// opens its keyring, and never again: every KEK is then in memory and no
// request pays a round trip to a key service. That is also the honest limit of
// what this buys — the root key lives in the process afterwards, exactly as the
// passphrase-derived one does (THREAT_MODEL §5.5). What it buys is that the
// secret is not a passphrase on the operator's machine, that access to it is
// logged and revocable by somebody else, and that revoking it locks every
// instance out at its next restart.
//
// It lives outside internal/crypto because talking to Vault and KMS is HTTP,
// and the crypto packages have no dependency on HTTP or on any service.
package rootkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// maxResponse bounds what is read from a key service. The answers are a few
// hundred bytes; anything larger is a misconfigured endpoint, not a key.
const maxResponse = 1 << 16

// defaultTimeout bounds a single call to a key service.
//
// This runs at startup, before the listener opens, so a service that hangs
// would otherwise hang the process with no diagnostics. Ten seconds is far more
// than a decrypt needs and short enough to fail visibly.
const defaultTimeout = 10 * time.Second

// VaultConfig addresses a Vault Transit key.
type VaultConfig struct {
	// Address is the Vault API base URL, e.g. https://vault.internal:8200.
	Address string
	// Token authenticates to Vault.
	Token string
	// Mount is the path the Transit engine is mounted at. Defaults to "transit".
	Mount string
	// KeyName is the Transit key that encrypts the root key.
	KeyName string
	// Namespace is Vault Enterprise's X-Vault-Namespace, if one applies.
	Namespace string

	HTTPClient *http.Client
}

// Vault obtains a root key from Vault's Transit secrets engine.
//
// Transit is the right shape for this: Vault holds the key, performs the
// decryption itself and never returns it, so a compromised gateway host yields
// the root key it is currently using and no ability to open a keyring it has
// not been given.
//
// It speaks Vault's HTTP API directly rather than through the Vault SDK, for
// the reason ADR-003 gives for the S3 client: two endpoints of a documented
// JSON API are less code than the dependency that would wrap them, and the
// dependency would be the largest in the module.
type Vault struct {
	cfg    VaultConfig
	client *http.Client
}

// NewVault validates the configuration and returns a source.
func NewVault(cfg VaultConfig) (*Vault, error) {
	switch {
	case strings.TrimSpace(cfg.Address) == "":
		return nil, fmt.Errorf("rootkey: vault needs an address")
	case strings.TrimSpace(cfg.Token) == "":
		return nil, fmt.Errorf("rootkey: vault needs a token")
	case strings.TrimSpace(cfg.KeyName) == "":
		return nil, fmt.Errorf("rootkey: vault needs a transit key name")
	}
	if _, err := url.Parse(cfg.Address); err != nil {
		return nil, fmt.Errorf("rootkey: vault address is not a URL: %w", err)
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	return &Vault{cfg: cfg, client: client}, nil
}

// Encrypt hands a fresh root key to Vault and returns what a keyring must
// record to get it back.
//
// Used by `blindbucket keygen`, never by the gateway: a running instance only
// ever decrypts.
//
// No Transit "context" is sent, which is the one place this differs from the
// KMS source. Transit accepts a context only for keys created with key
// derivation enabled, so sending one would fail against an ordinary Transit key
// and silently change what the key is. Narrowing access to this use of a
// Transit key is done with a policy on its own mount path instead.
func (v *Vault) Encrypt(ctx context.Context, rootKey []byte) (keys.RootKeyRef, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(rootKey)}
	if err := v.call(ctx, "encrypt", body, &out); err != nil {
		return keys.RootKeyRef{}, err
	}
	if out.Data.Ciphertext == "" {
		return keys.RootKeyRef{}, fmt.Errorf("rootkey: vault returned no ciphertext")
	}
	return keys.RootKeyRef{
		Source:     keys.SourceVaultTransit,
		Ciphertext: out.Data.Ciphertext,
		KeyName:    v.cfg.KeyName,
	}, nil
}

// RootKey asks Vault to decrypt the stored root key.
func (v *Vault) RootKey(ctx context.Context, ref keys.RootKeyRef) ([]byte, error) {
	if ref.Source != keys.SourceVaultTransit {
		return nil, fmt.Errorf("rootkey: keyring names source %q, not %q",
			ref.Source, keys.SourceVaultTransit)
	}
	// A mismatch here is the common misconfiguration -- a keyring from another
	// environment -- and saying so beats a decryption failure with no cause.
	if ref.KeyName != "" && ref.KeyName != v.cfg.KeyName {
		return nil, fmt.Errorf(
			"rootkey: this keyring was sealed under transit key %q, but %q is configured",
			ref.KeyName, v.cfg.KeyName)
	}

	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.call(ctx, "decrypt", map[string]string{"ciphertext": ref.Ciphertext}, &out); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("rootkey: vault returned a plaintext that is not base64: %w", err)
	}
	if len(key) != keys.KeySize {
		clear(key)
		return nil, fmt.Errorf("rootkey: vault returned a %d byte key, want %d",
			len(key), keys.KeySize)
	}
	return key, nil
}

// call posts to one Transit endpoint and decodes its answer.
func (v *Vault) call(ctx context.Context, op string, in any, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/v1/%s/%s/%s",
		strings.TrimRight(v.cfg.Address, "/"),
		url.PathEscape(v.cfg.Mount), op, url.PathEscape(v.cfg.KeyName))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("rootkey: vault %s: %w", op, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("rootkey: reading vault's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Vault reports its errors in a JSON "errors" array. The token is in
		// the request, never in the response, so this is safe to surface.
		var failure struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(raw, &failure) == nil && len(failure.Errors) > 0 {
			return fmt.Errorf("rootkey: vault %s: %s (%d)",
				op, strings.Join(failure.Errors, "; "), resp.StatusCode)
		}
		return fmt.Errorf("rootkey: vault %s returned %d", op, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("rootkey: vault's answer is not the expected JSON: %w", err)
	}
	return nil
}

// Source is what a keyring's root key can come from.
//
// Both implementations are startup-only: the gateway calls RootKey once and
// keeps the KEKs it unlocks. Encrypt exists for `blindbucket keygen`, which is
// the only thing that ever hands a key to a service.
type Source interface {
	RootKey(ctx context.Context, ref keys.RootKeyRef) ([]byte, error)
	// Encrypt seals a fresh root key and returns the reference a keyring file
	// records: everything the next process needs to ask for it back, including
	// any associated data the service bound the ciphertext to.
	Encrypt(ctx context.Context, rootKey []byte) (keys.RootKeyRef, error)
}

var (
	_ Source = (*Vault)(nil)
	_ Source = (*KMS)(nil)
)
