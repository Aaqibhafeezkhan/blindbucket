package main

import (
	"context"
	"fmt"
	"os"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/rootkey"
)

// newRootKeySource builds the source a configuration names.
//
// Returns nil for provider "file", which needs no service: the root key is
// derived from a passphrase inside the process.
func newRootKeySource(cfg config.Keys) (rootkey.Source, error) {
	switch cfg.Provider {
	case "", "file":
		return nil, nil
	case "vault":
		return rootkey.NewVault(rootkey.VaultConfig{
			Address:   cfg.Vault.Address,
			Token:     cfg.Vault.Token,
			Mount:     cfg.Vault.Mount,
			KeyName:   cfg.Vault.KeyName,
			Namespace: cfg.Vault.Namespace,
		})
	case "awskms":
		return rootkey.NewKMS(rootkey.KMSConfig{
			Region:          cfg.AWSKMS.Region,
			KeyID:           cfg.AWSKMS.KeyID,
			AccessKeyID:     cfg.AWSKMS.AccessKeyID,
			SecretAccessKey: cfg.AWSKMS.SecretAccessKey,
			SessionToken:    cfg.AWSKMS.SessionToken,
			Endpoint:        cfg.AWSKMS.Endpoint,
		})
	default:
		return nil, fmt.Errorf("unknown keys.provider %q", cfg.Provider)
	}
}

// openKeyring reads a keyring file and unlocks it by whatever sealed it.
//
// The file says which source that was, and the configuration says how to reach
// it. Disagreement between the two is an error: falling back to a passphrase
// prompt for a Vault-sealed keyring would ask the operator for something that
// cannot work, and silently using a configured service on a passphrase keyring
// would fail with no explanation. This is the single place all three commands
// open a keyring, so the rule is stated once.
func openKeyring(ctx context.Context, path string, cfg config.Keys, pass *passphraseFlags) (*keys.Keyring, error) {
	//nolint:gosec // the path comes from the operator's own configuration.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ref, err := keys.ReadRootKeyRef(data)
	if err != nil {
		return nil, err
	}

	if ref.Source == keys.SourcePassphrase {
		if cfg.Provider != "" && cfg.Provider != "file" {
			return nil, fmt.Errorf(
				"%s is sealed with a passphrase, but keys.provider is %q", path, cfg.Provider)
		}
		phrase, err := pass.resolve("Passphrase for "+path+": ", false)
		if err != nil {
			return nil, err
		}
		defer clear(phrase)
		return keys.LoadKeyring(data, phrase)
	}

	source, err := newRootKeySource(cfg)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf(
			"%s is sealed by %s, but keys.provider is %q; configure that provider to open it",
			path, ref.Source, cfg.Provider)
	}

	root, err := source.RootKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	return keys.LoadKeyringWithRootKey(data, root)
}
