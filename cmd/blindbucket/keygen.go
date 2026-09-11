package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

func runKeygen(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket keygen --out <file> [flags]

Creates a keyring holding one key-encryption key, protected by a passphrase
stretched with Argon2id. Without --add, an existing file is never overwritten:
losing a keyring means losing every object encrypted under it.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		out  = fs.String("out", "", "keyring file to write (required)")
		kid  = fs.String("kid", defaultKID(), "id of the key to create")
		add  = fs.Bool("add", false, "add a key to an existing keyring instead of creating one")
		act  = fs.Bool("activate", true, "with --add, make the new key the active one")
		pass passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		fs.Usage()
		return errors.New("--out is required")
	}
	if err := keys.ValidateKID(*kid); err != nil {
		return err
	}

	if *add {
		return addKey(*out, *kid, *act, &pass)
	}
	return createKeyring(*out, *kid, &pass)
}

func createKeyring(path, kid string, pass *passphraseFlags) error {
	// Refuse to clobber. A keyring is the only copy of the keys protecting every
	// object written under it; overwriting one is not recoverable.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists (use --add to add a key to it)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	phrase, err := pass.resolve("Passphrase for the new keyring: ", true)
	if err != nil {
		return err
	}
	defer clear(phrase)

	ring := keys.NewKeyring()
	if err := ring.Generate(kid); err != nil {
		return err
	}
	data, err := ring.Marshal(phrase, keys.DefaultKDFParams)
	if err != nil {
		return err
	}
	if err := writeKeyring(path, data); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s with key %q (active)\n", path, kid)
	return nil
}

func addKey(path, kid string, activate bool, pass *passphraseFlags) error {
	//nolint:gosec // the path is a command-line argument.
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	phrase, err := pass.resolve("Passphrase for "+path+": ", false)
	if err != nil {
		return err
	}
	defer clear(phrase)

	ring, err := keys.LoadKeyring(data, phrase)
	if err != nil {
		return err
	}
	if err := ring.Generate(kid); err != nil {
		return err
	}
	if activate {
		if err := ring.SetActive(kid); err != nil {
			return err
		}
	}

	updated, err := ring.Marshal(phrase, keys.DefaultKDFParams)
	if err != nil {
		return err
	}
	if err := writeKeyring(path, updated); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "added key %q to %s (active key: %q)\n", kid, path, ring.ActiveKID())
	return nil
}

// writeKeyring writes atomically and restrictively: a half-written keyring would
// be unreadable, and a world-readable one defeats the passphrase.
func writeKeyring(path string, data []byte) error {
	tmp := path + ".tmp"
	//nolint:gosec // the path is a command-line argument.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// defaultKID names a key after the month it was created, which is the shape the
// rotation workflow in CONCEPT.md section 11.2 assumes.
func defaultKID() string { return time.Now().UTC().Format("2006-01") }
