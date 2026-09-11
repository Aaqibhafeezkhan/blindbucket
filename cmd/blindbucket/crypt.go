package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"golang.org/x/term"

	"github.com/LennardGeissler/blindbucket/internal/crypto/envelope"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/stream"
)

// cryptFlags are shared by encrypt and decrypt.
type cryptFlags struct {
	keyring string
	in      string
	out     string
	pass    passphraseFlags
}

func (c *cryptFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.keyring, "keyring", "", "keyring file (required)")
	fs.StringVar(&c.in, "i", "-", "input file, or - for stdin")
	fs.StringVar(&c.out, "o", "-", "output file, or - for stdout")
	c.pass.register(fs)
}

func (c *cryptFlags) loadKeyring() (*keys.Keyring, error) {
	if c.keyring == "" {
		return nil, errors.New("--keyring is required")
	}
	data, err := os.ReadFile(c.keyring)
	if err != nil {
		return nil, err
	}
	phrase, err := c.pass.resolve("Passphrase for "+c.keyring+": ", false)
	if err != nil {
		return nil, err
	}
	defer clear(phrase)

	ring, err := keys.LoadKeyring(data, phrase)
	if err != nil {
		return nil, err
	}

	// Argon2id deliberately allocates 64 MiB, and that arena is dead the moment
	// the root key exists. Go does not hand freed pages back to the operating
	// system promptly on its own, so without this the process would sit at ~70
	// MiB of resident memory for the whole run and the streaming path's flat
	// memory profile would be invisible behind it. Returning it here is cheap:
	// it happens once, before any data moves.
	debug.FreeOSMemory()

	return ring, nil
}

func runEncrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket encrypt --keyring <file> [flags] < plaintext > ciphertext

Encrypts a stream into a blindbucket file under the keyring's active key.
Memory stays proportional to the chunk size, not to the size of the input.

Flags:
`)
		fs.PrintDefaults()
	}

	var c cryptFlags
	c.register(fs)
	log2C := fs.Uint("chunk-size-log2", stream.DefaultLog2ChunkSize,
		fmt.Sprintf("log2 of the chunk size in bytes (%d..%d)", stream.MinLog2ChunkSize, stream.MaxLog2ChunkSize))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *log2C > 255 {
		return fmt.Errorf("--chunk-size-log2 %d is out of range", *log2C)
	}
	if err := stream.ValidateLog2ChunkSize(uint8(*log2C)); err != nil {
		return err
	}

	ring, err := c.loadKeyring()
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(c.in)
	if err != nil {
		return err
	}
	defer closeSrc()

	dst, finish, err := openOutput(c.out, true)
	if err != nil {
		return err
	}
	if err := envelope.Encrypt(ctx, dst, src, ring, uint8(*log2C)); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func runDecrypt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket decrypt --keyring <file> [flags] < ciphertext > plaintext

Decrypts a blindbucket file. Nothing is written until the first chunk has been
authenticated, so a wrong key or a damaged file leaves the output untouched.

Flags:
`)
		fs.PrintDefaults()
	}

	var c cryptFlags
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ring, err := c.loadKeyring()
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(c.in)
	if err != nil {
		return err
	}
	defer closeSrc()

	dst, finish, err := openOutput(c.out, false)
	if err != nil {
		return err
	}
	if err := envelope.Decrypt(ctx, dst, src, ring); err != nil {
		return finish(err)
	}
	return finish(nil)
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	//nolint:gosec // the path is a command-line argument; opening it is the point.
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// openOutput returns the destination and a finish function that must be called
// with the outcome.
//
// For a real file the output is written to a temporary path and only renamed
// into place on success, so a failed run cannot leave a plausible-looking
// truncated file behind.
func openOutput(path string, binaryOut bool) (io.Writer, func(error) error, error) {
	if path == "-" {
		if binaryOut && term.IsTerminal(int(os.Stdout.Fd())) {
			return nil, nil, errors.New("refusing to write binary output to a terminal; use -o or redirect")
		}
		return os.Stdout, func(err error) error { return err }, nil
	}

	// Write-then-rename only makes sense for a regular file. A device or a fifo
	// -- /dev/null being the common case -- has to be written to directly.
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		//nolint:gosec // the path is a command-line argument; opening it is the point.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return nil, nil, err
		}
		return f, func(runErr error) error {
			closeErr := f.Close()
			if runErr != nil {
				return runErr
			}
			return closeErr
		}, nil
	}

	tmp := path + ".tmp"
	//nolint:gosec // the path is a command-line argument; creating it is the point.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	finish := func(runErr error) error {
		closeErr := f.Close()
		if runErr != nil {
			_ = os.Remove(tmp)
			return runErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		return os.Rename(tmp, path)
	}
	return f, finish, nil
}
