package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/proxy"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// shutdownGrace is how long in-flight requests may finish after a signal.
// Aborted uploads leave nothing behind upstream, because a segment is only
// valid once its final chunk is written.
const shutdownGrace = 30 * time.Second

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), `Usage: blindbucket serve --config <file>

Runs the S3 gateway. Clients point at this endpoint instead of the storage
provider; the provider only ever sees ciphertext.

Clients are authenticated with SigV4 against the credentials in the config file.
Between client and proxy the body is plaintext, so use TLS or keep the listener
on loopback.

Flags:
`)
		fs.PrintDefaults()
	}

	var (
		cfgPath = fs.String("config", "blindbucket.yaml", "configuration file")
		verbose = fs.Bool("v", false, "log at debug level")
		pass    passphraseFlags
	)
	pass.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if pass.file == "" {
		pass.file = cfg.Keys.PassphraseFile
	}
	ring, err := loadServerKeyring(cfg, &pass)
	if err != nil {
		return err
	}

	client, err := upstream.New(upstream.Config{
		Endpoint:        cfg.Upstream.Endpoint,
		Region:          cfg.Upstream.Region,
		PathStyle:       cfg.Upstream.PathStyle,
		AccessKeyID:     cfg.Upstream.AccessKeyID,
		SecretAccessKey: cfg.Upstream.SecretAccessKey,
		SessionToken:    cfg.Upstream.SessionToken,
	})
	if err != nil {
		return err
	}

	clients := make([]auth.Client, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients = append(clients, auth.Client{
			Name: c.Name, AccessKeyID: c.AccessKeyID,
			SecretAccessKey: c.SecretAccessKey, Buckets: c.Buckets,
		})
	}
	verifier, err := auth.NewVerifier(auth.Config{
		Clients:              clients,
		AllowUnsignedPayload: cfg.Server.AllowUnsignedPayload,
	})
	if err != nil {
		return err
	}

	handler, err := proxy.New(proxy.Config{
		Upstream:      client,
		Keys:          ring,
		Verifier:      verifier,
		BaseDomain:    cfg.Server.BaseDomain,
		Log2ChunkSize: cfg.Crypto.Log2ChunkSize,
		Logger:        log,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: handler,
		// Slowloris protection. There is deliberately no WriteTimeout: it would
		// cut off a large download after a fixed time regardless of progress.
		// Per-chunk deadlines via http.ResponseController arrive with M3.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	listener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}

	log.Info("blindbucket listening",
		"addr", listener.Addr().String(),
		"upstream", cfg.Upstream.Endpoint,
		"active_kid", ring.ActiveKID(),
		"log2_chunk_size", cfg.Crypto.Log2ChunkSize,
		"clients", len(cfg.Clients),
		"base_domain", cfg.Server.BaseDomain,
		"tls", cfg.Server.TLS.Enabled(),
	)
	if cfg.ExposesPlaintextPublicly() {
		log.Warn("this listener carries plaintext beyond loopback without TLS; " +
			"clients and proxy must share a trust boundary")
	}
	if cfg.Server.AllowUnsignedPayload {
		log.Warn("UNSIGNED-PAYLOAD is enabled; request bodies are not covered by the signature")
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.Server.TLS.Enabled() {
			serveErr <- srv.ServeTLS(listener, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			return
		}
		serveErr <- srv.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down", "grace", shutdownGrace.String())
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

func loadServerKeyring(cfg *config.Config, pass *passphraseFlags) (*keys.Keyring, error) {
	//nolint:gosec // the path comes from the operator's own configuration file.
	data, err := os.ReadFile(cfg.Keys.Keyring)
	if err != nil {
		return nil, err
	}
	phrase, err := pass.resolve("Passphrase for "+cfg.Keys.Keyring+": ", false)
	if err != nil {
		return nil, err
	}
	defer clear(phrase)
	return keys.LoadKeyring(data, phrase)
}
