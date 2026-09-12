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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/obs"
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
	ring, err := loadServerKeyring(ctx, cfg, &pass)
	if err != nil {
		return err
	}

	// The registry is built before the upstream client so that the client can
	// report how long the provider takes without knowing what a metric is.
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(
		collectors.ProcessCollectorOpts{}))
	metrics := obs.NewMetrics(registry)

	client, err := upstream.New(upstream.Config{
		Endpoint:        cfg.Upstream.Endpoint,
		Region:          cfg.Upstream.Region,
		PathStyle:       cfg.Upstream.PathStyle,
		AccessKeyID:     cfg.Upstream.AccessKeyID,
		SecretAccessKey: cfg.Upstream.SecretAccessKey,
		SessionToken:    cfg.Upstream.SessionToken,
		ObserveRequest:  metrics.Upstream,
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
		Metrics:       metrics,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: handler,
		// Slowloris protection for the headers. There is deliberately no
		// WriteTimeout: it would cut off a large download after a fixed time
		// regardless of progress. What replaces it is per-transfer rather than
		// per-server -- the proxy renews the connection's deadlines as bytes
		// move, so a request may run as long as it likes but not stall as long
		// as it likes (CONCEPT.md 12.3, internal/proxy/deadline.go).
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	listener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}

	// Metrics, health and profiles live on their own address. An empty
	// admin.listen turns the whole listener off rather than exporting nothing
	// on a port nobody asked for.
	var admin *obs.AdminServer
	if cfg.Admin.Listen != "" {
		admin = obs.NewAdminServer(obs.AdminConfig{
			Listen:      cfg.Admin.Listen,
			EnablePprof: cfg.Admin.Pprof,
			Registry:    registry,
			Ready:       readiness(client, ring, probeBucket(cfg)),
			Logger:      log,
		})
		if err := admin.Start(); err != nil {
			return err
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := admin.Shutdown(shutdownCtx); err != nil {
				log.Warn("the admin listener did not stop cleanly", "err", err)
			}
		}()
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

func loadServerKeyring(ctx context.Context, cfg *config.Config, pass *passphraseFlags) (*keys.Keyring, error) {
	return openKeyring(ctx, cfg.Keys.Keyring, cfg.Keys, pass)
}

// probeBucket picks a bucket for the readiness check to look at.
//
// There is no "the" bucket in the configuration -- a client names one per
// request -- so the first concrete bucket a credential is scoped to is used. A
// deployment whose credentials are all wildcards gives nothing to probe, and
// readiness then reports on the keyring alone rather than inventing a name.
func probeBucket(cfg *config.Config) string {
	for _, client := range cfg.Clients {
		for _, bucket := range client.Buckets {
			if bucket != "" && bucket != auth.AllBuckets {
				return bucket
			}
		}
	}
	return ""
}

// readiness reports whether the gateway can actually serve.
//
// Liveness is "the process runs"; readiness is "the keyring is loaded and the
// provider answers", which is the pair CONCEPT.md section 17.3 asks for. The
// provider check is a bucket HEAD rather than a listing: it is the cheapest call
// that still proves credentials and connectivity, and it reads nothing.
func readiness(client *upstream.Client, ring *keys.Keyring, bucket string) func(context.Context) error {
	return func(ctx context.Context) error {
		if ring.ActiveKID() == "" {
			return errors.New("no active key in the keyring")
		}
		if bucket == "" {
			// Nothing concrete to probe against; the keyring check stands alone.
			return nil
		}
		if _, err := client.Passthrough(ctx, http.MethodHead, bucket, nil, nil); err != nil {
			return fmt.Errorf("upstream: %w", err)
		}
		return nil
	}
}
