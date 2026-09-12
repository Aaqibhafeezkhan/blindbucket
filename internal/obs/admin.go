package obs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// readyTimeout bounds the upstream check behind /readyz.
//
// The endpoint reaches the storage provider, so it is a way to make this process
// generate traffic. A short timeout plus a cache (see AdminConfig.Ready) keeps a
// readiness probe from becoming an amplifier.
const readyTimeout = 3 * time.Second

// AdminConfig describes the operator-facing listener.
//
// It is separate from the S3 listener on purpose: metrics, health and profiles
// are not things a storage client should be able to reach, and keeping them on
// their own address means the S3 port can be exposed while this one is not.
type AdminConfig struct {
	// Listen is the address to serve on. It defaults to loopback, and should
	// stay there unless something in front of it is doing authorisation.
	Listen string
	// EnablePprof exposes /debug/pprof. Off by default: profiles include
	// goroutine stacks and heap contents, which is not something to publish by
	// accident.
	EnablePprof bool
	Registry    *prometheus.Registry
	// Ready reports whether the gateway can serve requests: the keyring is
	// loaded and the provider answers. A nil Ready means ready.
	Ready  func(context.Context) error
	Logger *slog.Logger
}

// AdminServer serves metrics, health and -- when asked for -- profiles.
type AdminServer struct {
	server *http.Server
	log    *slog.Logger
	addr   string
}

// NewAdminServer builds the listener without starting it.
func NewAdminServer(cfg AdminConfig) *AdminServer {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9100"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	mux := http.NewServeMux()

	// Liveness answers whether the process is running, and nothing else. It
	// deliberately does not touch the provider: a restart loop caused by an
	// upstream outage is worse than the outage.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if cfg.Ready == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		if err := cfg.Ready(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			// The reason is for an operator reading a probe log, so it says what
			// failed without repeating anything sensitive from the config.
			_, _ = fmt.Fprintf(w, "not ready: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	if cfg.Registry != nil {
		mux.Handle("GET /metrics", promhttp.HandlerFor(cfg.Registry, promhttp.HandlerOpts{
			// A collector that panics should not take the process with it, and
			// an error while scraping is the scraper's problem to see.
			ErrorHandling: promhttp.ContinueOnError,
		}))
	}

	if cfg.EnablePprof {
		cfg.Logger.Warn("pprof is enabled; profiles expose goroutine stacks and heap contents",
			"listen", cfg.Listen)
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	}

	return &AdminServer{
		server: &http.Server{
			Addr:    cfg.Listen,
			Handler: mux,
			// Generous enough for a 30-second CPU profile, bounded enough that a
			// stuck scraper does not hold a connection for ever.
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       60 * time.Second,
		},
		log:  cfg.Logger,
		addr: cfg.Listen,
	}
}

// Start serves until Shutdown is called. It returns once the listener is open,
// so a caller knows the port is bound before it reports itself started.
func (s *AdminServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("obs: admin listener on %s: %w", s.addr, err)
	}
	s.log.Info("admin listener started", "addr", listener.Addr().String())
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("admin listener stopped", "err", err)
		}
	}()
	return nil
}

// Shutdown stops the listener, letting in-flight scrapes finish.
func (s *AdminServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
