package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
)

// Hooks connect a service listener to its component lifecycle.
type Hooks struct {
	Startup   func(context.Context) error
	Readiness func(context.Context) error
	Reconcile func(context.Context, *slog.Logger)
	Close     func() error
	Handler   http.Handler
}

// Main parses service options and serves until the process is stopped.
func Main(component string, load func(string) (config.Server, Hooks, error)) int {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	configPath := flags.String("config", "", "path to a JSON configuration file")
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var level slog.LevelVar
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: &level})).With("component", component)
	if flags.NArg() != 0 {
		logger.Error("Unexpected positional arguments")
		return 2
	}

	settings, hooks, err := load(*configPath)
	if err != nil {
		logger.Error("Invalid configuration", "error", err)
		return 1
	}
	if hooks.Close != nil {
		defer hooks.Close()
	}
	level.Set(settings.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, settings, hooks, logger); err != nil {
		logger.Error("Service stopped with an error", "error", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, settings config.Server, hooks Hooks, logger *slog.Logger) error {
	server := &http.Server{
		Handler:           serviceHandler(ctx, hooks),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	if settings.TLS != nil {
		cert, err := tls.LoadX509KeyPair(settings.TLS.CertificateFile, settings.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if settings.TLS.ClientCAFile != "" {
			ca, err := os.ReadFile(settings.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("load client CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return errors.New("client CA file contains no certificates")
			}
			server.TLSConfig.ClientCAs = pool
			server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			if settings.TLS.OptionalClientCA {
				server.TLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
			}
		}
	}
	if hooks.Startup != nil {
		startup, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := hooks.Startup(startup)
		cancel()
		if err != nil {
			return fmt.Errorf("startup check: %w", err)
		}
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", settings.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	logger.Info("Service listening", "address", listener.Addr().String(), "tls", settings.TLS != nil)
	if hooks.Reconcile != nil {
		reconciler, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			hooks.Reconcile(reconciler, logger)
		}()
		defer func() {
			cancel()
			<-done
		}()
	}

	stopped := make(chan error, 1)
	go func() {
		if server.TLSConfig != nil {
			stopped <- server.ServeTLS(listener, "", "")
			return
		}
		stopped <- server.Serve(listener)
	}()

	select {
	case err := <-stopped:
		return err
	case <-ctx.Done():
		logger.Info("Stopping service")
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		if err := <-stopped; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func serviceHandler(ctx context.Context, hooks Hooks) http.Handler {
	mux := http.NewServeMux()
	if hooks.Handler != nil {
		mux.Handle("/", hooks.Handler)
	}
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if ctx.Err() != nil {
			http.Error(w, "Service is stopping", http.StatusServiceUnavailable)
			return
		}
		if hooks.Readiness != nil {
			probe, cancel := context.WithTimeout(request.Context(), time.Second)
			defer cancel()
			if err := hooks.Readiness(probe); err != nil {
				http.Error(w, "Service is not ready", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
