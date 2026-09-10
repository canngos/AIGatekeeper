package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/canngos/aigatekeeper/internal/admin"
	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/proxy"
)

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "configs/aigatekeeper.yaml", "path to the YAML configuration")
	logLevel := fs.String("log-level", "info", "operational log level: debug, info, warn, error")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, *cfgPath, stdout, logger); err != nil {
		logger.Error("fatal", "error", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, cfgPath string, stdout io.Writer, logger *slog.Logger) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return err
	}
	pol, err := policy.Compile(cfg, config.Hash(raw))
	if err != nil {
		return err
	}
	store := policy.NewStore(pol)

	rootCA, err := ca.Load(cfg.CA.Cert, cfg.CA.Key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w\nRun `aigatekeeper ca init` to create the root CA first", err)
		}
		return err
	}
	signer, err := ca.NewSigner(rootCA, cfg.CA.LeafTTL.Std())
	if err != nil {
		return err
	}
	certCache := ca.NewCache(signer, cfg.CA.CacheSize)

	transport, err := proxy.NewTransport(proxy.TransportConfig{
		ExtraRootPEMFiles:     cfg.TLS.UpstreamExtraRoots,
		Insecure:              cfg.TLS.UpstreamInsecure,
		UpstreamProxy:         cfg.TLS.UpstreamProxy,
		ResponseHeaderTimeout: cfg.Limits.UpstreamTimeout.Std(),
	})
	if err != nil {
		return err
	}
	if cfg.TLS.UpstreamInsecure {
		logger.Warn("tls.upstream_insecure is enabled: upstream certificates are NOT verified")
	}

	auditLog, closeAudit, err := buildAudit(cfg, stdout)
	if err != nil {
		return err
	}
	defer closeAudit()

	forwarder := proxy.NewForwarder(transport, logger)
	inspect := proxy.Chain(forwarder,
		proxy.Audited(auditLog, cfg.Audit.LogAllowed),
		proxy.Route(store),
		proxy.ReadBody(proxy.BodyLimits{
			MaxBodyBytes:    cfg.Limits.MaxBodyBytes.Int64(),
			MaxDecodedBytes: cfg.Limits.MaxDecodedBytes.Int64(),
		}),
		proxy.Parse(parser.Default()),
	)

	forward := proxy.New(proxy.Options{
		Certs:           certCache,
		Intercept:       store.Intercept,
		TunnelUnmatched: store.TunnelUnmatched,
		Inspect:         inspect,
		Transport:       transport,
		AdvertiseHTTP2:  cfg.TLS.AdvertiseHTTP2,
		Audit:           auditLog,
		Logger:          logger,
	})

	var reverses []*proxy.ReverseListener
	for _, rc := range cfg.Listen.Reverse {
		rl, err := proxy.NewReverseListener(rc.Name, rc.Upstream, inspect, logger, auditLog)
		if err != nil {
			return err
		}
		reverses = append(reverses, rl)
	}

	adminSrv := admin.New(admin.Options{
		CACertPEM: rootCA.CertPEM(),
		Version:   version,
		Ready:     func() bool { return store.Load() != nil },
		Logger:    logger,
	})

	logger.Info("policy loaded", "services", len(pol.Services), "hash", shortHash(pol.Hash), "monitor", pol.Monitor)
	logger.Info("root CA", "subject", rootCA.Cert.Subject.CommonName, "sha256", rootCA.Fingerprint())

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 2+len(reverses))
	launch := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(runCtx); err != nil {
				errc <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}
	launch("forward", func(c context.Context) error { return forward.ListenAndServe(c, cfg.Listen.Forward) })
	if cfg.Listen.Admin != "" {
		launch("admin", func(c context.Context) error { return adminSrv.ListenAndServe(c, cfg.Listen.Admin) })
	}
	for i, rl := range reverses {
		addr := cfg.Listen.Reverse[i].Listen
		launch("reverse/"+rl.Name, func(c context.Context) error { return rl.ListenAndServe(c, addr) })
	}

	<-runCtx.Done()
	wg.Wait()
	close(errc)
	var errs []error
	for e := range errc {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	logger.Info("shutdown complete")
	return nil
}

func buildAudit(cfg *config.Config, stdout io.Writer) (audit.Logger, func(), error) {
	var loggers audit.Multi
	var closers []func()
	if cfg.Audit.Stdout {
		loggers = append(loggers, audit.NewJSONLogger(stdout))
	}
	if cfg.Audit.File != "" {
		f, err := os.OpenFile(cfg.Audit.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("open audit file: %w", err)
		}
		loggers = append(loggers, audit.NewJSONLogger(f))
		closers = append(closers, func() { _ = f.Close() })
	}
	if len(loggers) == 0 {
		return audit.Discard, func() {}, nil
	}
	return loggers, func() {
		for _, c := range closers {
			c()
		}
	}, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q", s)
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
