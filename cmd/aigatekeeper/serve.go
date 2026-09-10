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
	"time"

	"github.com/canngos/aigatekeeper/internal/admin"
	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/metrics"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/proxy"
	"github.com/canngos/aigatekeeper/internal/reload"
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
	// The first parse tells us how to set up audit sinks and listeners,
	// which are fixed for the process lifetime; everything policy-related
	// is hot-reloadable through the manager.
	bootCfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	dispatcher, err := buildAudit(bootCfg, stdout)
	if err != nil {
		return err
	}
	defer func() {
		if err := dispatcher.Close(5 * time.Second); err != nil {
			logger.Warn("audit shutdown", "error", err)
		}
	}()
	auditLog := metrics.Counting(dispatcher)

	store := policy.NewStore(nil)
	manager := reload.NewManager(cfgPath, store, auditLog, logger)
	loaded, err := manager.Load(ctx)
	if err != nil {
		return err
	}
	cfg := loaded.Config

	rootCA, err := ca.Load(cfg.ResolvePath(cfg.CA.Cert), cfg.ResolvePath(cfg.CA.Key))
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

	var extraRoots []string
	for _, p := range cfg.TLS.UpstreamExtraRoots {
		extraRoots = append(extraRoots, cfg.ResolvePath(p))
	}
	transport, err := proxy.NewTransport(proxy.TransportConfig{
		ExtraRootPEMFiles:     extraRoots,
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

	forwarder := proxy.NewForwarder(transport, logger)
	inspect := proxy.Chain(forwarder,
		proxy.Audited(auditLog, cfg.Audit.LogAllowed),
		proxy.Route(store),
		proxy.ReadBody(proxy.BodyLimits{
			MaxBodyBytes:    cfg.Limits.MaxBodyBytes.Int64(),
			MaxDecodedBytes: cfg.Limits.MaxDecodedBytes.Int64(),
		}),
		proxy.Parse(parser.Default()),
		proxy.Enforce(store),
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

	reloadFn := func(ctx context.Context) (bool, string, error) {
		l, changed, err := manager.ReloadFromDisk(ctx, "admin")
		version := ""
		if l != nil {
			version = l.Hash
		}
		return changed, version, err
	}
	adminSrv := admin.New(admin.Options{
		CACertPEM:  rootCA.CertPEM(),
		Version:    version,
		Ready:      func() bool { return store.Load() != nil },
		Reload:     reloadFn,
		PolicyInfo: func() any { return policySummary(manager, dispatcher) },
		Logger:     logger,
	})

	logger.Info("root CA", "subject", rootCA.Cert.Subject.CommonName, "sha256", rootCA.Fingerprint())

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 3+len(reverses))
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
	if cfg.Reload.Watch || cfg.Reload.PollInterval.Std() > 0 {
		launch("config-watch", func(c context.Context) error {
			return reload.Watch(c, manager, reload.WatchOptions{
				Debounce:        cfg.Reload.Debounce.Std(),
				PollInterval:    cfg.Reload.PollInterval.Std(),
				DisableFsnotify: !cfg.Reload.Watch,
				Logger:          logger,
			})
		})
	}
	onHangup(runCtx, func() { _, _, _ = manager.ReloadFromDisk(runCtx, "signal") })

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

func buildAudit(cfg *config.Config, stdout io.Writer) (*audit.Dispatcher, error) {
	d := audit.NewDispatcher()
	if cfg.Audit.Stdout {
		d.Add("stdout", audit.NewJSONLogger(stdout), audit.SinkOptions{Queue: 1024, Overflow: audit.OverflowBlock})
	}
	if cfg.Audit.File != "" {
		f, err := os.OpenFile(cfg.ResolvePath(cfg.Audit.File), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, fmt.Errorf("open audit file: %w", err)
		}
		d.Add("file", audit.NewWriterSink(f), audit.SinkOptions{Queue: 4096, Overflow: audit.OverflowDrop})
	}
	return d, nil
}

// policySummary is the secret-free view served at /-/policy.
func policySummary(m *reload.Manager, d *audit.Dispatcher) any {
	l := m.Current()
	if l == nil {
		return map[string]any{"loaded": false}
	}
	reloads, failures, lastErr := m.Stats()
	services := make([]map[string]any, 0, len(l.Policy.Services))
	for _, s := range l.Policy.Services {
		hosts := make([]string, len(s.Hosts))
		for i, h := range s.Hosts {
			hosts[i] = h.String()
		}
		services = append(services, map[string]any{
			"name": s.Name, "hosts": hosts, "extractor": s.Extractor, "block_mode": s.BlockMode, "rules": s.RuleIDs(),
		})
	}
	rules := make([]map[string]any, 0, len(l.Policy.Rules))
	for _, r := range l.Policy.Rules {
		rules = append(rules, map[string]any{"id": r.ID, "severity": r.Severity, "action": r.Action})
	}
	return map[string]any{
		"loaded":      true,
		"version":     l.Hash,
		"loaded_at":   l.LoadedAt,
		"source":      l.Source,
		"path":        m.Path(),
		"monitor":     l.Policy.Monitor,
		"services":    services,
		"rules":       rules,
		"reloads":     reloads,
		"failures":    failures,
		"last_error":  lastErr,
		"audit_sinks": d.Stats(),
	}
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
