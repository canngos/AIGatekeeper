package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/canngos/aigatekeeper/internal/admin"
	"github.com/canngos/aigatekeeper/internal/alert"
	"github.com/canngos/aigatekeeper/internal/audit"
	"github.com/canngos/aigatekeeper/internal/ca"
	"github.com/canngos/aigatekeeper/internal/config"
	"github.com/canngos/aigatekeeper/internal/identity"
	"github.com/canngos/aigatekeeper/internal/metrics"
	"github.com/canngos/aigatekeeper/internal/parser"
	"github.com/canngos/aigatekeeper/internal/policy"
	"github.com/canngos/aigatekeeper/internal/proxy"
	"github.com/canngos/aigatekeeper/internal/reload"
	"github.com/canngos/aigatekeeper/web"
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

	dispatcher, history, err := buildAudit(bootCfg, stdout, logger)
	if err != nil {
		return err
	}
	var alerts *alert.Engine
	defer func() {
		if err := dispatcher.Close(5 * time.Second); err != nil {
			logger.Warn("audit shutdown", "error", err)
		}
	}()
	auditLog := metrics.Counting(dispatcher)

	ids, err := buildIdentity(bootCfg, logger)
	if err != nil {
		return err
	}
	defer ids.Close()

	if engine, err := buildAlerts(bootCfg, history, ids.Directory, logger); err != nil {
		return err
	} else if engine != nil {
		alerts = engine
		// The engine is an audit sink, so alerts are raised from the same
		// stream the console reads and never block the proxy.
		dispatcher.Add("alerts", engine, audit.SinkOptions{Queue: 2048, Overflow: audit.OverflowDrop})
	}

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
		Identify:        identifyFunc(ids),
		AuthRealm:       cfg.Identity.ProxyAuth.Realm,
		Audit:           auditLog,
		Logger:          logger,
	})

	var reverses []*proxy.ReverseListener
	for _, rc := range cfg.Listen.Reverse {
		rl, err := proxy.NewReverseListener(rc.Name, rc.Upstream, inspect, logger, auditLog)
		if err != nil {
			return err
		}
		rl.Identify = identifyFunc(ids)
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
	listeners := map[string]string{"forward": cfg.Listen.Forward, "admin": cfg.Listen.Admin}
	for _, rc := range cfg.Listen.Reverse {
		listeners["reverse/"+rc.Name] = rc.Listen
	}
	adminOpts := admin.Options{
		CACertPEM:  rootCA.CertPEM(),
		Version:    version,
		Ready:      func() bool { return store.Load() != nil },
		Reload:     reloadFn,
		PolicyInfo: func() any { return policySummary(manager, dispatcher) },
		Auth: admin.AuthConfig{
			PasswordHash:   cfg.Admin.Auth.PasswordHash,
			Token:          cfg.Admin.Auth.Token,
			SessionTTL:     cfg.Admin.Auth.SessionTTL.Std(),
			LoginBurst:     cfg.Admin.Auth.LoginBurst,
			LoginPerMinute: cfg.Admin.Auth.LoginPerMinute,
		},
		Manager:     manager,
		History:     history,
		Alerts:      alerts,
		Identity:    identityStatus(ids),
		Events:      dispatcher,
		Listeners:   listeners,
		CORSOrigins: cfg.Admin.CORSOrigins,
		TLSCert:     cfg.ResolvePath(cfg.Admin.TLSCert),
		TLSKey:      cfg.ResolvePath(cfg.Admin.TLSKey),
		Logger:      logger,
	}
	if cfg.Admin.UI {
		adminOpts.UI = web.FS()
		adminOpts.UIBuilt = web.Built()
	}
	adminSrv := admin.New(adminOpts)
	if !cfg.Admin.Auth.Configured() && cfg.Listen.Admin != "" {
		logger.Warn("admin API and UI are disabled until a credential is set; run `aigatekeeper admin hash-password`")
	}

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

// buildAudit wires the audit sinks. The stdout sink uses the blocking
// overflow policy so the primary trail is never silently truncated;
// optional sinks drop instead, and the drop counters are exposed at
// /api/v1/status.
func buildAudit(cfg *config.Config, stdout io.Writer, logger *slog.Logger) (*audit.Dispatcher, *audit.SQLiteStore, error) {
	d := audit.NewDispatcher()
	if cfg.Audit.Stdout {
		d.Add("stdout", audit.NewJSONLogger(stdout), audit.SinkOptions{Queue: 1024, Overflow: audit.OverflowBlock})
	}
	if cfg.Audit.File != "" {
		f, err := os.OpenFile(cfg.ResolvePath(cfg.Audit.File), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("open audit file: %w", err)
		}
		d.Add("file", audit.NewWriterSink(f), audit.SinkOptions{Queue: 4096, Overflow: audit.OverflowDrop})
	}
	var history *audit.SQLiteStore
	if cfg.Audit.SQLite.Enabled {
		sq := cfg.Audit.SQLite
		store, err := audit.OpenSQLite(cfg.ResolvePath(sq.Path), audit.SQLiteOptions{
			BatchSize:     sq.BatchSize,
			FlushInterval: sq.BatchInterval.Std(),
			MaxAge:        sq.MaxAge.Std(),
			MaxRows:       sq.MaxRows,
			SweepInterval: sq.SweepInterval.Std(),
		})
		if err != nil {
			return nil, nil, err
		}
		history = store
		d.Add("sqlite", store, audit.SinkOptions{Queue: sq.Queue, Overflow: audit.OverflowDrop})
		logger.Info("audit history store open", "path", cfg.ResolvePath(sq.Path), "max_age", sq.MaxAge, "max_rows", sq.MaxRows)
	}
	return d, history, nil
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

// identifyFunc adapts the identity stack for the proxy, or returns nil when
// identity is switched off so the proxy skips the step entirely.
func identifyFunc(ids *identityStack) func(*http.Request, net.IP) (identity.Identity, bool) {
	if ids == nil || len(ids.Chain) == 0 {
		return nil
	}
	return ids.Identify
}

// identityStatus is the secret-free summary shown on the Status page.
func identityStatus(ids *identityStack) map[string]any {
	out := map[string]any{"proxy_auth": false, "reverse_dns": false, "directory": false}
	if ids == nil {
		return out
	}
	out["directory"] = ids.Directory != nil
	for _, r := range ids.Chain {
		switch r.Name() {
		case "proxy_auth":
			out["proxy_auth"] = true
		case "reverse_dns":
			out["reverse_dns"] = true
		}
	}
	if ids.ProxyAuth != nil {
		out["proxy_auth_stats"] = ids.ProxyAuth.Stats()
	}
	return out
}
