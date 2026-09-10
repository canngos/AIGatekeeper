package reload

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchOptions tune the file watcher.
type WatchOptions struct {
	// Debounce coalesces the burst of events editors emit per save.
	Debounce time.Duration
	// PollInterval enables mtime/size polling in addition to fsnotify. It is
	// the only mechanism that works on some bind mounts (Docker Desktop).
	PollInterval time.Duration
	// DisableFsnotify forces polling only (tests, exotic filesystems).
	DisableFsnotify bool
	Logger          *slog.Logger
}

// Watch blocks until ctx is done, reloading the manager's file whenever it
// changes. The parent directory is watched rather than the file itself
// because editors and the admin Apply replace the file via rename, which
// would silently break a watch on the file's inode.
func Watch(ctx context.Context, m *Manager, opts WatchOptions) error {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 300 * time.Millisecond
	}
	absPath, err := filepath.Abs(m.Path())
	if err != nil {
		return err
	}
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	var events <-chan fsnotify.Event
	var errs <-chan error
	if !opts.DisableFsnotify {
		w, err := fsnotify.NewWatcher()
		if err != nil {
			opts.Logger.Warn("fsnotify unavailable; falling back to polling", "error", err)
			if opts.PollInterval <= 0 {
				opts.PollInterval = 5 * time.Second
			}
		} else {
			defer w.Close()
			if err := w.Add(dir); err != nil {
				opts.Logger.Warn("cannot watch config directory; falling back to polling", "dir", dir, "error", err)
				if opts.PollInterval <= 0 {
					opts.PollInterval = 5 * time.Second
				}
			} else {
				events, errs = w.Events, w.Errors
				opts.Logger.Info("watching configuration", "path", absPath, "debounce", opts.Debounce)
			}
		}
	} else if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}

	var pollC <-chan time.Time
	var lastMod time.Time
	var lastSize int64
	if opts.PollInterval > 0 {
		if info, err := os.Stat(absPath); err == nil {
			lastMod, lastSize = info.ModTime(), info.Size()
		}
		ticker := time.NewTicker(opts.PollInterval)
		defer ticker.Stop()
		pollC = ticker.C
		opts.Logger.Info("polling configuration", "path", absPath, "interval", opts.PollInterval)
	}

	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	pending := false
	reload := func(source string) {
		if _, changed, err := m.ReloadFromDisk(ctx, source); err == nil && changed {
			if info, err := os.Stat(absPath); err == nil {
				lastMod, lastSize = info.ModTime(), info.Size()
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
				continue
			}
			if !pending {
				pending = true
			}
			debounce.Reset(opts.Debounce)
		case err, ok := <-errs:
			if ok && err != nil {
				opts.Logger.Warn("config watcher error", "error", err)
			}
		case <-debounce.C:
			pending = false
			if _, err := os.Stat(absPath); err != nil {
				// Mid-rename or deleted: wait for the next event.
				continue
			}
			reload("file")
		case <-pollC:
			info, err := os.Stat(absPath)
			if err != nil {
				continue
			}
			if !info.ModTime().Equal(lastMod) || info.Size() != lastSize {
				lastMod, lastSize = info.ModTime(), info.Size()
				reload("poll")
			}
		}
	}
}
