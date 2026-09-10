//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// onHangup calls fn whenever SIGHUP arrives, until ctx is done.
func onHangup(ctx context.Context, fn func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				fn()
			}
		}
	}()
}
