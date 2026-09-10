//go:build windows

package main

import "context"

// onHangup is a no-op on Windows, which has no SIGHUP. Use the file watcher
// or POST /-/reload on the admin listener instead.
func onHangup(context.Context, func()) {}
