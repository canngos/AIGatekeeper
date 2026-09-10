// Package identity works out who sent an intercepted request, so findings
// can be attributed to a person rather than an address that changes with
// every DHCP lease.
//
// Resolution is a chain: proxy authentication names the user outright, and
// a reverse DNS lookup always fills in the workstation. Nothing here is
// required; with it all switched off events simply carry a client address,
// as they did before.
package identity

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Identity is what is known about the sender of a request.
type Identity struct {
	// User is the account name, empty when nothing authenticated the caller.
	User string `json:"user,omitempty"`
	// Device is the workstation name, usually from reverse DNS.
	Device string `json:"device,omitempty"`
	// Source names the resolver that supplied User, for the audit trail.
	Source string `json:"source,omitempty"`
	// Email and Manager come from the directory, for notifications.
	Email   string `json:"email,omitempty"`
	Manager string `json:"manager,omitempty"`
}

// Known reports whether anything identified the caller.
func (i Identity) Known() bool { return i.User != "" }

// Label returns the best available name for grouping and display.
func (i Identity) Label(clientIP string) string {
	switch {
	case i.User != "":
		return i.User
	case i.Device != "":
		return i.Device
	default:
		return clientIP
	}
}

// Resolver contributes what it knows about a request.
type Resolver interface {
	Name() string
	// Resolve returns an identity and whether it found anything. It must
	// not block for long; use a cache and a timeout.
	Resolve(ctx context.Context, r *http.Request, clientIP net.IP) (Identity, bool)
}

// Chain asks each resolver in order. The first to name a user wins; the
// device is taken from whichever resolver supplies one.
type Chain []Resolver

// Resolve implements Resolver.
func (c Chain) Resolve(ctx context.Context, r *http.Request, clientIP net.IP) (Identity, bool) {
	var out Identity
	for _, res := range c {
		id, ok := res.Resolve(ctx, r, clientIP)
		if !ok {
			continue
		}
		if out.User == "" && id.User != "" {
			out.User, out.Source, out.Email, out.Manager = id.User, res.Name(), id.Email, id.Manager
		}
		if out.Device == "" && id.Device != "" {
			out.Device = id.Device
		}
	}
	return out, out.User != "" || out.Device != ""
}

// Name implements Resolver.
func (c Chain) Name() string { return "chain" }

type ctxKey struct{}

// WithIdentity stores id in ctx.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored in ctx, if any.
func FromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(ctxKey{}).(Identity)
	return id
}

// Directory maps a user name to contact details for notifications.
type Directory interface {
	Lookup(ctx context.Context, user string) (email, manager string, err error)
}

// normalizeUser lowercases and strips a domain prefix or suffix so
// CORP\alice, alice@corp.example and alice group together.
func normalizeUser(user string) string {
	user = strings.TrimSpace(user)
	if i := strings.LastIndexAny(user, `\/`); i >= 0 {
		user = user[i+1:]
	}
	if i := strings.IndexByte(user, '@'); i > 0 {
		user = user[:i]
	}
	return strings.ToLower(user)
}
