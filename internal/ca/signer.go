package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultLeafTTL keeps leaf certificates under the 398-day limit enforced by
// Apple and Chrome trust policies.
const DefaultLeafTTL = 397 * 24 * time.Hour

// Signer issues per-host leaf certificates signed by the CA. All leaves share
// one ECDSA key, which is standard practice for interception proxies and keeps
// issuance to a single signature.
type Signer struct {
	ca      *CA
	leafKey *ecdsa.PrivateKey
	ttl     time.Duration
	now     func() time.Time
}

// NewSigner creates a Signer for the given CA. ttl <= 0 selects DefaultLeafTTL.
func NewSigner(c *CA, ttl time.Duration) (*Signer, error) {
	if ttl <= 0 {
		ttl = DefaultLeafTTL
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	return &Signer{ca: c, leafKey: key, ttl: ttl, now: time.Now}, nil
}

// TTL returns the validity period applied to issued leaves.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Sign issues a certificate for host, which may be a DNS name or an IP
// address. The returned tls.Certificate carries the full chain (leaf + CA).
func (s *Signer) Sign(host string) (*tls.Certificate, error) {
	host = NormalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("sign: empty host")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: s.ca.Cert.Subject.Organization},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(s.ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca.Cert, &s.leafKey.PublicKey, s.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf for %s: %w", host, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, s.ca.certDER},
		PrivateKey:  s.leafKey,
		Leaf:        leaf,
	}, nil
}

// NormalizeHost lowercases a host name and strips a trailing dot and any
// surrounding IPv6 brackets so cache keys and SANs are canonical.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}
