package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSaveLoadRoundTrip(t *testing.T) {
	c, err := Generate("Test Root", "TestOrg", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Cert.IsCA {
		t.Fatal("generated certificate is not a CA")
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "sub", "ca.crt")
	keyPath := filepath.Join(dir, "sub", "ca.key")
	if err := c.Save(certPath, keyPath, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(certPath, keyPath, false); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists on second save, got %v", err)
	}
	if err := c.Save(certPath, keyPath, true); err != nil {
		t.Fatalf("forced save failed: %v", err)
	}
	loaded, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint() != c.Fingerprint() {
		t.Fatalf("fingerprint mismatch after reload: %s vs %s", loaded.Fingerprint(), c.Fingerprint())
	}
	if len(loaded.Fingerprint()) != 95 { // 32 bytes as "AA:BB:..." = 32*2 + 31 colons
		t.Fatalf("unexpected fingerprint format: %s", loaded.Fingerprint())
	}
}

func TestParseRejectsMismatchedKey(t *testing.T) {
	a, _ := Generate("A", "", time.Hour)
	b, _ := Generate("B", "", time.Hour)
	bKey, _ := b.KeyPEM()
	if _, err := Parse(a.CertPEM(), bKey); err == nil {
		t.Fatal("expected mismatched key to be rejected")
	}
}

func TestSignerIssuesVerifiableLeaves(t *testing.T) {
	c, err := Generate("", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.Cert)

	for _, host := range []string{"api.openai.com", "API.GitHubCopilot.com.", "127.0.0.1", "[::1]"} {
		cert, err := s.Sign(host)
		if err != nil {
			t.Fatalf("sign %s: %v", host, err)
		}
		if len(cert.Certificate) != 2 {
			t.Fatalf("expected leaf + CA chain, got %d certs", len(cert.Certificate))
		}
		opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		norm := NormalizeHost(host)
		if ip := net.ParseIP(norm); ip != nil {
			if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(ip) {
				t.Fatalf("leaf for %s lacks IP SAN", host)
			}
		} else {
			opts.DNSName = norm
		}
		if _, err := cert.Leaf.Verify(opts); err != nil {
			t.Fatalf("leaf for %s does not verify: %v", host, err)
		}
		if cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) > 398*24*time.Hour {
			t.Fatalf("leaf for %s exceeds 398-day validity", host)
		}
	}
}

func TestCacheReusesAndEvicts(t *testing.T) {
	c, _ := Generate("", "", 0)
	s, _ := NewSigner(c, time.Hour)
	cache := NewCache(s, 2)

	first, err := cache.Get("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := cache.Get("A.example.com")
	if first != again {
		t.Fatal("expected cached certificate to be reused for the same host")
	}
	cache.Get("b.example.com")
	cache.Get("c.example.com") // LRU order is now [c, b]; a is evicted
	if cache.Len() != 2 {
		t.Fatalf("expected cache size 2, got %d", cache.Len())
	}
	hits, misses := cache.Stats()
	if hits != 1 || misses != 3 {
		t.Fatalf("unexpected stats hits=%d misses=%d", hits, misses)
	}
}

func TestCacheRefreshesNearExpiry(t *testing.T) {
	c, _ := Generate("", "", 0)
	s, _ := NewSigner(c, time.Hour)
	cache := NewCache(s, 10)
	base := time.Now()
	cache.now = func() time.Time { return base }
	s.now = func() time.Time { return base }

	first, _ := cache.Get("x.example.com")
	cache.now = func() time.Time { return base.Add(59 * time.Minute) } // past 80% of 1h
	second, _ := cache.Get("x.example.com")
	if first == second {
		t.Fatal("expected leaf to be reissued after 80% of its TTL")
	}
}

func TestGetCertificateFallsBackToConnectHost(t *testing.T) {
	c, _ := Generate("", "", 0)
	s, _ := NewSigner(c, time.Hour)
	cache := NewCache(s, 10)
	get := cache.GetCertificate("fallback.example.com")
	cert, err := get(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.DNSNames[0] != "fallback.example.com" {
		t.Fatalf("expected fallback host SAN, got %v", cert.Leaf.DNSNames)
	}
	cert, _ = get(&tls.ClientHelloInfo{ServerName: "sni.example.com"})
	if cert.Leaf.DNSNames[0] != "sni.example.com" {
		t.Fatalf("expected SNI host SAN, got %v", cert.Leaf.DNSNames)
	}
}
