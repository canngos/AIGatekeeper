// Package ca generates and manages the AIGatekeeper root certificate
// authority and the per-host leaf certificates presented to intercepted
// clients. Everything is pure Go (crypto/x509); no openssl is required.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultCommonName is the subject CN used by `ca init` unless overridden.
	DefaultCommonName = "AIGatekeeper Root CA"
	// DefaultOrganization is the subject O used by `ca init` unless overridden.
	DefaultOrganization = "AIGatekeeper"
	// DefaultValidity is how long a freshly generated root CA is valid.
	DefaultValidity = 10 * 365 * 24 * time.Hour
)

// ErrExists is returned by Save when a target file already exists and force is false.
var ErrExists = errors.New("certificate or key file already exists (use --force to overwrite)")

// CA is a loaded or freshly generated root certificate authority.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	certDER []byte
}

// Generate creates a new self-signed ECDSA P-256 root CA.
func Generate(commonName, organization string, validity time.Duration) (*CA, error) {
	if commonName == "" {
		commonName = DefaultCommonName
	}
	if organization == "" {
		organization = DefaultOrganization
	}
	if validity <= 0 {
		validity = DefaultValidity
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{organization}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}
	return &CA{Cert: cert, Key: key, certDER: der}, nil
}

// Load reads a PEM certificate and PEM private key from disk.
func Load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	return Parse(certPEM, keyPEM)
}

// Parse builds a CA from PEM-encoded certificate and private key bytes.
func Parse(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate: no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("CA certificate: certificate is not marked as a CA (BasicConstraints)")
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysMatch(cert, key) {
		return nil, errors.New("CA key does not match CA certificate")
	}
	return &CA{Cert: cert, Key: key, certDER: block.Bytes}, nil
}

// ParseCertificate builds a key-less CA from a PEM certificate, for
// displaying fingerprints and trust instructions without touching the key.
func ParseCertificate(certPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA certificate: no CERTIFICATE PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{Cert: cert, certDER: block.Bytes}, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("CA key: no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("CA key: unsupported key type")
		}
		return s, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC key: %w", err)
		}
		return k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key: %w", err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("CA key: unsupported PEM block %q", block.Type)
	}
}

func publicKeysMatch(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := cert.PublicKey.(equaler)
	if !ok {
		return false
	}
	return pub.Equal(key.Public())
}

// CertPEM returns the PEM-encoded CA certificate (safe to distribute).
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certDER})
}

// KeyPEM returns the PEM-encoded (PKCS#8) private key. Handle with care.
func (c *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// CertDER returns the raw DER certificate bytes.
func (c *CA) CertDER() []byte { return c.certDER }

// Fingerprint returns the SHA-256 fingerprint of the certificate as
// colon-separated uppercase hex, the format most trust-store UIs display.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.certDER)
	var b strings.Builder
	for i, x := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", x)
	}
	return b.String()
}

// Save writes the certificate and key as PEM files. The key file is created
// with mode 0600. Unless force is true, existing files are never overwritten.
func (c *CA) Save(certPath, keyPath string, force bool) error {
	if !force {
		for _, p := range []string{certPath, keyPath} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%w: %s", ErrExists, p)
			}
		}
	}
	for _, p := range []string{certPath, keyPath} {
		if dir := filepath.Dir(p); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create directory %s: %w", dir, err)
			}
		}
	}
	keyPEM, err := c.KeyPEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, c.CertPEM(), 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	// Ensure the serial is positive and non-zero as required by RFC 5280.
	return n.Add(n, big.NewInt(1)), nil
}
