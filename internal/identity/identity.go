// Package identity gives every Tarion install a long-lived Ed25519 key.
// The key is the user's real identity: it signs the TLS handshake, so a peer
// can only claim a peer ID if it owns the matching private key.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Identity is a local key pair plus the TLS certificate built from it.
type Identity struct {
	Key  ed25519.PrivateKey
	Cert tls.Certificate
	ID   string
}

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// PeerID derives the stable peer ID for a public key: base32(sha256(key))[:32].
func PeerID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return strings.ToLower(idEncoding.EncodeToString(sum[:20]))
}

// Short returns a short prefix of a peer ID for display.
func Short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// Fingerprint formats a peer ID in groups of four so two people can compare it.
func Fingerprint(id string) string {
	var groups []string
	for i := 0; i < len(id); i += 4 {
		end := i + 4
		if end > len(id) {
			end = len(id)
		}
		groups = append(groups, id[i:end])
	}
	return strings.Join(groups, " ")
}

// PeerIDFromCerts extracts the peer ID from the leaf certificate a peer
// presented. TLS 1.3 already proved the peer owns the matching private key.
func PeerIDFromCerts(certs []*x509.Certificate) (string, error) {
	if len(certs) == 0 {
		return "", errors.New("peer presented no certificate")
	}
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("peer certificate is not an Ed25519 Tarion identity")
	}
	return PeerID(pub), nil
}

// Generate creates a fresh in-memory identity.
func Generate() (*Identity, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return fromKey(key)
}

// LoadOrCreate reads the identity key at path, creating it (0600) if missing.
func LoadOrCreate(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("identity file %s is not PEM", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse identity %s: %w", path, err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identity %s is not an Ed25519 key", path)
		}
		return fromKey(key)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	id, err := Generate()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, err
	}
	return id, nil
}

func fromKey(key ed25519.PrivateKey) (*Identity, error) {
	pub := key.Public().(ed25519.PublicKey)
	id := PeerID(pub)

	// The certificate is only a container for the public key; peers pin the
	// key, not the certificate, so a long validity is fine.
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	tmpl.Subject.CommonName = "tarion-" + id
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, key)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Key:  key,
		Cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		ID:   id,
	}, nil
}
