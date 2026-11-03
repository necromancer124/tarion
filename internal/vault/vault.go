// Package vault keeps Tarion's local files unreadable to anyone who copies
// them: the identity key, chat history, contacts and queued messages are
// encrypted with a random data key, and the data key itself is protected by
// Windows (DPAPI, tied to the user's login) or by a passphrase.
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// How the data key is protected.
const (
	Windows    = "windows"    // DPAPI: only this Windows user on this PC can unlock it
	Passphrase = "passphrase" // argon2id from a passphrase typed at start
)

// KeySize is the data key's length.
const KeySize = chacha20poly1305.KeySize

// File is vault.json: the data key, wrapped by its protector.
type File struct {
	V         int    `json:"v"`
	Protector string `json:"protector"`
	Wrapped   []byte `json:"wrapped"`
	// Passphrase only.
	Salt    []byte `json:"salt,omitempty"`
	MemKiB  uint32 `json:"mem_kib,omitempty"`
	Time    uint32 `json:"time,omitempty"`
	Threads uint8  `json:"threads,omitempty"`
}

// ErrWrongPassphrase means the passphrase didn't unlock the vault.
var ErrWrongPassphrase = errors.New("wrong passphrase")

// Load reads vault.json; it returns nil, nil if there is none.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil || f.V != 1 {
		return nil, fmt.Errorf("%s is damaged", path)
	}
	return &f, nil
}

// NewKey makes a random data key.
func NewKey() []byte {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

// Wrap protects key with the given protector and writes vault.json.
func Wrap(path string, key []byte, protector, passphrase string) error {
	f := &File{V: 1, Protector: protector}
	switch protector {
	case Windows:
		w, err := dpapiProtect(key)
		if err != nil {
			return fmt.Errorf("Windows data protection: %w", err)
		}
		f.Wrapped = w
	case Passphrase:
		f.Salt = make([]byte, 16)
		if _, err := rand.Read(f.Salt); err != nil {
			return err
		}
		f.MemKiB, f.Time, f.Threads = 64*1024, 3, 4
		f.Wrapped = Seal(f.kek(passphrase), "vault", key)
	default:
		return fmt.Errorf("unknown protector %q", protector)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Unlock recovers the data key. passphrase is asked only for a passphrase
// vault.
func (f *File) Unlock(passphrase func() (string, error)) ([]byte, error) {
	switch f.Protector {
	case Windows:
		k, err := dpapiUnprotect(f.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("Windows could not unlock your Tarion data (was it copied from another PC or Windows account?): %w", err)
		}
		return k, nil
	case Passphrase:
		p, err := passphrase()
		if err != nil {
			return nil, err
		}
		k, err := Open(f.kek(p), "vault", f.Wrapped)
		if err != nil {
			return nil, ErrWrongPassphrase
		}
		return k, nil
	}
	return nil, fmt.Errorf("unknown protector %q in vault.json", f.Protector)
}

func (f *File) kek(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), f.Salt, f.Time, f.MemKiB, f.Threads, KeySize)
}

// Describe says how the data is protected, for status output.
func Describe(protector string) string {
	switch protector {
	case Windows:
		return "encrypted, unlocked by your Windows login (DPAPI)"
	case Passphrase:
		return "encrypted, unlocked by your passphrase"
	}
	return "not encrypted (protected by file permissions only)"
}

// magic starts every sealed file.
var magic = []byte("TARION-SEALED-1\n")

// Seal encrypts plain with key. kind (the file's role, e.g. "history") is
// authenticated, so one sealed file can't be passed off as another.
func Seal(key []byte, kind string, plain []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err) // only for a wrong key size, a programming error
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return append(append([]byte{}, magic...), aead.Seal(nonce, nonce, plain, []byte(kind))...)
}

// IsSealed reports whether data came from Seal.
func IsSealed(data []byte) bool {
	return len(data) >= len(magic) && string(data[:len(magic)]) == string(magic)
}

// ErrDamaged means sealed data failed to decrypt: a wrong key, a damaged
// file, or a file swapped for another kind.
var ErrDamaged = errors.New("encrypted data could not be opened (damaged, or not yours)")

// Open decrypts data from Seal.
func Open(key []byte, kind string, data []byte) ([]byte, error) {
	if !IsSealed(data) {
		return nil, ErrDamaged
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	data = data[len(magic):]
	if len(data) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDamaged
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(kind))
	if err != nil {
		return nil, ErrDamaged
	}
	return plain, nil
}

// linePrefix marks an encrypted line in an append-only file.
const linePrefix = "~sealed1:"

// SealLine encrypts one line of an append-only file (history, dropped.log).
func SealLine(key []byte, kind, line string) string {
	return linePrefix + base64.RawStdEncoding.EncodeToString(Seal(key, kind, []byte(line))[len(magic):])
}

// IsSealedLine reports whether a line came from SealLine.
func IsSealedLine(line string) bool { return strings.HasPrefix(line, linePrefix) }

// OpenLine decrypts a line from SealLine.
func OpenLine(key []byte, kind, line string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, linePrefix))
	if err != nil {
		return "", ErrDamaged
	}
	plain, err := Open(key, kind, append(append([]byte{}, magic...), raw...))
	return string(plain), err
}
