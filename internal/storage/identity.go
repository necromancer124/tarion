package storage

import (
	"errors"
	"fmt"
	"os"

	"github.com/necromancer124/tarion/internal/identity"
)

// LoadOrCreateIdentity reads this device's identity key (decrypting it when
// it is sealed), creating one if there is none yet.
func LoadOrCreateIdentity() (*identity.Identity, error) {
	path := GetIdentityPath()
	data, err := readSealed(path, kindIdentity)
	if err == nil {
		id, err := identity.FromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", path, err)
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	pemData, err := id.PEM()
	if err != nil {
		return nil, err
	}
	return id, writeSealed(path, kindIdentity, pemData)
}
