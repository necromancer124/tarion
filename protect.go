package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"unicode/utf8"

	"github.com/necromancer124/tarion/internal/storage"
	"github.com/necromancer124/tarion/internal/vault"
)

// dataKeyEnv carries the unlocked data key from `tarion background
// --detach` to its child, which has no terminal to ask for a passphrase.
// The child removes it from its environment right away.
const dataKeyEnv = "TARION_DATA_KEY"

// noAutoProtectEnv turns off encrypting a new install automatically.
const noAutoProtectEnv = "TARION_NO_AUTO_PROTECT"

const minPassphrase = 8

// unlockData unlocks the encrypted local files for this process. On
// Windows, data that isn't protected yet is encrypted automatically with
// the user's login (DPAPI), so nothing changes for the user. Files still
// plain from an older version are encrypted on the way.
func unlockData() error {
	if hexKey := os.Getenv(dataKeyEnv); hexKey != "" {
		_ = os.Unsetenv(dataKeyEnv)
		key, err := hex.DecodeString(hexKey)
		if err != nil || len(key) != vault.KeySize {
			return errors.New("the background process got a bad data key")
		}
		storage.SetDataKey(key)
		return nil
	}
	vf, err := vault.Load(storage.GetVaultPath())
	if err != nil {
		return err
	}
	if vf == nil {
		if !vault.WindowsAvailable || os.Getenv(noAutoProtectEnv) != "" {
			return nil
		}
		return turnOnProtection(vault.Windows, "")
	}
	key, err := vf.Unlock(func() (string, error) {
		return readSecret("Passphrase to unlock your Tarion data: ")
	})
	if err != nil {
		return err
	}
	storage.SetDataKey(key)
	if storage.NeedsSealing() {
		return storage.Reseal(key)
	}
	return nil
}

// turnOnProtection creates a data key, protects it, and encrypts every
// file with it.
func turnOnProtection(protector, passphrase string) error {
	key := vault.NewKey()
	if err := vault.Wrap(storage.GetVaultPath(), key, protector, passphrase); err != nil {
		return err
	}
	storage.SetDataKey(key)
	if err := storage.Reseal(nil); err != nil {
		return fmt.Errorf("encrypting your files: %w", err)
	}
	return nil
}

// passDataKey hands the unlocked key to a detached child through its
// environment (see dataKeyEnv); the returned func clears it again here.
func passDataKey(key []byte) func() {
	if key == nil {
		return func() {}
	}
	_ = os.Setenv(dataKeyEnv, hex.EncodeToString(key))
	return func() { _ = os.Unsetenv(dataKeyEnv) }
}

func setProtectUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage:
  tarion protect               show how your local Tarion data is protected
  tarion protect passphrase    encrypt it with a passphrase you type at every start (any OS)
  tarion protect windows       encrypt it with your Windows login (DPAPI; the default on Windows)
  tarion protect off           store it unencrypted again

"Data" is your identity key, chat history, contacts, queued messages and
the dropped-message log. Stop the background process first (tarion stop).
`)
	}
}

func runProtect(args []string) error {
	fs := flag.NewFlagSet("protect", flag.ExitOnError)
	setProtectUsage(fs)
	_ = fs.Parse(args)
	vf, err := vault.Load(storage.GetVaultPath())
	if err != nil {
		return err
	}
	current := ""
	if vf != nil {
		current = vf.Protector
	}
	action := fs.Arg(0)
	if action == "" {
		fmt.Println("Your Tarion data is " + vault.Describe(current) + ".")
		fmt.Println("Folder:", storage.GetBaseConfigDir())
		if current == "" {
			fmt.Println("Encrypt it with: tarion protect passphrase" + map[bool]string{true: "  (or: tarion protect windows)"}[vault.WindowsAvailable])
		}
		return nil
	}
	switch action {
	case "passphrase", "windows", "off":
	default:
		fs.Usage()
		return fmt.Errorf("unknown protect option %q", action)
	}
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	if backgroundRunning(cfg) {
		return errors.New("the background process is running; stop it first (tarion stop), then try again")
	}
	if err := unlockData(); err != nil {
		return err
	}

	switch action {
	case "off":
		if current == "" {
			fmt.Println("Your Tarion data is already unencrypted.")
			return nil
		}
		key := storageKey()
		storage.SetDataKey(nil)
		if err := storage.Reseal(key); err != nil {
			return err
		}
		if err := os.Remove(storage.GetVaultPath()); err != nil {
			return err
		}
		fmt.Println("Done. Your Tarion data is stored unencrypted again (protected by file permissions only).")
		if vault.WindowsAvailable {
			fmt.Printf("It stays that way: Tarion only encrypts new installs automatically. To skip that too, set %s=1.\n", noAutoProtectEnv)
		}
		return nil
	case "windows":
		if !vault.WindowsAvailable {
			return errors.New("Windows protection is only available on Windows; use: tarion protect passphrase")
		}
		return switchProtector(vault.Windows, "")
	default:
		fmt.Printf("Choose a passphrase (%d+ characters). If you forget it, your history and identity key can't be recovered:\n", minPassphrase)
		p1, err := readSecret("New passphrase: ")
		if err != nil {
			return err
		}
		if utf8.RuneCountInString(p1) < minPassphrase {
			return fmt.Errorf("the passphrase must be at least %d characters", minPassphrase)
		}
		p2, err := readSecret("Repeat it: ")
		if err != nil {
			return err
		}
		if p1 != p2 {
			return errors.New("the passphrases don't match; nothing was changed")
		}
		return switchProtector(vault.Passphrase, p1)
	}
}

// storageKey is the currently unlocked data key, or nil.
func storageKey() []byte { return storage.DataKey() }

// switchProtector protects the data key a new way, encrypting the files
// first if they weren't encrypted yet. The data key itself stays the same,
// so nothing has to be re-encrypted when only the protector changes.
func switchProtector(to, passphrase string) error {
	if key := storageKey(); key != nil {
		if err := vault.Wrap(storage.GetVaultPath(), key, to, passphrase); err != nil {
			return err
		}
	} else if err := turnOnProtection(to, passphrase); err != nil {
		return err
	}
	fmt.Println("Done. Your Tarion data is now " + vault.Describe(to) + ".")
	if to == vault.Passphrase {
		fmt.Println("Tarion asks for the passphrase when it starts. `tarion background --detach` asks once, then passes the unlocked key to the background process.")
	}
	return nil
}
