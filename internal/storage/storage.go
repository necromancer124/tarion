package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Contact struct {
	Name string `json:"name"`
	Addr string `json:"addr,omitempty"`
	// ID optionally pins the contact's peer ID up front (verified out of band),
	// instead of trusting whatever key answers first.
	ID string `json:"id,omitempty"`
}

type Config struct {
	ServerAddr string `json:"server_addr"`
	// ServerID pins the directory server's key after the first connection.
	ServerID string `json:"server_id,omitempty"`
	Username string `json:"username"`
	// Password is only needed until this device's key is linked to the
	// account; the client removes it from the file after that login.
	Password string `json:"password,omitempty"`
	// Invite is a one-time code for invite-only servers; removed after use.
	Invite string `json:"invite,omitempty"`
	// Port is the one UDP port used for chat and for talking to the server.
	Port int `json:"port"`
	// ControlPort is the local TCP port of the background process (default:
	// Port+10000, or Port-10000 when that would exceed 65535).
	ControlPort int `json:"control_port,omitempty"`
	// Accept is "anyone" (default) or "contacts": only keys in contacts or
	// already pinned (people you messaged or who messaged you before).
	Accept   string    `json:"accept,omitempty"`
	Contacts []Contact `json:"contacts"`
}

// DefaultPort is the client's UDP port. It differs from the server's default
// (63425) so a client and tariond can run on the same machine.
const DefaultPort = 63426

func DefaultConfig() *Config {
	return &Config{Port: DefaultPort, Contacts: []Contact{}}
}

// GetBaseConfigDir returns Tarion's data folder. TARION_HOME overrides it,
// which also lets two instances with separate identities run on one machine.
func GetBaseConfigDir() string {
	if dir := os.Getenv("TARION_HOME"); dir != "" {
		return dir
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "tarion")
	}
	return filepath.Join(configDir, "tarion")
}

func GetConfigPath() string { return filepath.Join(GetBaseConfigDir(), "config.json") }

func GetIdentityPath() string { return filepath.Join(GetBaseConfigDir(), "identity.key") }

func GetControlTokenPath() string { return filepath.Join(GetBaseConfigDir(), "control.token") }

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(GetConfigPath())
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	return cfg, json.Unmarshal(data, cfg)
}

func LoadOrCreateConfig() (*Config, error) {
	cfg, err := LoadConfig()
	if err == nil {
		return cfg, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	cfg = DefaultConfig()
	return cfg, SaveConfig(cfg)
}

var configMu sync.Mutex

// UpdateConfig re-reads the config file, applies fn, and saves it, so a
// background goroutine can change one field without clobbering the rest.
func UpdateConfig(fn func(*Config)) error {
	configMu.Lock()
	defer configMu.Unlock()
	cfg, err := LoadOrCreateConfig()
	if err != nil {
		return err
	}
	fn(cfg)
	return SaveConfig(cfg)
}

func SaveConfig(cfg *Config) error {
	path := GetConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func GetHistoryDir() string { return filepath.Join(GetBaseConfigDir(), "history") }

var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func safeName(name string) string {
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(name)
	name = strings.TrimRight(name, " .")
	if name == "" || windowsReservedNames[strings.ToUpper(name)] {
		name = "_" + name
	}
	return name
}

func GetHistoryPath(username string) string {
	return filepath.Join(GetHistoryDir(), safeName(username)+".txt")
}

// Older versions wrote the peer's address as the first line of each history
// file; it is skipped when reading. Addresses now live in peers.json.
const peerAddrPrefix = "# tarion-peer-addr: "

func AppendHistory(username, message string) error {
	path := GetHistoryPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(message + "\n")
	return err
}

func ReadHistory(username string) ([]string, error) {
	f, err := os.Open(GetHistoryPath(username))
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, peerAddrPrefix) {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func ListHistoryContacts() ([]Contact, error) {
	dir := GetHistoryDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	contacts := make([]Contact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".txt") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if name != "" {
			contacts = append(contacts, Contact{Name: name})
		}
	}
	return contacts, nil
}

func GetLastModified(username string) time.Time {
	info, err := os.Stat(GetHistoryPath(username))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func DeleteAllHistory() error {
	if err := os.RemoveAll(GetHistoryDir()); err != nil {
		return err
	}
	return os.MkdirAll(GetHistoryDir(), 0700)
}
