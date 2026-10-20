package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	ServerAddr string    `json:"server_addr"`
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	Port       int       `json:"port"`
	Contacts   []Contact `json:"contacts"`
}

func DefaultConfig() *Config {
	return &Config{Port: 63425, Contacts: []Contact{}}
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
