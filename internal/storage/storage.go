package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Contact struct {
	Name string `json:"name"`
	Addr string `json:"addr,omitempty"`
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

func GetBaseConfigDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "tarion")
	}
	return filepath.Join(configDir, "tarion")
}

func GetConfigPath() string { return filepath.Join(GetBaseConfigDir(), "config.json") }

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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func GetHistoryDir() string { return filepath.Join(GetBaseConfigDir(), "history") }

func safeName(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(name)
}

func GetHistoryPath(username string) string {
	return filepath.Join(GetHistoryDir(), safeName(username)+".txt")
}

const peerAddrPrefix = "# tarion-peer-addr: "

func peerAddrForFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, peerAddrPrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, peerAddrPrefix))
		}
	}
	return ""
}

func ensurePeerAddrHeader(username, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	path := GetHistoryPath(username)
	if data, err := os.ReadFile(path); err == nil {
		if strings.HasPrefix(string(data), peerAddrPrefix) {
			return nil
		}
		return os.WriteFile(path, append([]byte(peerAddrPrefix+addr+"\n"), data...), 0644)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(peerAddrPrefix+addr+"\n"), 0644)
}

func ResolvePeerHistoryName(username, addr string) (string, error) {
	username = strings.TrimSpace(username)
	addr = strings.TrimSpace(addr)
	if username == "" {
		username = addr
	}
	if username == "" {
		username = "unknown-peer"
	}
	if addr == "" {
		return username, nil
	}

	basePath := GetHistoryPath(username)
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return username, ensurePeerAddrHeader(username, addr)
	} else if err != nil {
		return "", err
	}
	if existing := peerAddrForFile(basePath); existing == "" || existing == addr {
		if existing == "" {
			return username, ensurePeerAddrHeader(username, addr)
		}
		return username, nil
	}

	variant := fmt.Sprintf("%s_%s", username, safeName(addr))
	variantPath := GetHistoryPath(variant)
	if _, err := os.Stat(variantPath); os.IsNotExist(err) {
		return variant, ensurePeerAddrHeader(variant, addr)
	} else if err != nil {
		return "", err
	}
	return variant, nil
}

func AppendHistory(username, message string) error {
	path := GetHistoryPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	return os.MkdirAll(GetHistoryDir(), 0755)
}
