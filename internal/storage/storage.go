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
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
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
