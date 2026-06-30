package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	ServerAddr string `json:"server_addr"`
	Username   string `json:"username"`
	Port       int    `json:"port"`
}

func GetBaseConfigDir() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "tarion")
	}
	return filepath.Join(configDir, "tarion")
}

func GetConfigPath() string {
	return filepath.Join(GetBaseConfigDir(), "config.json")
}

func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(GetConfigPath())
	if err != nil {
		return nil, err
	}
	var cfg Config
	return &cfg, json.Unmarshal(data, &cfg)
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
	return os.WriteFile(path, data, 0644)
}

func GetHistoryDir() string {
	return filepath.Join(GetBaseConfigDir(), "history")
}

func GetHistoryPath(username string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_").Replace(username)
	return filepath.Join(GetHistoryDir(), safe+".txt")
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
	err := os.RemoveAll(GetHistoryDir())
	if err != nil {
		return err
	}
	return os.MkdirAll(GetHistoryDir(), 0755)
}
