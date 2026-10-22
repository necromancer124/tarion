package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// OutboxItem is a message that could not be delivered yet. The client keeps
// retrying it, with its original ID so the receiver never sees it twice.
type OutboxItem struct {
	ID        string    `json:"id"`
	To        string    `json:"to"`
	Addr      string    `json:"addr,omitempty"`
	Body      string    `json:"body"`
	Created   time.Time `json:"created"`
	Attempts  int       `json:"attempts"`
	NextTry   time.Time `json:"next_try"`
	LastError string    `json:"last_error,omitempty"`
}

// MaxOutbox caps how many undelivered messages are kept.
const MaxOutbox = 500

var (
	outboxMu      sync.Mutex
	ErrOutboxFull = errors.New("outbox full")
)

func GetOutboxPath() string { return filepath.Join(GetBaseConfigDir(), "outbox.json") }

func loadOutbox() ([]OutboxItem, error) {
	data, err := os.ReadFile(GetOutboxPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []OutboxItem
	return items, json.Unmarshal(data, &items)
}

func saveOutbox(items []OutboxItem) error {
	if items == nil {
		items = []OutboxItem{}
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(GetOutboxPath(), data)
}

// Outbox returns the queued messages, oldest first.
func Outbox() ([]OutboxItem, error) {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	items, err := loadOutbox()
	sort.SliceStable(items, func(i, j int) bool { return items[i].Created.Before(items[j].Created) })
	return items, err
}

// Enqueue adds a message to the outbox.
func Enqueue(item OutboxItem) error {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	items, err := loadOutbox()
	if err != nil {
		return err
	}
	if len(items) >= MaxOutbox {
		return ErrOutboxFull
	}
	return saveOutbox(append(items, item))
}

// UpdateOutbox replaces the item with the same ID.
func UpdateOutbox(item OutboxItem) error {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	items, err := loadOutbox()
	if err != nil {
		return err
	}
	for i := range items {
		if items[i].ID == item.ID {
			items[i] = item
			return saveOutbox(items)
		}
	}
	return nil
}

// RemoveOutbox deletes the item with this ID.
func RemoveOutbox(id string) error {
	outboxMu.Lock()
	defer outboxMu.Unlock()
	items, err := loadOutbox()
	if err != nil {
		return err
	}
	for i := range items {
		if items[i].ID == id {
			return saveOutbox(append(items[:i], items[i+1:]...))
		}
	}
	return nil
}
