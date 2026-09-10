package identity

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// CSVDirectory reads user contact details from a CSV file with the columns
// user, email, manager_email. A header row is optional. The file is
// re-read when it changes, so adding a joiner does not need a restart.
type CSVDirectory struct {
	path string

	mu      sync.RWMutex
	entries map[string]csvEntry
	modTime time.Time
	size    int64
}

type csvEntry struct{ email, manager string }

// NewCSVDirectory loads the file once; later changes are picked up.
func NewCSVDirectory(path string) (*CSVDirectory, error) {
	d := &CSVDirectory{path: path, entries: map[string]csvEntry{}}
	if err := d.reload(); err != nil {
		return nil, err
	}
	return d, nil
}

// Users returns how many entries are loaded.
func (d *CSVDirectory) Users() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

func (d *CSVDirectory) reload() error {
	info, err := os.Stat(d.path)
	if err != nil {
		return fmt.Errorf("read user directory: %w", err)
	}
	d.mu.RLock()
	unchanged := info.ModTime().Equal(d.modTime) && info.Size() == d.size
	d.mu.RUnlock()
	if unchanged {
		return nil
	}
	f, err := os.Open(d.path)
	if err != nil {
		return fmt.Errorf("read user directory: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.Comment = '#'
	rows, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("parse user directory: %w", err)
	}
	entries := map[string]csvEntry{}
	for i, row := range rows {
		if len(row) < 2 {
			continue
		}
		user := normalizeUser(row[0])
		if user == "" || (i == 0 && strings.EqualFold(user, "user")) {
			continue // header row
		}
		e := csvEntry{email: strings.TrimSpace(row[1])}
		if len(row) > 2 {
			e.manager = strings.TrimSpace(row[2])
		}
		entries[user] = e
	}
	d.mu.Lock()
	d.entries, d.modTime, d.size = entries, info.ModTime(), info.Size()
	d.mu.Unlock()
	return nil
}

// Lookup implements Directory.
func (d *CSVDirectory) Lookup(_ context.Context, user string) (string, string, error) {
	_ = d.reload()
	d.mu.RLock()
	e, ok := d.entries[normalizeUser(user)]
	d.mu.RUnlock()
	if !ok {
		return "", "", fmt.Errorf("user %q is not in the directory", user)
	}
	return e.email, e.manager, nil
}

// StaticDirectory is a fixed map, used by tests and small deployments.
type StaticDirectory map[string][2]string

// Lookup implements Directory.
func (s StaticDirectory) Lookup(_ context.Context, user string) (string, string, error) {
	e, ok := s[normalizeUser(user)]
	if !ok {
		return "", "", fmt.Errorf("user %q is not in the directory", user)
	}
	return e[0], e[1], nil
}
