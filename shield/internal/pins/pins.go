// Package pins manages persistent tool hash registry, drift diffing, and re-approvals.
package pins

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrPinNotFound = errors.New("pin not found")
)

type PinRecord struct {
	Key       string    `json:"key"`
	Server    string    `json:"server"`
	Tool      string    `json:"tool"`
	Digest    string    `json:"digest"`
	UpdatedAt time.Time `json:"updated_at"`
}

type FileStore struct {
	path string
	mu   sync.RWMutex
	m    map[string]PinRecord
}

func NewFileStore(filePath string) (*FileStore, error) {
	fs := &FileStore{
		path: filePath,
		m:    make(map[string]PinRecord),
	}
	if err := fs.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return fs, nil
}

func (s *FileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var records []PinRecord
	if err := json.Unmarshal(b, &records); err != nil {
		return err
	}
	s.m = make(map[string]PinRecord, len(records))
	for _, r := range records {
		s.m[r.Key] = r
	}
	return nil
}

func (s *FileStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	records := make([]PinRecord, 0, len(s.m))
	for _, r := range s.m {
		records = append(records, r)
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0600)
}

func (s *FileStore) Get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.m[key]
	if !ok {
		return "", false
	}
	return r.Digest, true
}

func (s *FileStore) Set(key, digest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := strings.Split(key, "|")
	server, tool := "", ""
	if len(parts) >= 3 {
		server, tool = parts[1], parts[2]
	} else if len(parts) == 2 {
		server = parts[1]
	}
	s.m[key] = PinRecord{
		Key:       key,
		Server:    server,
		Tool:      tool,
		Digest:    digest,
		UpdatedAt: time.Now(),
	}
	_ = s.saveLocked()
}

func (s *FileStore) List() []PinRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PinRecord, 0, len(s.m))
	for _, r := range s.m {
		out = append(out, r)
	}
	return out
}

func (s *FileStore) Approve(server, tool, newDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("tool|%s|%s", server, tool)
	s.m[key] = PinRecord{
		Key:       key,
		Server:    server,
		Tool:      tool,
		Digest:    newDigest,
		UpdatedAt: time.Now(),
	}
	return s.saveLocked()
}

func Diff(server, tool, oldDigest, newDigest string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "=== Tool Pin Diff: %s/%s ===\n", server, tool)
	fmt.Fprintf(&sb, "- Previous Pinned Digest: %s\n", oldDigest)
	fmt.Fprintf(&sb, "+ Incoming Drift Digest:  %s\n", newDigest)
	if oldDigest == newDigest {
		sb.WriteString("Status: Matches existing pin (No drift)\n")
	} else {
		sb.WriteString("Status: DRIFT DETECTED (Quarantined until approved)\n")
	}
	return sb.String()
}
