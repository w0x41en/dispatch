// Package storage manages file blobs on the local filesystem. Blobs are keyed
// by UUID and sharded into a 2-char hex subdirectory. Storage paths are always
// derived from the UUID — never from user input — so path traversal is impossible.
package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Storage is the blob store rooted at a single directory.
type Storage struct {
	root string
	tmp  string // root/.tmp, used for staging uploads
}

// New creates the root and temp directories if needed and returns a Storage.
func New(root string) (*Storage, error) {
	tmp := filepath.Join(root, ".tmp")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, fmt.Errorf("create storage dirs: %w", err)
	}
	return &Storage{root: root, tmp: tmp}, nil
}

// Save streams src into a temp file and atomically renames it into place.
// It returns the relative storage path (e.g. "ab/<uuid>.bin") and the byte count.
func (s *Storage) Save(uuid string, src io.Reader) (string, int64, error) {
	if !uuidRe.MatchString(uuid) {
		return "", 0, fmt.Errorf("invalid uuid")
	}
	storagePath := filepath.Join(uuid[:2], uuid+".bin")
	tmpPath := filepath.Join(s.tmp, uuid+".part")
	finalPath := filepath.Join(s.root, storagePath)

	f, err := os.Create(tmpPath)
	if err != nil {
		return "", 0, fmt.Errorf("create temp: %w", err)
	}
	n, err := io.Copy(f, src)
	cerr := f.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", 0, fmt.Errorf("write temp: %w", err)
	}
	if cerr != nil {
		_ = os.Remove(tmpPath)
		return "", 0, fmt.Errorf("close temp: %w", cerr)
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return "", 0, fmt.Errorf("mkdir shard: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", 0, fmt.Errorf("rename: %w", err)
	}
	return storagePath, n, nil
}

// Open returns a reader and the blob's modification time. The reader is a
// ReadSeekCloser so http.ServeContent can serve Range requests.
func (s *Storage) Open(storagePath string) (io.ReadSeekCloser, time.Time, error) {
	if !safeRelPath(storagePath) {
		return nil, time.Time{}, fmt.Errorf("invalid storage path")
	}
	f, err := os.Open(filepath.Join(s.root, storagePath))
	if err != nil {
		return nil, time.Time{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, time.Time{}, err
	}
	return f, fi.ModTime(), nil
}

// Remove deletes a blob. A missing blob is not an error (idempotent).
func (s *Storage) Remove(storagePath string) error {
	if !safeRelPath(storagePath) {
		return fmt.Errorf("invalid storage path")
	}
	err := os.Remove(filepath.Join(s.root, storagePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// safeRelPath rejects absolute paths and any path containing a ".." component,
// so a stored path can never escape the storage root.
func safeRelPath(p string) bool {
	if p == "" || filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	if clean == "." || clean == ".." {
		return false
	}
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part == ".." {
			return false
		}
	}
	return true
}
