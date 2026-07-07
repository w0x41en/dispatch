// Package store persists file metadata in SQLite (pure-Go driver, no CGO).
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"

	"dispatch/internal/model"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned by Get / SetExpiry when no row matches the UUID.
var ErrNotFound = errors.New("file not found")

// Store wraps a SQLite database holding file metadata.
type Store struct {
	db *sql.DB
}

// Open creates/opens the database at path, applies pragmas and schema, and
// returns a ready Store.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single connection serializes writes, avoiding "database is locked" at
	// this scale. busy_timeout covers the rare contention window.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	st := &Store{db: db}
	if err := st.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return st, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// migrate adds columns introduced after v1. Idempotent: it inspects
// PRAGMA table_info and only ALTERs when a column is missing, so re-opening an
// already-migrated DB is a no-op. The project ships no separate migration tool
// (see database-guidelines.md); this extends the "apply on every open" pattern
// to column additions.
func (s *Store) migrate() error {
	rows, err := s.db.Query(`PRAGMA table_info(files)`)
	if err != nil {
		return fmt.Errorf("table_info: %w", err)
	}
	defer rows.Close()
	hasMax := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		if name == "max_downloads" {
			hasMax = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("table_info rows: %w", err)
	}
	if !hasMax {
		if _, err := s.db.Exec(`ALTER TABLE files ADD COLUMN max_downloads INTEGER`); err != nil {
			return fmt.Errorf("add max_downloads: %w", err)
		}
	}
	return nil
}

// Create inserts a new file record.
func (s *Store) Create(ctx context.Context, f model.File) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO files (uuid, original_filename, content_type, size, storage_path, download_count, created_at, expires_at, max_downloads)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		f.UUID, f.OriginalFilename, f.ContentType, f.Size, f.StoragePath, f.CreatedAt, toNullInt64(f.ExpiresAt), toNullInt64(f.MaxDownloads),
	)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	return nil
}

// Get returns the file record for uuid, or ErrNotFound.
func (s *Store) Get(ctx context.Context, uuid string) (model.File, error) {
	row := s.db.QueryRowContext(ctx, selectCols+` FROM files WHERE uuid = ?`, uuid)
	return scanFile(row)
}

// List returns all file records, newest first.
func (s *Store) List(ctx context.Context) ([]model.File, error) {
	rows, err := s.db.QueryContext(ctx, selectCols+` FROM files ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	return collect(rows)
}

// Delete removes a file record. It is idempotent: a missing row is not an error.
func (s *Store) Delete(ctx context.Context, uuid string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM files WHERE uuid = ?`, uuid); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// IncrementDownloadCount bumps download_count for uuid. A missing row is not an
// error (the file may have been reaped mid-flight).
func (s *Store) IncrementDownloadCount(ctx context.Context, uuid string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE files SET download_count = download_count + 1 WHERE uuid = ?`, uuid)
	return err
}

// ConsumeDownloadSlot atomically increments download_count for uuid, but only
// if it is currently below maxDownloads. Returns ok=true if a slot was
// consumed (the caller should serve the file); ok=false if the limit is
// reached (the caller should 404). A missing row also yields ok=false with no
// error — the caller has already established the row exists, and a mid-flight
// reap is treated as "no slot". The single-statement conditional UPDATE is
// serialized by SetMaxOpenConns(1), so concurrent callers cannot both pass.
func (s *Store) ConsumeDownloadSlot(ctx context.Context, uuid string, maxDownloads int64) (ok bool, err error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE files
		SET download_count = download_count + 1
		WHERE uuid = ? AND download_count < ?`, uuid, maxDownloads)
	if err != nil {
		return false, fmt.Errorf("consume download slot: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SetMaxDownloads sets or clears (nil = unlimited) the download cap for uuid.
// Returns ErrNotFound if the UUID does not exist. Lowering the cap below the
// current download_count immediately invalidates the link (the next download
// 404s because ConsumeDownloadSlot's WHERE clause no longer matches).
func (s *Store) SetMaxDownloads(ctx context.Context, uuid string, max *int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE files SET max_downloads = ? WHERE uuid = ?`, toNullInt64(max), uuid)
	if err != nil {
		return fmt.Errorf("set max downloads: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetExpiry sets or clears (nil) the expiry for uuid. Returns ErrNotFound if
// the UUID does not exist.
func (s *Store) SetExpiry(ctx context.Context, uuid string, expiresAt *int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE files SET expires_at = ? WHERE uuid = ?`, toNullInt64(expiresAt), uuid)
	if err != nil {
		return fmt.Errorf("set expiry: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListExpired returns records whose expiry has passed (expires_at <= now).
func (s *Store) ListExpired(ctx context.Context, now int64) ([]model.File, error) {
	rows, err := s.db.QueryContext(ctx, selectCols+` FROM files WHERE expires_at IS NOT NULL AND expires_at <= ?`, now)
	if err != nil {
		return nil, fmt.Errorf("list expired: %w", err)
	}
	return collect(rows)
}

const selectCols = `SELECT uuid, original_filename, content_type, size, storage_path, download_count, created_at, expires_at, max_downloads`

type scanner interface {
	Scan(dest ...any) error
}

func scanFile(sc scanner) (model.File, error) {
	var f model.File
	var exp, mx sql.NullInt64
	if err := sc.Scan(&f.UUID, &f.OriginalFilename, &f.ContentType, &f.Size, &f.StoragePath, &f.DownloadCount, &f.CreatedAt, &exp, &mx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return f, ErrNotFound
		}
		return f, err
	}
	if exp.Valid {
		v := exp.Int64
		f.ExpiresAt = &v
	}
	if mx.Valid {
		v := mx.Int64
		f.MaxDownloads = &v
	}
	return f, nil
}

func collect(rows *sql.Rows) ([]model.File, error) {
	defer rows.Close()
	var out []model.File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func toNullInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
