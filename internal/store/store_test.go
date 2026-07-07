package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"dispatch/internal/model"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mkFile(uuid string, exp *int64) model.File {
	return model.File{
		UUID:             uuid,
		OriginalFilename: uuid + ".bin",
		ContentType:      "application/octet-stream",
		Size:             10,
		StoragePath:      "ab/" + uuid + ".bin",
		CreatedAt:        1000,
		ExpiresAt:        exp,
	}
}

// mkFileMax is mkFile with a download cap. nil max = unlimited.
func mkFileMax(uuid string, exp *int64, max *int64) model.File {
	f := mkFile(uuid, exp)
	f.MaxDownloads = max
	return f
}

func TestCreateAndGet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	exp := int64(2000)
	if err := st.Create(ctx, mkFile("u1", &exp)); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.Get(ctx, "u1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.OriginalFilename != "u1.bin" || got.Size != 10 || got.DownloadCount != 0 {
		t.Errorf("unexpected file: %+v", got)
	}
	if got.ExpiresAt == nil || *got.ExpiresAt != 2000 {
		t.Errorf("expected expires_at=2000, got %+v", got.ExpiresAt)
	}
}

func TestGetNotFound(t *testing.T) {
	st := newTestStore(t)
	_, err := st.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListOrder(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	a := mkFile("a", nil)
	a.CreatedAt = 100
	b := mkFile("b", nil)
	b.CreatedAt = 300
	c := mkFile("c", nil)
	c.CreatedAt = 200
	for _, f := range []model.File{a, b, c} {
		if err := st.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	out, err := st.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 3 || out[0].UUID != "b" || out[1].UUID != "c" || out[2].UUID != "a" {
		t.Errorf("unexpected order: %v", []string{out[0].UUID, out[1].UUID, out[2].UUID})
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, mkFile("x", nil)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Delete(ctx, "x"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := st.Delete(ctx, "x"); err != nil {
		t.Fatalf("delete missing should be idempotent: %v", err)
	}
}

func TestIncrementDownloadCount(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, mkFile("c", nil)); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := st.IncrementDownloadCount(ctx, "c"); err != nil {
			t.Fatalf("incr: %v", err)
		}
	}
	got, _ := st.Get(ctx, "c")
	if got.DownloadCount != 3 {
		t.Errorf("expected 3, got %d", got.DownloadCount)
	}
}

func TestSetExpirySetAndClear(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, mkFile("e", nil)); err != nil {
		t.Fatalf("create: %v", err)
	}
	exp := int64(5000)
	if err := st.SetExpiry(ctx, "e", &exp); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	got, _ := st.Get(ctx, "e")
	if got.ExpiresAt == nil || *got.ExpiresAt != 5000 {
		t.Errorf("expected 5000, got %+v", got.ExpiresAt)
	}
	if err := st.SetExpiry(ctx, "e", nil); err != nil {
		t.Fatalf("clear expiry: %v", err)
	}
	got, _ = st.Get(ctx, "e")
	if got.ExpiresAt != nil {
		t.Errorf("expected nil after clear, got %+v", got.ExpiresAt)
	}
}

func TestSetExpiryNotFound(t *testing.T) {
	st := newTestStore(t)
	exp := int64(5000)
	if err := st.SetExpiry(context.Background(), "nope", &exp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListExpired(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	past := int64(100)
	future := int64(9000)
	if err := st.Create(ctx, mkFile("expired", &past)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Create(ctx, mkFile("future", &future)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Create(ctx, mkFile("never", nil)); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.ListExpired(ctx, 200)
	if err != nil {
		t.Fatalf("list expired: %v", err)
	}
	if len(got) != 1 || got[0].UUID != "expired" {
		t.Errorf("expected only [expired], got %+v", got)
	}
}

func TestCreateAndGetMaxDownloads(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	max := int64(5)
	if err := st.Create(ctx, mkFileMax("m1", nil, &max)); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.Get(ctx, "m1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MaxDownloads == nil || *got.MaxDownloads != 5 {
		t.Errorf("expected max_downloads=5, got %+v", got.MaxDownloads)
	}
	// Unlimited round-trips as nil.
	if err := st.Create(ctx, mkFileMax("m2", nil, nil)); err != nil {
		t.Fatalf("create m2: %v", err)
	}
	got2, _ := st.Get(ctx, "m2")
	if got2.MaxDownloads != nil {
		t.Errorf("expected nil max_downloads, got %+v", got2.MaxDownloads)
	}
}

func TestConsumeDownloadSlot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	max := int64(2)
	if err := st.Create(ctx, mkFileMax("c", nil, &max)); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Two slots are consumable; the third is rejected.
	for i := 0; i < 2; i++ {
		ok, err := st.ConsumeDownloadSlot(ctx, "c", max)
		if err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("consume %d: expected ok", i)
		}
	}
	ok, err := st.ConsumeDownloadSlot(ctx, "c", max)
	if err != nil {
		t.Fatalf("consume over: %v", err)
	}
	if ok {
		t.Fatal("expected !ok when limit reached")
	}
	got, _ := st.Get(ctx, "c")
	if got.DownloadCount != 2 {
		t.Errorf("expected download_count=2, got %d", got.DownloadCount)
	}
}

func TestSetMaxDownloadsSetClearNotFound(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, mkFile("s", nil)); err != nil {
		t.Fatalf("create: %v", err)
	}
	max := int64(3)
	if err := st.SetMaxDownloads(ctx, "s", &max); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _ := st.Get(ctx, "s")
	if got.MaxDownloads == nil || *got.MaxDownloads != 3 {
		t.Errorf("expected 3, got %+v", got.MaxDownloads)
	}
	if err := st.SetMaxDownloads(ctx, "s", nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, _ = st.Get(ctx, "s")
	if got.MaxDownloads != nil {
		t.Errorf("expected nil after clear, got %+v", got.MaxDownloads)
	}
	if err := st.SetMaxDownloads(ctx, "nope", &max); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestMigrationAddsColumn seeds a v1 DB (no max_downloads column), re-opens it
// through store.Open, and asserts the column is added, pre-existing rows stay
// unlimited, and a second open is a no-op.
func TestMigrationAddsColumn(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "old.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE files (
		uuid TEXT PRIMARY KEY, original_filename TEXT NOT NULL,
		content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
		size INTEGER NOT NULL, storage_path TEXT NOT NULL,
		download_count INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL, expires_at INTEGER)`)
	if err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	_, err = db.Exec(`INSERT INTO files (uuid, original_filename, content_type, size, storage_path, download_count, created_at, expires_at)
		VALUES ('old', 'old.bin', 'application/octet-stream', 10, 'ab/old.bin', 0, 1000, NULL)`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer st.Close()

	got, err := st.Get(context.Background(), "old")
	if err != nil {
		t.Fatalf("get old: %v", err)
	}
	if got.MaxDownloads != nil {
		t.Errorf("expected pre-existing row unlimited (nil), got %+v", got.MaxDownloads)
	}

	// Re-open is a no-op (idempotent migration).
	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer st2.Close()
	got2, _ := st2.Get(context.Background(), "old")
	if got2.MaxDownloads != nil {
		t.Errorf("expected nil after re-open, got %+v", got2.MaxDownloads)
	}
}
