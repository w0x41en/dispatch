package storage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestSaveOpenRoundTrip(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	id := uuid.NewString()
	payload := []byte("hello blob world")
	storagePath, n, err := st.Save(id, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("expected size %d, got %d", len(payload), n)
	}
	if storagePath != filepath.Join(id[:2], id+".bin") {
		t.Errorf("unexpected storage path: %s", storagePath)
	}

	rc, _, err := st.Open(storagePath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestSaveRejectsInvalidUUID(t *testing.T) {
	st, _ := New(t.TempDir())
	for _, bad := range []string{"../etc/passwd", "not-a-uuid", "", "abcdef"} {
		if _, _, err := st.Save(bad, bytes.NewReader(nil)); err == nil {
			t.Errorf("expected error for uuid %q", bad)
		}
	}
}

func TestRemoveIdempotent(t *testing.T) {
	st, _ := New(t.TempDir())
	id := uuid.NewString()
	p, _, _ := st.Save(id, bytes.NewReader([]byte("x")))
	if err := st.Remove(p); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := st.Remove(p); err != nil {
		t.Fatalf("remove missing should be idempotent: %v", err)
	}
}

func TestOpenRejectsTraversal(t *testing.T) {
	st, _ := New(t.TempDir())
	// Plant a file outside the root to prove traversal is blocked.
	secret := filepath.Join(st.root, "..", "secret.txt")
	_ = os.WriteFile(secret, []byte("leaked"), 0o644)
	for _, p := range []string{"../secret.txt", "/etc/passwd", ".."} {
		if _, _, err := st.Open(p); err == nil {
			t.Errorf("expected error for path %q", p)
		}
	}
	_ = os.Remove(secret)
}
