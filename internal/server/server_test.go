package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dispatch/internal/config"
	"dispatch/internal/storage"
	"dispatch/internal/store"

	"golang.org/x/crypto/bcrypt"
)

const testSecret = "test-secret-0123456789abcdef"

type testEnv struct {
	srv     *httptest.Server
	store   *store.Store
	storage *storage.Storage
	secret  string
}

func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sg, err := storage.New(filepath.Join(dir, "files"))
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw123"), bcrypt.MinCost)
	cfg := config.Config{
		ListenAddr:     "127.0.0.1:0",
		AdminURLSecret: testSecret,
		PasswordHash:   hash,
		SessionSecret:  []byte("0123456789abcdef0123456789abcdef"),
		StorageDir:     filepath.Join(dir, "files"),
		DBPath:         filepath.Join(dir, "test.db"),
		MaxUploadBytes: 1 << 20,
		SessionMaxAge:  time.Hour,
		ReaperInterval: 0,
	}
	srv, err := New(cfg, st, sg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return testEnv{srv: ts, store: st, storage: sg, secret: testSecret}
}

func loginClient(t *testing.T, base, secret, pw string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.PostForm(base+"/"+secret+"/login", url.Values{"password": {pw}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	return c
}

func uploadFile(t *testing.T, c *http.Client, base, secret, filename string, content []byte, expiresIn string) map[string]any {
	return uploadFileMax(t, c, base, secret, filename, content, expiresIn, "")
}

func uploadFileMax(t *testing.T, c *http.Client, base, secret, filename string, content []byte, expiresIn, maxDownloads string) map[string]any {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	fw.Write(content)
	if expiresIn != "" {
		_ = mw.WriteField("expires_in", expiresIn)
	}
	if maxDownloads != "" {
		_ = mw.WriteField("max_downloads", maxDownloads)
	}
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, base+"/"+secret+"/api/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", base)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload status %d: %s", resp.StatusCode, b)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestHealthzAndRoot(t *testing.T) {
	env := newTestEnv(t)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/healthz", http.StatusOK},
		{"/", http.StatusNotFound},
		{"/not-a-uuid", http.StatusNotFound},
		{"/00000000-0000-0000-0000-000000000000", http.StatusNotFound},
	} {
		resp, err := http.Get(env.srv.URL + tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if resp.StatusCode != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.path, tc.want, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestLoginFlow(t *testing.T) {
	env := newTestEnv(t)
	// Wrong password → 303 to ?err=1, no cookie.
	c := loginClient(t, env.srv.URL, env.secret, "wrong")
	resp, err := c.PostForm(env.srv.URL+"/"+env.secret+"/login", url.Values{"password": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("wrong pw: expected 303, got %d", resp.StatusCode)
	}
	// Correct password → 302 to dashboard with cookie.
	resp, err = c.PostForm(env.srv.URL+"/"+env.secret+"/login", url.Values{"password": {"pw123"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("correct pw: expected 302, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Location"), "/dashboard") {
		t.Errorf("expected redirect to dashboard, got %s", resp.Header.Get("Location"))
	}
	if resp.Cookies() == nil {
		t.Error("expected session cookie to be set")
	}
}

func TestAuthGate(t *testing.T) {
	env := newTestEnv(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Dashboard without cookie → 302 to login.
	resp, err := noRedirect.Get(env.srv.URL + "/" + env.secret + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("dashboard no cookie: expected 302, got %d", resp.StatusCode)
	}
	// API without cookie → 401.
	resp, err = http.Get(env.srv.URL + "/" + env.secret + "/api/files")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("api no cookie: expected 401, got %d", resp.StatusCode)
	}
}

func TestCSRFRejected(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	// Upload without Origin header → 400.
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, _ := mw.CreateFormFile("file", "x.txt")
	fw.Write([]byte("x"))
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, env.srv.URL+"/"+env.secret+"/api/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// No Origin set.
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 without Origin, got %d", resp.StatusCode)
	}
}

func TestUploadDownload(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")

	payload := []byte("hello blob world")
	up := uploadFile(t, c, env.srv.URL, env.secret, "hello.txt", payload, "")
	uuid, _ := up["uuid"].(string)
	if uuid == "" {
		t.Fatal("expected uuid in response")
	}

	resp, err := http.Get(env.srv.URL + "/" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download: expected 200, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, payload) {
		t.Errorf("download bytes mismatch: got %q want %q", got, payload)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, `filename="hello.txt"`) {
		t.Errorf("expected Content-Disposition with hello.txt, got %q", cd)
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Error("expected Accept-Ranges: bytes")
	}
}

func TestRangeRequest(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "range.bin", []byte("0123456789abcdef"), "")
	uuid, _ := up["uuid"].(string)

	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/"+uuid, nil)
	req.Header.Set("Range", "bytes=0-4")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("expected 206, got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "01234" {
		t.Errorf("expected '01234', got %q", got)
	}
}

func TestDownloadExpired(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "exp.txt", []byte("data"), "")
	uuid, _ := up["uuid"].(string)

	// Set expiry in the past directly, then download must 404.
	past := time.Now().Unix() - 100
	if err := env.store.SetExpiry(context.Background(), uuid, &past); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(env.srv.URL + "/" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expired download: expected 404, got %d", resp.StatusCode)
	}
}

func TestSetExpiryViaAPI(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "api-exp.txt", []byte("data"), "")
	uuid, _ := up["uuid"].(string)

	// Set 1h expiry.
	resp, err := postJSON(c, env.srv.URL+"/"+env.secret+"/api/files/"+uuid+"/expiry", `{"expires_in":3600}`, env.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set expiry: expected 200, got %d", resp.StatusCode)
	}
	var r map[string]any
	json.NewDecoder(resp.Body).Decode(&r)
	resp.Body.Close()
	if r["expires_at"] == nil {
		t.Error("expected non-null expires_at after setting 3600")
	}

	// Download still works (not expired).
	dl, _ := http.Get(env.srv.URL + "/" + uuid)
	dl.Body.Close()
	if dl.StatusCode != http.StatusOK {
		t.Errorf("expected 200 before expiry, got %d", dl.StatusCode)
	}

	// Clear expiry (Never).
	resp2, _ := postJSON(c, env.srv.URL+"/"+env.secret+"/api/files/"+uuid+"/expiry", `{"expires_in":0}`, env.srv.URL)
	var r2 map[string]any
	json.NewDecoder(resp2.Body).Decode(&r2)
	resp2.Body.Close()
	if r2["expires_at"] != nil {
		t.Error("expected null expires_at after clearing")
	}
}

func TestUploadWithExpiryParam(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "param.txt", []byte("data"), "3600")
	if up["expires_at"] == nil {
		t.Error("expected non-null expires_at when uploading with expires_in=3600")
	}
	// And a never upload.
	up2 := uploadFile(t, c, env.srv.URL, env.secret, "never.txt", []byte("data"), "")
	if up2["expires_at"] != nil {
		t.Error("expected null expires_at for default upload")
	}
}

func TestDelete(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "del.txt", []byte("data"), "")
	uuid, _ := up["uuid"].(string)

	resp, _ := postJSON(c, env.srv.URL+"/"+env.secret+"/api/files/"+uuid+"/delete", "", env.srv.URL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}
	dl, _ := http.Get(env.srv.URL + "/" + uuid)
	dl.Body.Close()
	if dl.StatusCode != http.StatusNotFound {
		t.Errorf("after delete: expected 404, got %d", dl.StatusCode)
	}
}

func TestReaperPurgesExpired(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "reap.txt", []byte("data"), "")
	uuid, _ := up["uuid"].(string)

	f, err := env.store.Get(context.Background(), uuid)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Unix() - 100
	_ = env.store.SetExpiry(context.Background(), uuid, &past)

	// Run one reap cycle synchronously.
	srv := newServerFromEnv(t, env)
	srv.reapExpired(context.Background())

	if _, err := env.store.Get(context.Background(), uuid); err == nil {
		t.Error("expected row to be deleted by reaper")
	}
	// Blob file should be gone too.
	if _, _, err := env.storage.Open(f.StoragePath); err == nil {
		t.Error("expected blob to be removed by reaper")
	}
}

func TestNonASCIIFilename(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "café.txt", []byte("x"), "")
	uuid, _ := up["uuid"].(string)

	resp, err := http.Get(env.srv.URL + "/" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "filename*=UTF-8''") {
		t.Errorf("expected RFC 5987 filename* for non-ASCII, got %q", cd)
	}
	if !strings.Contains(cd, "caf%C3%A9.txt") {
		t.Errorf("expected percent-encoded café, got %q", cd)
	}
}

func TestApiList(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	uploadFile(t, c, env.srv.URL, env.secret, "list.txt", []byte("data"), "")
	uploadFile(t, c, env.srv.URL, env.secret, "list2.txt", []byte("data"), "")

	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/"+env.secret+"/api/files", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r struct {
		Files []map[string]any `json:"files"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	if len(r.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(r.Files))
	}
}

func TestBurnAfterDownload(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	payload := []byte("burn-after-download")
	up := uploadFileMax(t, c, env.srv.URL, env.secret, "burn.txt", payload, "", "3")
	uuid, _ := up["uuid"].(string)
	if up["max_downloads"] != float64(3) {
		t.Fatalf("expected max_downloads=3 in response, got %v", up["max_downloads"])
	}

	// First 3 downloads succeed and return the body.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(env.srv.URL + "/" + uuid)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download %d: expected 200, got %d", i, resp.StatusCode)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("download %d: bytes mismatch", i)
		}
	}
	// 4th download → 404 with a body identical to an unknown UUID's 404
	// (no information leak — exhausted links are indistinguishable from unknown).
	resp, err := http.Get(env.srv.URL + "/" + uuid)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	unknown, _ := http.Get(env.srv.URL + "/00000000-0000-0000-0000-000000000000")
	unknownBody, _ := io.ReadAll(unknown.Body)
	unknown.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("exhausted: expected 404, got %d", resp.StatusCode)
	}
	if !bytes.Equal(body, unknownBody) {
		t.Errorf("exhausted 404 body should match unknown-UUID 404 body: got %q want %q", body, unknownBody)
	}
	// download_count stopped at the cap.
	f, _ := env.store.Get(context.Background(), uuid)
	if f.DownloadCount != 3 {
		t.Errorf("expected download_count=3, got %d", f.DownloadCount)
	}
}

func TestDownloadUnlimitedCount(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "unlim.txt", []byte("x"), "")
	uuid, _ := up["uuid"].(string)
	if up["max_downloads"] != nil {
		t.Fatalf("expected nil max_downloads for unlimited upload, got %v", up["max_downloads"])
	}
	for i := 0; i < 5; i++ {
		resp, err := http.Get(env.srv.URL + "/" + uuid)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("download %d: expected 200, got %d", i, resp.StatusCode)
		}
	}
	// Unlimited path counts completed downloads after serving.
	f, _ := env.store.Get(context.Background(), uuid)
	if f.DownloadCount != 5 {
		t.Errorf("expected download_count=5, got %d", f.DownloadCount)
	}
}

func TestDownloadExpiredBeforeLimit(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFileMax(t, c, env.srv.URL, env.secret, "both.txt", []byte("x"), "", "5")
	uuid, _ := up["uuid"].(string)

	// Time-expire it; the time gate must fire before a slot is consumed.
	past := time.Now().Unix() - 100
	if err := env.store.SetExpiry(context.Background(), uuid, &past); err != nil {
		t.Fatal(err)
	}
	resp, _ := http.Get(env.srv.URL + "/" + uuid)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 from time expiry, got %d", resp.StatusCode)
	}
	// Slot not consumed: download_count stays 0.
	f, _ := env.store.Get(context.Background(), uuid)
	if f.DownloadCount != 0 {
		t.Errorf("expected download_count=0 (time gate before slot), got %d", f.DownloadCount)
	}
}

func TestSetMaxDownloadsViaAPI(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFile(t, c, env.srv.URL, env.secret, "cap.txt", []byte("x"), "")
	uuid, _ := up["uuid"].(string)

	// One completed download (unlimited path) → count=1.
	resp, _ := http.Get(env.srv.URL + "/" + uuid)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first download: expected 200, got %d", resp.StatusCode)
	}

	// Cap at the current count → next download 404s.
	r, err := postJSON(c, env.srv.URL+"/"+env.secret+"/api/files/"+uuid+"/max-downloads", `{"max_downloads":1}`, env.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("set max: expected 200, got %d", r.StatusCode)
	}
	var got map[string]any
	json.NewDecoder(r.Body).Decode(&got)
	r.Body.Close()
	if got["max_downloads"] != float64(1) {
		t.Errorf("expected max_downloads=1 in response, got %v", got["max_downloads"])
	}
	dl, _ := http.Get(env.srv.URL + "/" + uuid)
	dl.Body.Close()
	if dl.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after capping at count, got %d", dl.StatusCode)
	}

	// Clear the cap → downloads work again.
	r2, _ := postJSON(c, env.srv.URL+"/"+env.secret+"/api/files/"+uuid+"/max-downloads", `{"max_downloads":0}`, env.srv.URL)
	r2.Body.Close()
	dl2, _ := http.Get(env.srv.URL + "/" + uuid)
	dl2.Body.Close()
	if dl2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after clearing cap, got %d", dl2.StatusCode)
	}
}

func TestConcurrentDownloadLimit(t *testing.T) {
	env := newTestEnv(t)
	c := loginClient(t, env.srv.URL, env.secret, "pw123")
	up := uploadFileMax(t, c, env.srv.URL, env.secret, "conc.txt", []byte("concurrent"), "", "1")
	uuid, _ := up["uuid"].(string)

	const N = 10
	var wg sync.WaitGroup
	var successes, notFounds int64
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			resp, err := http.Get(env.srv.URL + "/" + uuid)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			switch resp.StatusCode {
			case http.StatusOK:
				atomic.AddInt64(&successes, 1)
			case http.StatusNotFound:
				atomic.AddInt64(&notFounds, 1)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d", successes)
	}
	if notFounds != N-1 {
		t.Errorf("expected %d 404s, got %d", N-1, notFounds)
	}
	f, _ := env.store.Get(context.Background(), uuid)
	if f.DownloadCount != 1 {
		t.Errorf("expected download_count=1, got %d", f.DownloadCount)
	}
}

// TestMigratedOldDBServes seeds a v1 DB (no max_downloads column) with a real
// blob, re-opens it through store.Open (migration), and asserts the file still
// serves and is unlimited.
func TestMigratedOldDBServes(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "migrated.db")
	filesDir := filepath.Join(dir, "files")

	id := "11111111-2222-3333-4444-555555555555"
	sg, err := storage.New(filesDir)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	storagePath, _, err := sg.Save(id, strings.NewReader("legacy"))
	if err != nil {
		t.Fatalf("save blob: %v", err)
	}

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
		t.Fatalf("old schema: %v", err)
	}
	_, err = db.Exec(`INSERT INTO files (uuid, original_filename, content_type, size, storage_path, download_count, created_at, expires_at)
		VALUES (?, 'legacy.bin', 'text/plain', 6, ?, 0, 1000, NULL)`, id, storagePath)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer st.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("pw123"), bcrypt.MinCost)
	cfg := config.Config{
		AdminURLSecret: testSecret,
		PasswordHash:   hash,
		SessionSecret:  []byte("0123456789abcdef0123456789abcdef"),
		StorageDir:     filesDir,
		DBPath:         dbPath,
		MaxUploadBytes: 1 << 20,
		SessionMaxAge:  time.Hour,
	}
	srv, err := New(cfg, st, sg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/" + id)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected migrated file to serve 200, got %d", resp.StatusCode)
	}
	if string(got) != "legacy" {
		t.Errorf("expected 'legacy', got %q", got)
	}
	f, _ := st.Get(context.Background(), id)
	if f.MaxDownloads != nil {
		t.Errorf("expected migrated row unlimited, got %+v", f.MaxDownloads)
	}
}

// --- helpers ---

func postJSON(c *http.Client, urlStr, body, origin string) (*http.Response, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(http.MethodPost, urlStr, r)
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return c.Do(req)
}

func newServerFromEnv(t *testing.T, env testEnv) *Server {
	t.Helper()
	cfg := config.Config{
		AdminURLSecret: env.secret,
		PasswordHash:   []byte("x"),
		SessionSecret:  []byte("0123456789abcdef0123456789abcdef"),
		StorageDir:     "/tmp",
		DBPath:         "/tmp/x.db",
		MaxUploadBytes: 1 << 20,
		SessionMaxAge:  time.Hour,
	}
	srv, err := New(cfg, env.store, env.storage, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return srv
}
