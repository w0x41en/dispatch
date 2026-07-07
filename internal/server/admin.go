package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"dispatch/internal/auth"
	"dispatch/internal/model"
	"dispatch/internal/store"

	"github.com/google/uuid"
)

// loginPage renders the login form at the exact admin index; any other admin
// path that fell through to this subtree handler returns 404.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/"+s.cfg.AdminURLSecret+"/" {
		http.NotFound(w, r)
		return
	}
	if auth.ReadSession(r, s.cfg.SessionSecret, s.cfg.SessionMaxAge) {
		http.Redirect(w, r, "/"+s.cfg.AdminURLSecret+"/dashboard", http.StatusFound)
		return
	}
	s.render(w, "login.html", map[string]any{
		"AdminSecret": s.cfg.AdminURLSecret,
		"Error":       r.URL.Query().Get("err") == "1",
	})
}

// login verifies the password and establishes a session cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap on login body
	ip := clientIP(r)
	if wait := s.throttleWait(ip); wait > 0 {
		time.Sleep(wait) // backoff slows brute force; legit admin waits too
	}
	pw := r.FormValue("password")
	if auth.VerifyPassword(s.cfg.PasswordHash, []byte(pw)) {
		s.recordLoginSuccess(ip)
		tok, err := auth.NewToken(s.cfg.SessionSecret)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		auth.SetSessionCookie(w, r, tok, "/"+s.cfg.AdminURLSecret, s.cfg.SessionMaxAge)
		http.Redirect(w, r, "/"+s.cfg.AdminURLSecret+"/dashboard", http.StatusFound)
		return
	}
	s.recordLoginFail(ip)
	http.Redirect(w, r, "/"+s.cfg.AdminURLSecret+"/?err=1", http.StatusSeeOther)
}

// logout clears the session cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(w, r, "/"+s.cfg.AdminURLSecret)
	http.Redirect(w, r, "/"+s.cfg.AdminURLSecret+"/", http.StatusSeeOther)
}

// dashboard renders the management UI shell; the file list is loaded via JS.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, "dashboard.html", map[string]any{"AdminSecret": s.cfg.AdminURLSecret})
}

// apiList returns all files as JSON.
func (s *Server) apiList(w http.ResponseWriter, r *http.Request) {
	files, err := s.store.List(r.Context())
	if err != nil {
		s.log.Error("list files", "err", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		out = append(out, fileJSON(f))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// apiUpload stores an uploaded file and returns its download URL.
func (s *Server) apiUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if isMaxBytes(err) {
			s.jsonError(w, "file too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var expiresAt *int64
	if ev := r.FormValue("expires_in"); ev != "" {
		n, err := strconv.ParseInt(ev, 10, 64)
		if err != nil || n < 0 {
			s.jsonError(w, "invalid expires_in", http.StatusBadRequest)
			return
		}
		if n > 0 {
			v := time.Now().Unix() + n
			expiresAt = &v
		}
	}

	var maxDownloads *int64
	if mv := r.FormValue("max_downloads"); mv != "" {
		n, err := strconv.ParseInt(mv, 10, 64)
		if err != nil || n < 0 {
			s.jsonError(w, "invalid max_downloads", http.StatusBadRequest)
			return
		}
		if n > 0 { // 0 = unlimited (nil)
			v := n
			maxDownloads = &v
		}
	}

	origName := sanitizeBasename(header.Filename)
	if origName == "" {
		origName = "file"
	}
	// Sniff content type from the first 512 bytes, then prepend them back so
	// the whole stream is saved. Browsers rarely set per-part Content-Type.
	head := make([]byte, 512)
	n, _ := io.ReadFull(file, head)
	contentType := http.DetectContentType(head[:n])
	var src io.Reader = file
	if n > 0 {
		src = io.MultiReader(bytes.NewReader(head[:n]), file)
	}

	id := uuid.NewString()
	storagePath, size, err := s.storage.Save(id, src)
	if err != nil {
		s.log.Error("upload save", "err", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	f := model.File{
		UUID:             id,
		OriginalFilename: origName,
		ContentType:      contentType,
		Size:             size,
		StoragePath:      storagePath,
		CreatedAt:        time.Now().Unix(),
		ExpiresAt:        expiresAt,
		MaxDownloads:     maxDownloads,
	}
	if err := s.store.Create(r.Context(), f); err != nil {
		_ = s.storage.Remove(storagePath) // best-effort cleanup
		s.log.Error("upload create", "err", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, http.StatusOK, fileJSON(f))
}

// apiExpiry sets or clears a file's expiry. The deadline is computed server-side
// (now + expires_in) so clients cannot forge absolute timestamps.
func (s *Server) apiExpiry(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if !uuidRe.MatchString(id) {
		s.jsonError(w, "not found", http.StatusNotFound)
		return
	}
	var body struct {
		ExpiresIn *int64 `json:"expires_in"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.ExpiresIn == nil || *body.ExpiresIn < 0 {
		s.jsonError(w, "invalid expires_in", http.StatusBadRequest)
		return
	}
	var expiresAt *int64
	if *body.ExpiresIn > 0 {
		v := time.Now().Unix() + *body.ExpiresIn
		expiresAt = &v
	}
	if err := s.store.SetExpiry(r.Context(), id, expiresAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.jsonError(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("set expiry", "err", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	var respExpiresAt any
	if expiresAt != nil {
		respExpiresAt = *expiresAt
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expires_at": respExpiresAt})
}

// apiMaxDownloads sets or clears a file's download cap. 0 clears it (unlimited).
// Lowering the cap below the current download_count immediately invalidates the
// link (next download 404s). Mirrors apiExpiry in shape and validation.
func (s *Server) apiMaxDownloads(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if !uuidRe.MatchString(id) {
		s.jsonError(w, "not found", http.StatusNotFound)
		return
	}
	var body struct {
		MaxDownloads *int64 `json:"max_downloads"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.MaxDownloads == nil || *body.MaxDownloads < 0 {
		s.jsonError(w, "invalid max_downloads", http.StatusBadRequest)
		return
	}
	var max *int64
	if *body.MaxDownloads > 0 {
		v := *body.MaxDownloads
		max = &v
	}
	if err := s.store.SetMaxDownloads(r.Context(), id, max); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.jsonError(w, "not found", http.StatusNotFound)
			return
		}
		s.log.Error("set max downloads", "err", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	var respMax any
	if max != nil {
		respMax = *max
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "max_downloads": respMax})
}

// apiDelete removes a file's blob and metadata (idempotent).
func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if !uuidRe.MatchString(id) {
		s.jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if f, err := s.store.Get(r.Context(), id); err == nil {
		_ = s.storage.Remove(f.StoragePath)
	}
	_ = s.store.Delete(r.Context(), id)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// fileJSON maps a model.File to the API response shape.
func fileJSON(f model.File) map[string]any {
	m := map[string]any{
		"uuid":           f.UUID,
		"filename":       f.OriginalFilename,
		"content_type":   f.ContentType,
		"size":           f.Size,
		"download_count": f.DownloadCount,
		"created_at":     f.CreatedAt,
		"url":            "/" + f.UUID,
	}
	if f.ExpiresAt != nil {
		m["expires_at"] = *f.ExpiresAt
	} else {
		m["expires_at"] = nil
	}
	if f.MaxDownloads != nil {
		m["max_downloads"] = *f.MaxDownloads
		remaining := *f.MaxDownloads - f.DownloadCount
		if remaining < 0 {
			remaining = 0
		}
		m["remaining"] = remaining
	} else {
		m["max_downloads"] = nil
		m["remaining"] = nil
	}
	return m
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) jsonError(w http.ResponseWriter, msg string, status int) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("render template", "err", err, "name", name)
	}
}

func isMaxBytes(err error) bool {
	var mbErr *http.MaxBytesError
	return errors.As(err, &mbErr)
}
