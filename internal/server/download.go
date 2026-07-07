package server

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"dispatch/internal/store"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// download serves a file by UUID. Unknown and expired UUIDs return an identical
// empty 404 (no information leak). Range requests are supported via
// http.ServeContent, so `wget -c` resume works.
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if !uuidRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	f, err := s.store.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.log.Error("download get", "err", err, "uuid", id)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Expiry gate — identical 404 to an unknown UUID. Checked before the
	// download-slot gate so an expired link never consumes a slot.
	if f.ExpiresAt != nil && time.Now().Unix() >= *f.ExpiresAt {
		http.NotFound(w, r)
		return
	}

	// Burn-after-download gate: for limited links, atomically consume a slot
	// before serving. ConsumeDownloadSlot increments download_count only when
	// it is below the cap, so concurrent requests cannot over-serve. !ok means
	// the limit is reached — return the same empty 404 as an unknown UUID (no
	// information leak). The slot is consumed even if the transfer later fails
	// (option B: no refund).
	if f.MaxDownloads != nil {
		ok, err := s.store.ConsumeDownloadSlot(r.Context(), id, *f.MaxDownloads)
		if err != nil {
			s.log.Error("consume download slot", "err", err, "uuid", id)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
	}

	rc, modTime, err := s.storage.Open(f.StoragePath)
	if err != nil {
		s.log.Error("download open", "err", err, "uuid", id)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Disposition", contentDisposition(f.OriginalFilename))
	w.Header().Set("Accept-Ranges", "bytes")
	// ServeContent sets Content-Type, Content-Length, Last-Modified, ETag,
	// and handles Range → 206 / If-Modified-Since → 304.
	http.ServeContent(w, r, f.ContentType, modTime, rc)

	// Unlimited links count a completed download after serving (existing
	// semantics). Limited links were already counted by ConsumeDownloadSlot.
	if f.MaxDownloads == nil {
		if err := s.store.IncrementDownloadCount(r.Context(), id); err != nil {
			s.log.Warn("increment download count", "err", err, "uuid", id)
		}
	}
}

// contentDisposition builds an RFC 6266 / 5987 header. The ASCII fallback is
// sanitized for the quoted string; non-ASCII names also get filename*=UTF-8”.
func contentDisposition(name string) string {
	name = sanitizeBasename(name)
	if name == "" {
		name = "file"
	}
	var b strings.Builder
	b.WriteString(`attachment; filename="`)
	b.WriteString(sanitizeASCII(name))
	b.WriteString(`"`)
	if !isASCII(name) {
		b.WriteString(`; filename*=UTF-8''`)
		b.WriteString(pctEncode(name))
	}
	return b.String()
}

func sanitizeBasename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// sanitizeASCII strips characters that would break the quoted filename="..."
// fallback: control chars, quotes, backslashes, and non-ASCII bytes.
func sanitizeASCII(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r > 0x7e {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" {
		out = "file"
	}
	return out
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 0x7f {
			return false
		}
	}
	return true
}

// pctEncode percent-encodes per RFC 3986 unreserved set, suitable for the
// RFC 5987 filename* value (space → %20, not "+").
func pctEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
