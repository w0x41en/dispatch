// Package auth handles admin password verification and stateless HMAC-signed
// session cookies. Sessions carry no server-side state; revocation is via
// rotating the session secret (see README).
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	randLen    = 16
	issuedLen  = 8
	payloadLen = randLen + issuedLen
	macLen     = 32 // HMAC-SHA256 output

	// CookieName is the session cookie name.
	CookieName = "dispatch_session"
)

// HashPassword returns a bcrypt hash of pw at cost 12.
func HashPassword(pw string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(pw), 12)
}

// VerifyPassword reports whether pw matches the bcrypt hash (constant-time).
func VerifyPassword(hash, pw []byte) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

// NewToken returns a fresh session token: base64url(payload).base64url(hmac),
// where payload = 16 random bytes + 8-byte big-endian issued timestamp.
func NewToken(secret []byte) (string, error) {
	var buf [payloadLen]byte
	if _, err := rand.Read(buf[:randLen]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(buf[randLen:], uint64(time.Now().Unix()))
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:])
	return base64.RawURLEncoding.EncodeToString(buf[:]) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ParseToken reports whether token is well-formed, correctly signed, and not
// older than maxAge. It is constant-time in the MAC comparison.
func ParseToken(token string, secret []byte, maxAge time.Duration) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) != payloadLen {
		return false
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(gotMAC) != macLen {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if subtle.ConstantTimeCompare(mac.Sum(nil), gotMAC) != 1 {
		return false
	}
	issued := int64(binary.BigEndian.Uint64(payload[randLen:]))
	if time.Since(time.Unix(issued, 0)) > maxAge {
		return false
	}
	return true
}

// IsHTTPS reports whether the request arrived over https. Because the server
// binds loopback behind a TLS-terminating Cloudflare Tunnel, X-Forwarded-Proto
// is trusted when r.TLS is nil.
func IsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// SetSessionCookie writes a signed session cookie scoped to path.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token, path string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     path,
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie client-side.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   IsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadSession reports whether the request carries a valid session cookie.
func ReadSession(r *http.Request, secret []byte, maxAge time.Duration) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	return ParseToken(c.Value, secret, maxAge)
}
