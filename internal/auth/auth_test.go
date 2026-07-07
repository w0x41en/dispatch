package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, err := NewToken(secret)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if !ParseToken(tok, secret, time.Hour) {
		t.Fatal("expected valid token")
	}
}

func TestTokenTamperDetected(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, _ := NewToken(secret)
	// Flip a character in the mac portion.
	tampered := tok[:len(tok)-1]
	if tok[len(tok)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}
	if ParseToken(tampered, secret, time.Hour) {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestTokenWrongSecret(t *testing.T) {
	tok, _ := NewToken([]byte("secret-one-0123456789abcdef00000"))
	if ParseToken(tok, []byte("secret-two-0123456789abcdef00000"), time.Hour) {
		t.Fatal("expected token to fail under a different secret")
	}
}

func TestTokenExpiry(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, _ := NewToken(secret)
	// maxAge of zero means "issued more than 0 ago" — any token in the past
	// fails. Use a tiny window with a sleep to be robust across clocks.
	if !ParseToken(tok, secret, time.Hour) {
		t.Fatal("fresh token should validate")
	}
	if ParseToken(tok, secret, 0) {
		t.Fatal("expired token should not validate")
	}
}

func TestCookieSetAndRead(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, _ := NewToken(secret)

	r := httptest.NewRequest(http.MethodGet, "/admin-x/", nil)
	w := httptest.NewRecorder()
	SetSessionCookie(w, r, tok, "/admin-x", time.Hour)

	r2 := httptest.NewRequest(http.MethodGet, "/admin-x/dashboard", nil)
	r2.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	if !ReadSession(r2, secret, time.Hour) {
		t.Fatal("expected ReadSession to validate the cookie")
	}
}

func TestIsHTTPS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if IsHTTPS(r) {
		t.Fatal("plain request should not be https")
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if !IsHTTPS(r) {
		t.Fatal("X-Forwarded-Proto=https should be trusted")
	}
}
