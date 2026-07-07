package config

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func mustBcrypt(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// clearAuthEnv unsets every env var Load() reads so each test starts clean.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LISTEN_ADDR", "ADMIN_URL_SECRET", "ADMIN_PASSWORD_HASH", "ADMIN_PASSWORD",
		"SESSION_SECRET", "STORAGE_DIR", "DB_PATH", "MAX_UPLOAD_BYTES",
		"SESSION_MAX_AGE", "REAPER_INTERVAL",
	} {
		t.Setenv(k, "")
	}
}

func TestLoad_MissingSecret(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_PASSWORD", "pw123456")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing ADMIN_URL_SECRET")
	}
}

func TestLoad_ShortSecret(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "short")
	t.Setenv("ADMIN_PASSWORD", "pw123456")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short ADMIN_URL_SECRET")
	}
}

func TestLoad_BothPasswordSources(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "a-very-very-very-long-secret-value")
	t.Setenv("ADMIN_PASSWORD_HASH", mustBcrypt(t, "pw123456"))
	t.Setenv("ADMIN_PASSWORD", "pw123456")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when both password sources set")
	}
}

func TestLoad_NoPasswordSource(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "a-very-very-very-long-secret-value")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when no password source set")
	}
}

func TestLoad_BadBcryptHash(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "a-very-very-very-long-secret-value")
	t.Setenv("ADMIN_PASSWORD_HASH", "not-a-bcrypt-hash")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for malformed bcrypt hash")
	}
}

func TestLoad_NegativeReaper(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "a-very-very-very-long-secret-value")
	t.Setenv("ADMIN_PASSWORD", "pw123456")
	t.Setenv("REAPER_INTERVAL", "-1")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for negative REAPER_INTERVAL")
	}
}

func TestLoad_Valid(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ADMIN_URL_SECRET", "a-very-very-very-long-secret-value")
	t.Setenv("ADMIN_PASSWORD_HASH", mustBcrypt(t, "pw123456"))
	t.Setenv("REAPER_INTERVAL", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ReaperInterval != 0 {
		t.Errorf("expected reaper disabled (0), got %v", cfg.ReaperInterval)
	}
	if cfg.SessionsPersist {
		t.Error("expected SessionsPersist=false when SESSION_SECRET unset")
	}
	if cfg.SessionMaxAge != 12*time.Hour {
		t.Errorf("expected default 12h session max age, got %v", cfg.SessionMaxAge)
	}
}
