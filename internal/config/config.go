// Package config loads runtime configuration from environment variables and
// validates it at startup. Invalid config fails fast with a clear message.
package config

import (
	"crypto/rand"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// secretRe constrains ADMIN_URL_SECRET to url-safe path-segment characters so
// it can be used verbatim as a URL path segment and a cookie Path.
var secretRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Config holds all runtime settings. It is built once at startup and treated
// as immutable thereafter.
type Config struct {
	ListenAddr     string
	AdminURLSecret string // unguessable path prefix segment
	PasswordHash   []byte // bcrypt hash of the admin password
	SessionSecret  []byte // HMAC key for session cookies
	StorageDir     string
	DBPath         string
	MaxUploadBytes int64
	SessionMaxAge  time.Duration
	ReaperInterval time.Duration // 0 = reaper disabled

	// SessionsPersist reports whether SessionSecret came from the env (survives
	// restart) vs. generated per-process (lost on restart).
	SessionsPersist bool
}

// Load reads env vars, applies defaults, and validates. Returns an error
// describing the first invalid field, if any.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:     envOr("LISTEN_ADDR", "127.0.0.1:8080"),
		AdminURLSecret: os.Getenv("ADMIN_URL_SECRET"),
		StorageDir:     envOr("STORAGE_DIR", "./data/files"),
		DBPath:         envOr("DB_PATH", "./data/dispatch.db"),
		MaxUploadBytes: envOrInt64("MAX_UPLOAD_BYTES", 104857600), // 100 MiB
		SessionMaxAge:  time.Duration(envOrInt("SESSION_MAX_AGE", 43200)) * time.Second,
		ReaperInterval: time.Duration(envOrInt("REAPER_INTERVAL", 3600)) * time.Second,
	}

	if cfg.AdminURLSecret == "" {
		return cfg, fmt.Errorf("ADMIN_URL_SECRET is required (random url-safe token, >=24 chars)")
	}
	if len(cfg.AdminURLSecret) < 24 {
		return cfg, fmt.Errorf("ADMIN_URL_SECRET must be >= 24 chars (got %d)", len(cfg.AdminURLSecret))
	}
	if !secretRe.MatchString(cfg.AdminURLSecret) {
		return cfg, fmt.Errorf("ADMIN_URL_SECRET must contain only [A-Za-z0-9_-]")
	}
	if strings.ContainsAny(cfg.AdminURLSecret, "/?#") {
		return cfg, fmt.Errorf("ADMIN_URL_SECRET must not contain '/', '?', or '#'")
	}

	// Exactly one password source.
	hashStr := os.Getenv("ADMIN_PASSWORD_HASH")
	pw := os.Getenv("ADMIN_PASSWORD")
	switch {
	case hashStr != "" && pw != "":
		return cfg, fmt.Errorf("set either ADMIN_PASSWORD_HASH or ADMIN_PASSWORD, not both")
	case hashStr != "":
		h := []byte(hashStr)
		if _, err := bcrypt.Cost(h); err != nil {
			return cfg, fmt.Errorf("ADMIN_PASSWORD_HASH is not a valid bcrypt hash: %w", err)
		}
		cfg.PasswordHash = h
	case pw != "":
		h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
		if err != nil {
			return cfg, fmt.Errorf("failed to hash ADMIN_PASSWORD: %w", err)
		}
		cfg.PasswordHash = h
	default:
		return cfg, fmt.Errorf("set ADMIN_PASSWORD_HASH (preferred) or ADMIN_PASSWORD")
	}

	// Session secret: env (persistent) or random per-process.
	if s := os.Getenv("SESSION_SECRET"); s != "" {
		if len(s) < 32 {
			return cfg, fmt.Errorf("SESSION_SECRET must be >= 32 chars if set")
		}
		cfg.SessionSecret = []byte(s)
		cfg.SessionsPersist = true
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return cfg, fmt.Errorf("failed to generate session secret: %w", err)
		}
		cfg.SessionSecret = b
	}

	if cfg.ReaperInterval < 0 {
		return cfg, fmt.Errorf("REAPER_INTERVAL must be >= 0 (got %d)", int(cfg.ReaperInterval/time.Second))
	}
	if cfg.MaxUploadBytes <= 0 {
		return cfg, fmt.Errorf("MAX_UPLOAD_BYTES must be > 0")
	}
	if cfg.SessionMaxAge <= 0 {
		return cfg, fmt.Errorf("SESSION_MAX_AGE must be > 0")
	}

	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOrInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
