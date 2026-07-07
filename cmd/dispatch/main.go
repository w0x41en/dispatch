// Command dispatch runs the file-distribution HTTP server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"dispatch/internal/config"
	"dispatch/internal/server"
	"dispatch/internal/storage"
	"dispatch/internal/store"
	"github.com/joho/godotenv"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	_ = godotenv.Load() // .env is optional; env vars take precedence

	cfg, err := config.Load()
	if err != nil {
		log.Error("config invalid", "err", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		log.Error("create db dir", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Error("open store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	sg, err := storage.New(cfg.StorageDir)
	if err != nil {
		log.Error("open storage", "err", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, st, sg, log)
	if err != nil {
		log.Error("build server", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go srv.Reaper(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Info("listening",
		"addr", cfg.ListenAddr,
		"storage", cfg.StorageDir,
		"db", cfg.DBPath,
		"sessions_persist", cfg.SessionsPersist,
		"reaper", reaperLabel(cfg.ReaperInterval),
		"max_upload_bytes", cfg.MaxUploadBytes,
	)

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

func reaperLabel(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}
