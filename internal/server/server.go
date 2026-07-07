// Package server wires HTTP routing, middleware, and handlers for the
// file-distribution service.
package server

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"dispatch/internal/config"
	"dispatch/internal/storage"
	"dispatch/internal/store"
	"dispatch/web"
)

// Server holds shared dependencies and login-throttle state.
type Server struct {
	cfg     config.Config
	store   *store.Store
	storage *storage.Storage
	tpl     *template.Template
	log     *slog.Logger

	mu    sync.Mutex
	fails map[string]*loginState
}

type loginState struct {
	count int
	next  time.Time // earliest time the next attempt is allowed
}

// New builds a Server with parsed templates.
func New(cfg config.Config, st *store.Store, sg *storage.Storage, log *slog.Logger) (*Server, error) {
	tpl, err := template.ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{
		cfg:     cfg,
		store:   st,
		storage: sg,
		tpl:     tpl,
		log:     log,
		fails:   make(map[string]*loginState),
	}, nil
}

// Handler assembles the mux and the global middleware chain.
func (s *Server) Handler() http.Handler {
	secret := s.cfg.AdminURLSecret
	admin := "/" + secret + "/"

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /", s.notFound) // root + unmatched multi-segment → 404

	// Admin subtree. loginPage 404s anything that isn't the exact index.
	mux.HandleFunc("GET "+admin, s.loginPage)
	mux.HandleFunc("POST "+admin+"login", s.login)
	mux.HandleFunc("POST "+admin+"logout", s.logout)
	mux.HandleFunc("GET "+admin+"dashboard", s.requireAuth(s.dashboard))
	mux.HandleFunc("GET "+admin+"api/files", s.requireAuth(s.apiList))
	mux.HandleFunc("POST "+admin+"api/upload", s.requireAuth(s.csrf(s.apiUpload)))
	mux.HandleFunc("POST "+admin+"api/files/{uuid}/expiry", s.requireAuth(s.csrf(s.apiExpiry)))
	mux.HandleFunc("POST "+admin+"api/files/{uuid}/max-downloads", s.requireAuth(s.csrf(s.apiMaxDownloads)))
	mux.HandleFunc("POST "+admin+"api/files/{uuid}/delete", s.requireAuth(s.csrf(s.apiDelete)))

	// Public capability URL.
	mux.HandleFunc("GET /{uuid}", s.download)

	return s.recover(s.logRequest(mux))
}

// healthz is the tunnel uptime probe.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// notFound returns an empty 404 so probes learn nothing.
func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}
