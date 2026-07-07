package server

import (
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"dispatch/internal/auth"
)

// statusWriter captures the response status code for logging.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// recover catches panics, logs a stack trace, and returns a generic 500.
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// logRequest logs one line per request with method, path, status, duration.
func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

// requireAuth gates a handler behind a valid session cookie. API paths get a
// 401; HTML pages redirect to the login page.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.ReadSession(r, s.cfg.SessionSecret, s.cfg.SessionMaxAge) {
			h(w, r)
			return
		}
		if strings.Contains(r.URL.Path, "/api/") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/"+s.cfg.AdminURLSecret+"/", http.StatusFound)
	}
}

// csrf rejects state-changing requests whose Origin/Referer host does not
// match the request host. SameSite=Lax is the primary defense; this is
// defense-in-depth.
func (s *Server) csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h(w, r)
	}
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// clientIP extracts the originating IP for throttle bucketing. Behind
// Cloudflare Tunnel, X-Forwarded-For carries the real client; otherwise
// RemoteAddr is used. Used only for coarse throttling, never for authz.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// throttleWait returns how long until the next login attempt from ip is allowed.
func (s *Server) throttleWait(ip string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.fails[ip]
	if st == nil {
		return 0
	}
	return time.Until(st.next)
}

// recordLoginFail increments the failure counter and sets an exponential
// backoff after 5 failures (capped at 30s).
func (s *Server) recordLoginFail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.fails[ip]
	if st == nil {
		st = &loginState{}
		s.fails[ip] = st
	}
	st.count++
	if st.count >= 5 {
		backoff := time.Duration(1<<(st.count-5)) * time.Second // 2^(n-5)
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		st.next = time.Now().Add(backoff)
	}
}

// recordLoginSuccess clears the failure counter for ip.
func (s *Server) recordLoginSuccess(ip string) {
	s.mu.Lock()
	delete(s.fails, ip)
	s.mu.Unlock()
}
