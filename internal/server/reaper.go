package server

import (
	"context"
	"time"
)

// Reaper periodically purges expired files (blob + metadata) to reclaim disk.
// Links already 404 at download time the moment they expire; this goroutine
// only reclaims storage. A no-op if ReaperInterval is 0.
func (s *Server) Reaper(ctx context.Context) {
	if s.cfg.ReaperInterval <= 0 {
		return
	}
	t := time.NewTicker(s.cfg.ReaperInterval)
	defer t.Stop()
	s.log.Info("reaper started", "interval", s.cfg.ReaperInterval.String())
	for {
		select {
		case <-ctx.Done():
			s.log.Info("reaper stopped")
			return
		case <-t.C:
			s.reapExpired(ctx)
		}
	}
}

func (s *Server) reapExpired(ctx context.Context) {
	files, err := s.store.ListExpired(ctx, time.Now().Unix())
	if err != nil {
		s.log.Error("reaper list", "err", err)
		return
	}
	for _, f := range files {
		// Blob first, row second. If we crash between the two, the next tick
		// reaps the orphaned row (Remove tolerates a missing blob).
		if err := s.storage.Remove(f.StoragePath); err != nil {
			s.log.Error("reaper remove blob", "err", err, "uuid", f.UUID)
			continue
		}
		if err := s.store.Delete(ctx, f.UUID); err != nil {
			s.log.Error("reaper delete row", "err", err, "uuid", f.UUID)
		}
	}
	if len(files) > 0 {
		s.log.Info("reaper purged", "count", len(files))
	}
}
