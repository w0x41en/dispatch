// Package model defines shared domain types passed between layers.
package model

// File is the metadata record for an uploaded file. Blobs are stored on disk
// under StoragePath (UUID-derived); this struct holds everything else.
type File struct {
	UUID             string
	OriginalFilename string
	ContentType      string
	Size             int64
	StoragePath      string
	DownloadCount    int64
	CreatedAt        int64  // unix seconds
	ExpiresAt        *int64 // unix seconds; nil = never expires
	MaxDownloads     *int64 // nil = unlimited; else cap on served downloads (burn-after-download)
}
