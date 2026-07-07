CREATE TABLE IF NOT EXISTS files (
    uuid              TEXT    PRIMARY KEY,
    original_filename TEXT    NOT NULL,
    content_type      TEXT    NOT NULL DEFAULT 'application/octet-stream',
    size              INTEGER NOT NULL,
    storage_path      TEXT    NOT NULL,   -- relative to STORAGE_DIR, e.g. "ab/<uuid>.bin"
    download_count    INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,   -- unix seconds
    expires_at        INTEGER,             -- unix seconds; NULL = never expires
    max_downloads     INTEGER              -- NULL = unlimited; else cap on served downloads
);

CREATE INDEX IF NOT EXISTS files_created_at_idx ON files(created_at DESC);
CREATE INDEX IF NOT EXISTS files_expires_at_idx ON files(expires_at) WHERE expires_at IS NOT NULL;
