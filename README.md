# dispatch

A lightweight, single-binary file-distribution service written in Go. Designed to
run behind a **Cloudflare Tunnel** on `127.0.0.1`.

- **Secret admin URL** — management UI at an unguessable path `/<ADMIN_URL_SECRET>/`,
  gated by a password (bcrypt) and a signed session cookie.
- **UUID download links** — files are served at `/<uuid>` with **no file extension
  in the URL**. The original filename is preserved via `Content-Disposition`, so
  `wget --content-disposition` and `curl -OJ` save under the real name.
- **wget / curl friendly** — `http.ServeContent` gives `Accept-Ranges: bytes` and
  full Range support, so `wget -c` resume works.
- **Optional link expiry** — per-file expiry (Never / 1h / 24h / 7d / 30d / custom),
  editable after upload. Expired links `404` immediately; a background reaper
  reclaims disk on a configurable interval.
- **Burn-after-download** — optional per-link download cap (`max_downloads`).
  Once the cap is reached the link `404`s immediately while the record is
  retained for traceability; the cap is editable after upload and composes with
  time expiry.
- **Pure Go, no CGO** — builds with `CGO_ENABLED=0` into one static binary; SQLite
  via the pure-Go `modernc.org/sqlite` driver.

## Build

```bash
go build -o dispatch ./cmd/dispatch
# or a fully static binary:
CGO_ENABLED=0 go build -o dispatch ./cmd/dispatch
```

## Configure

All settings come from environment variables.

| Env | Default | Required | Notes |
|-----|---------|----------|-------|
| `LISTEN_ADDR` | `127.0.0.1:8080` | no | keep loopback in prod |
| `ADMIN_URL_SECRET` | — | **yes** | random `[A-Za-z0-9_-]`, ≥24 chars |
| `ADMIN_PASSWORD_HASH` | — | one of | bcrypt hash (preferred) |
| `ADMIN_PASSWORD` | — | one of | plaintext, hashed at startup (convenience) |
| `SESSION_SECRET` | random per-start | no | ≥32 chars; set = sessions survive restart |
| `STORAGE_DIR` | `./data/files` | no | blob root |
| `DB_PATH` | `./data/dispatch.db` | no | SQLite file |
| `MAX_UPLOAD_BYTES` | `104857600` | no | 100 MiB (Cloudflare free-tier limit) |
| `SESSION_MAX_AGE` | `43200` | no | seconds (12h) |
| `REAPER_INTERVAL` | `3600` | no | seconds; `0` disables the expiry reaper |

### Generate the admin secret

```bash
openssl rand -hex 24    # 48 url-safe hex chars
```

### Generate a bcrypt password hash (preferred)

```bash
htpasswd -bnBC 12 "" 'your-password' | tr -d ':\n' | sed 's/^\$2y/\$2a/'
```

(If you don't have `htpasswd`, just set `ADMIN_PASSWORD` and the server will hash
it at startup with bcrypt cost 12.)

### Example

```bash
export ADMIN_URL_SECRET="$(openssl rand -hex 24)"
export ADMIN_PASSWORD_HASH="$(htpasswd -bnBC 12 "" 'correct horse battery staple' | tr -d ':\n' | sed 's/^\$2y/\$2a/')"
export SESSION_SECRET="$(openssl rand -hex 32)"
./dispatch
```

See `.example.env` for a ready-to-copy template.

## Run behind a Cloudflare Tunnel

1. Start dispatch on loopback:

   ```bash
   LISTEN_ADDR=127.0.0.1:8080 ./dispatch
   ```

2. Point `cloudflared` at it (config snippet):

   ```yaml
   ingress:
     - hostname: files.example.com
       service: http://127.0.0.1:8080
     - service: http_status:404
   ```

The server trusts `X-Forwarded-Proto: https` (set by the tunnel) so session
cookies carry the `Secure` flag and the dashboard builds `https://` download URLs.

### Upload size caveat

Cloudflare's free tier caps request bodies at **100 MiB**. `MAX_UPLOAD_BYTES`
defaults to 100 MiB and is enforced server-side with a clean `413` so you get a
sensible error instead of an opaque CF rejection. For larger files, raise the
limit **and** use a Cloudflare plan that allows it, or upload directly (but note
the server binds loopback only).

## Usage

Open `https://<tunnel-host>/<ADMIN_URL_SECRET>/` and sign in. Drag a file in,
optionally pick an expiry, and the download URL is copied to your clipboard.

Download (no extension in the URL):

```bash
wget https://files.example.com/<uuid>                       # saves as <uuid>
wget --content-disposition https://files.example.com/<uuid>  # saves as original name
wget -c https://files.example.com/<uuid>                     # resume a partial download
curl -OJ https://files.example.com/<uuid>                    # save as original name
```

## Expiry & reaper

- Set an expiry at upload (Never / 1h / 24h / 7d / 30d / custom) or edit it
  later from the dashboard (or `POST /<secret>/api/files/<uuid>/expiry` with
  `{"expires_in": <seconds>}`; `0` clears it).
- The deadline is computed server-side as `now + expires_in`; clients cannot
  forge absolute timestamps.
- An expired link returns `404` **immediately** — indistinguishable from an
  unknown UUID, so no information leaks.
- The background reaper (every `REAPER_INTERVAL`, default 1h) deletes expired
  blobs and metadata to reclaim disk. `REAPER_INTERVAL=0` disables it; expired
  files then linger on disk but their links are already dead.

## Burn-after-download

Set a per-link download cap at upload (the **Max downloads** field, or the
`max_downloads` form value) or change it later from the dashboard (or
`POST /<secret>/api/files/<uuid>/max-downloads` with `{"max_downloads": <n>}`;
`0` clears it → unlimited). Once a link has been downloaded `max_downloads`
times, further requests return `404` — indistinguishable from an unknown or
expired UUID. The metadata row and blob are **retained** for traceability and
are not auto-reaped; delete the file manually to reclaim disk.

A download **consumes a slot when it starts** (atomically, before the body is
sent), so concurrent requests against a link with one remaining slot yield
exactly one successful download; the rest get `404`. A transfer that fails
mid-stream does not refund the slot. The cap composes with time expiry:
whichever is reached first invalidates the link. Lowering the cap below the
current `download_count` immediately invalidates the link.

## Session revocation

Sessions are stateless HMAC-signed cookies. Logout clears the cookie client-side.
To forcibly invalidate **all** sessions, rotate `SESSION_SECRET` and restart the
binary (existing cookies then fail to verify). If `SESSION_SECRET` is unset, a
random one is generated per start, so a restart also clears all sessions.

## Project layout

```
cmd/dispatch/        entrypoint
internal/config/     env loading + validation
internal/model/      shared File type
internal/store/      SQLite metadata (modernc.org/sqlite, no CGO)
internal/storage/    filesystem blobs (UUID-sharded, traversal-safe)
internal/auth/       bcrypt + HMAC session cookies
internal/server/     routing, middleware, handlers, reaper
web/                 embedded HTML templates (light theme)
```

## Security notes

- The secret admin URL is a **capability URL**, not the sole defense — a password
  (bcrypt) is required on top.
- Cookies: `HttpOnly`, `SameSite=Lax`, conditional `Secure`, scoped to the admin
  path.
- CSRF: SameSite + `Origin`/`Referer` host check on mutating routes.
- Storage paths are UUID-derived only — path traversal is impossible.
- Unknown, expired, and count-exhausted UUIDs return an identical `404` (no information leak).
- Login attempts are throttled with exponential backoff after 5 failures.
