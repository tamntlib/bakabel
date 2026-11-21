# Bakabel

Minimal, label-driven backup scheduler for Docker Compose and single-node Docker Swarm — **"Traefik for backups"**.

Drop Bakabel in as an independent backup stack, add `bakabel.type` labels to the services you want protected, and Bakabel discovers them automatically and backs them up online to Restic (local storage or S3-compatible).

## Highlights

- **100% environment-variable configuration** (`*_FILE` supported for all secrets) — no required YAML config file.
- **Zero-touch safe `restic init`:** on first run, if the repository does not exist and is empty, Bakabel initializes it automatically and pins its `repository_id` in state. If storage ever disappears or changes later, Bakabel fails closed and refuses to re-initialize.
- **Online PostgreSQL streaming:** runs `pg_dump --format=custom --compress=0` via Docker exec and streams directly into `restic backup --stdin` (letting Restic deduplicate chunks before zstd compression) with header + completion-sentinel verification (no staging dump file, no silent truncation, no database downtime).
- **Online SQLite WAL-safe backup:** uses an ephemeral helper container with `sqlite3` Online Backup API (`PRAGMA query_only=ON` + `.backup`, dropping to the DB file's UID:GID so `-wal`/`-shm` ownership is untouched), verifies `PRAGMA integrity_check`, and streams the consistent snapshot into Restic — works even when the app container has no `sqlite3` CLI.
- **Named Docker volumes:** mounts each labeled local named volume read-only into an ephemeral helper container using Bakabel's own image (auto-detected — no `worker_image` duplication) and backs it up with Restic.
- **Safe restore & health checks:** restores only into explicit empty targets (`bakabel restore`), includes read-only `bakabel health`, optional retention (`BAKABEL_RETENTION`), and optional failure webhooks.
- **Minimal Alpine image:** static Go binary (`GOAMD64=v1`) + Restic + `sqlite3` + CA certs + embedded timezone data.

## Quick start

### 1. Deploy Bakabel

See [deploy/compose.example.yaml](deploy/compose.example.yaml) or [deploy/swarm.example.yaml](deploy/swarm.example.yaml). Minimal Compose example:

```yaml
services:
  bakabel:
    image: ghcr.io/tamntlib/bakabel:v0.2.0
    environment:
      BAKABEL_REPOSITORY: /repository # or s3:https://...
      BAKABEL_SCHEDULE: "0 2 * * *"
      BAKABEL_TZ: Asia/Ho_Chi_Minh
      RESTIC_PASSWORD: ${RESTIC_PASSWORD}
    volumes:
      - bakabel-state:/var/lib/bakabel
      - bakabel-repo:/repository
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

> **Note:** Always store a copy of your `RESTIC_PASSWORD` outside the server. Local storage on the same host does not survive loss of that host/disk — use an S3-compatible repository (`s3:https://...`) for off-host backups.

### 2. Label services to back up

**PostgreSQL** (Compose `labels:` or Swarm `deploy.labels:`):

```yaml
bakabel.type: postgres
# Optional overrides (default: container POSTGRES_DB / POSTGRES_USER):
# bakabel.postgres.database: app
# bakabel.postgres.user: app
```

**SQLite** (Compose `labels:` or Swarm `deploy.labels:`):

```yaml
bakabel.type: sqlite
bakabel.paths: /data/app.db # comma-separated SQLite DB file paths inside named volume(s)
```

**Named Docker volume** (Compose `labels:` or Swarm `deploy.labels:`):

```yaml
bakabel.type: volume
bakabel.paths: /data # comma-separated exact container mount destinations
```

> Do not use `bakabel.type: volume` for live database data directories (PGDATA is explicitly refused; use `bakabel.type: postgres` or `bakabel.type: sqlite`).

### 3. CLI commands

```bash
# Preview discovered targets (read-only)
docker exec <bakabel-container> bakabel plan

# Run a backup immediately (auto-initializes empty repository on first run)
docker exec <bakabel-container> bakabel run

# List Bakabel snapshots
docker exec <bakabel-container> bakabel snapshots

# Restore PostgreSQL snapshot into a separate empty database container
docker exec <bakabel-container> bakabel restore <snapshot-id> --container <empty-pg-container>

# Restore volume snapshot into a separate empty Docker volume
docker exec <bakabel-container> bakabel restore <snapshot-id> --volume <empty-volume>

# Check scheduler/backup health (read-only; exit 0 healthy/running, 1 failed/overdue/never)
docker exec <bakabel-container> bakabel health
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BAKABEL_REPOSITORY` (or `RESTIC_REPOSITORY`) | *(required)* | Local path (e.g. `/repository`) or Restic URL (e.g. `s3:https://...`) |
| `RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE` | *(required)* | Restic repository passphrase or secret file path |
| `BAKABEL_SCHEDULE` | `0 2 * * *` | 5-field cron schedule for `serve` |
| `BAKABEL_TZ` (or `TZ`) | `UTC` | IANA timezone for cron evaluation |
| `BAKABEL_SCOPE` | *(all)* | Optional comma-separated Swarm stacks / Compose projects to include |
| `BAKABEL_PLATFORM` | `auto` | `auto` (Swarm manager if active, else Compose), `swarm`, or `compose` |
| `BAKABEL_AUTO_INIT` | `true` | Auto-initialize repository when missing and empty (guarded by `state/repo.json`) |
| `BAKABEL_RETENTION` | *(off)* | Optional Restic retention policy, e.g. `7d,4w,6m` or `last=10,daily=7` |
| `BAKABEL_TIMEOUT` | `1h` | Per-run timeout duration |
| `BAKABEL_STATE_DIR` | `/var/lib/bakabel` | State directory (`bakabel.lock`, `repo.json`, `last-result.json`, `cache/`) |
| `BAKABEL_INSTALLATION` | `bakabel` | Stable Restic snapshot hostname |
| `BAKABEL_DOCKER_SOCKET` | `/var/run/docker.sock` | Local Docker Engine Unix socket path |
| `BAKABEL_WORKER_IMAGE` | *(auto)* | Optional override for volume helper container image |
| `BAKABEL_WORKER_NETWORK` | *(auto)* | Network mode for volume helper (`none` for local repo, controller network/bridge for remote) |
| `BAKABEL_WEBHOOK_URL` / `BAKABEL_WEBHOOK_URL_FILE` | *(off)* | Optional HTTP POST webhook notified on backup failure |
| `AWS_ACCESS_KEY_ID` / `_FILE`, `AWS_SECRET_ACCESS_KEY` / `_FILE`, `AWS_DEFAULT_REGION` | *(optional)* | S3-compatible repository credentials |

## Scope & limits

- Single-node Compose or Swarm manager: in Swarm mode, Bakabel requires each marked service to have 1 running replica on the same manager node as Bakabel (no remote-node volume access).
- Logical PostgreSQL dumps (`pg_dump -Fc`) back up a single database per target (not cluster globals/roles or PITR/WAL).
- Volume backups copy live files read-only without stopping writers; do not use for live databases.
- Mounting `/var/run/docker.sock` grants root-equivalent Docker Engine authority even with `:ro`.
