# Source labels and supported sources

Selection is opt-in through `bakabel.type`, inside config `scope`. No type inference from image names, enable flags, hooks, shell commands, worker image overrides, or consistency acknowledgements are supported.

## PostgreSQL

Apply this **fragment to the existing service**, not as a standalone application manifest. For Compose, labels belong on the container:

```yaml
# services.db
labels:
  bakabel.type: postgres
```

For Swarm, source selection uses **service** labels:

```yaml
# services.db
# Keep the existing application's placement and one-replica policy explicit.
deploy:
  labels:
    bakabel.type: postgres
```

The database defaults to the container's explicit `POSTGRES_DB`; the user comes from explicit `POSTGRES_USER`. Missing or unusable values fail rather than guessing. Add `bakabel.postgres.database: app` only to select a different database. In Swarm the frozen service-label override is authoritative; it need not exist on the task container.

Use the tested stock `postgres:18.6-alpine3.24` baseline; the fixture's recorded digest is `postgres@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792`. Restore's trusted empty-catalog baseline and target clients require **18.6**, not arbitrary PostgreSQL versions or customized system catalogs. Pin/review your actual application image; this fragment does not upgrade it.

Fixed `pg_dump`/`psql` and cancellation/control tools must exist inside the trusted source container. Docker exec runs as container root and connects at `/var/run/postgresql`, port 5432, as the configured PostgreSQL **superuser**, without password prompting/injection. The operator must provision that local authentication policy; Bakabel does not change `pg_hba.conf`, create users or silently fall back to TCP/password authentication. The dump client's version must match the server major. A complete single-database custom-format dump is not roles/globals, PITR/WAL recovery, or a consistent multi-database/multi-volume checkpoint.

The dump streams from the online source into Restic without a full local dump staging file. Source CPU/RAM/I/O still count: the worker limit does not limit the database's export exec.

## Files

Compose fragment for an existing files service with a default local named volume mounted at `/data`:

```yaml
# services.files
labels:
  bakabel.type: volume
  bakabel.paths: /data
```

Swarm equivalent:

```yaml
# services.files
deploy:
  labels:
    bakabel.type: volume
    bakabel.paths: /data
```

`bakabel.paths` is an exact mount destination, or comma-separated distinct exact destinations without added whitespace. Each selected mount becomes a separate target. A parent directory, arbitrary host path, relative path, traversal, subpath mount or nested mount cannot broaden selection. Only inspected option-free `local` Docker volumes on supported local Linux filesystems are accepted; bind/plugin/network volumes are not supported file sources. The worker reads source mounts read-only; no full tar/copy staging is used.

**This is file copying, not application-consistent backup.** Files may change during traversal. Do not use it for a live database directory; the PGDATA guard refuses recognized PostgreSQL data directories, but cannot identify every database format or unsafe application state. A consistency label cannot make such a source safe. Use the PostgreSQL adapter for PostgreSQL, not `type=volume` on PGDATA.

## Placement, availability and identity

- Under the approved stateless Compose contract, each observable marked service must have exactly one running container; retained stopped duplicates/multiple replicas are unsupported and stopped marked sources fail. With **zero remaining containers**, Engine metadata cannot reveal the removed service's labels. An entirely empty selection yields `no targets` on `run`, not backup success. A complete run covers its fixed discovered targets, not an external desired-service inventory; no registry, Compose-file dependency or event watcher is implied.
- Swarm reads service metadata, resolves a single running task and requires the same exact local manager/node/daemon. Remote placement, zero/multiple replicas or ambiguous sources fail; there is no fuzzy primary choice. Keep the application and backup stack separately deployed, but constrain selected sources to that same node.
- Targets remain online throughout backup. Source replacement or mount drift fails the target rather than silently switching incarnations. No stop/restart/scale-down fallback exists.
- Stable source identity is installation + platform + project/stack + service + database/mount, not task/container ID. Keep names stable. Restic uses one stable installation hostname and stable per-source paths. PostgreSQL additionally pins a verified same-source complete parent because stdin-command parent selection cannot safely rely on host/path grouping alone.
- Logical names are not physical proof: PostgreSQL cluster system ID/database OID and resolved volume backing identities support restore exclusions. Config, credentials, Docker socket, repository and state storage must never be selected, including aliases or nested paths.
- Before file backup, the controller captures metadata-only physical identities for all its inspected persistent mounts, including regular credential/config files and sockets. The worker rejects a source whose backing overlaps any protected identity. Unprovable identities, symlinked protected namespace paths and hard-linked protected regular files are refused rather than guessed safe; no protected file contents are copied into job metadata.

Always review `plan` after changing source labels or application storage. It validates discovery, not a future backup, application consistency, or a tested restore.
