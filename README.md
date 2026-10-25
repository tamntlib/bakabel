# Bakabel

Bakabel is a Go + Restic backup tool for online PostgreSQL databases and selected Docker volumes. Labels select sources within an explicit Compose project or Swarm stack scope. Each run discovers once, processes targets sequentially in one temporary worker, and uses the same immutable image as the controller. It does not stop, restart, or scale applications.

**Pre-release, not production-approved:** the repository and image are not published. Build locally; no GHCR pull is promised. The public CLI is `--config FILE plan|run|serve|health|snapshots|restore`. Full isolated-Engine file/PostgreSQL and Swarm/S3 CLI acceptance passed on historical baseline source `633192cb` / image `568e907b`, not automatically on later revisions. Resource baseline `2fd683f9` / image `ff1a6cd8` added verified lifecycle/resource and Compose/local/S3 PostgreSQL-subset evidence; Astra R1 then found implementation defects. Later fix verification and Astra verdicts are recorded in the [current implementation status](tests/integration/IMPLEMENTATION_STATUS.md); historical evidence does not transfer to a newer image. Current full file-restore/Swarm replay remains blocked by isolated-runtime permissions; see [resource evidence and boundaries](docs/resources.md). No production certification is implied.

## Supported baseline

- Linux Docker Engine API **1.55**, tested with Engine **29.6.1**. The adapter does not negotiate older API versions. amd64 builds use `GOAMD64=v1`, without an advanced CPU requirement.
- Compose: one running container per selected service. Swarm: one running replica, on the exact manager/node/daemon used by Bakabel. No remote-node volume lookup or heuristic primary selection.
- Files: default `local` Docker volumes with **no driver options**, selected at exact container mount destinations. Source bind mounts, volume subpaths, plugin/network volumes and opaque mount topologies are unsupported.
- PostgreSQL: use the tested stock **18.6** baseline (see [sources](docs/sources.md)). The fixed clients run inside the source/restore PostgreSQL container, not the Bakabel image. Operator-configured Unix-socket superuser access is required; this is not arbitrary remote PostgreSQL support.
- One installation owns one repository. Local storage on the same host does **not** protect against loss of that server.

The Docker socket is root-equivalent authority, **even mounted `:ro`**. Protect the controller, worker image, config, state, repository and credential files accordingly. Never label Bakabel's own storage as a source.

## Quick start: local repository, one-shot Compose

Run these commands only on the intended Docker host, after reviewing the paths, scope and source prerequisites. They are operator instructions, not an automatic installer. Do not source a `.env` file. Prepare private files as the identity mapped to container UID 0: root for a rootful daemon, or the daemon owner for rootless Docker. Otherwise a capability-restricted worker may not be able to read a 0600 password file.

### 1. Build and pin the image

From a reviewed checkout, use the supplied Dockerfile, which pins its build frontend, Go builder and Restic image by digest. The runtime is `scratch`: Bakabel, Restic, CA certificates and embedded Go timezone data; no shell or Docker CLI.

```bash
docker build --platform linux/amd64 --build-arg BUILD_CPUSET=0,1 \
  --cpu-period 100000 --cpu-quota 200000 -t bakabel:local . &&
BAKABEL_IMAGE="$(docker image inspect bakabel:local --format '{{.Id}}')" &&
test -n "$BAKABEL_IMAGE" && export BAKABEL_IMAGE
```

Keep this exact image ID available on the same daemon for both controller and worker. Rebuilding a mutable tag is not an upgrade of the configured worker. The build-only CPU affinity assumes cores 0,1 are available; adjust it for a different builder. Measured resource baselines and their revision boundaries are recorded in `docs/resources.md`; they are not universal production budgets.

### 2. Prepare private storage and a password-file reference

Obtain a strong repository password from your secret manager first, as a protected file at `/secure/operator/restic-password`. The source path is a placeholder, not a supplied secret. Do not put the password in YAML, shell arguments, labels or Git. Preserve the decryption key and repository recovery/access details **outside this host** before the first backup.

```bash
umask 077
export BAKABEL_HOME="$HOME/.local/share/bakabel"
install -d -m 0700 "$BAKABEL_HOME/state" "$BAKABEL_HOME/repository" "$BAKABEL_HOME/credentials" &&
test -s /secure/operator/restic-password &&
test ! -e "$BAKABEL_HOME/credentials/restic-password" &&
test ! -L "$BAKABEL_HOME/credentials/restic-password" &&
install -m 0600 /secure/operator/restic-password "$BAKABEL_HOME/credentials/restic-password"
```

Do not rerun credential installation over an existing repository's key. Losing the password can make the backup unusable. Populate any optional S3/webhook credential files through the same protected-file process; never commit their contents.

### 3. Configure scope and worker identity

Copy [deploy/bakabel.example.yaml](deploy/bakabel.example.yaml) to `$BAKABEL_HOME/bakabel.yaml`. Its `worker_image` is intentionally invalid until replaced with the exact `BAKABEL_IMAGE` returned above; do not substitute an invented digest or mutable tag. Change `scope: [myapp]` to the existing application's Compose project. The backup project remains separate.

```bash
test ! -e "$BAKABEL_HOME/bakabel.yaml" &&
test ! -L "$BAKABEL_HOME/bakabel.yaml" &&
install -m 0600 deploy/bakabel.example.yaml "$BAKABEL_HOME/bakabel.yaml"
```

Edit that file to replace the image placeholder and scope. For rootless Docker, also export `DOCKER_SOCKET` as the actual local socket shown by `docker context inspect --format '{{.Endpoints.docker.Host}}'`, removing only its `unix://` prefix. The deployment defaults to `/var/run/docker.sock` for rootful Docker; remote Engine endpoints are not supported by these examples. Keep the exported non-secret variables in the operator shell, not a sourced `.env`.

Read [configuration](docs/configuration.md) and add the minimal [source labels](docs/sources.md) to the application separately. Sources must be online; labeling is not permission for Bakabel to restart them.

### 4. Initialize Restic explicitly, before backup

Only initialize a deliberately new, empty repository. Access errors are not evidence that an existing repository needs initialization. Bakabel never auto-initializes.

```bash
docker run --rm --network none --cpus 2 \
  --mount "type=bind,src=$BAKABEL_HOME/repository,dst=/repository" \
  --mount "type=bind,src=$BAKABEL_HOME/credentials/restic-password,dst=/run/secrets/restic-password,readonly" \
  --env RESTIC_PASSWORD_FILE=/run/secrets/restic-password \
  --entrypoint /usr/bin/restic "$BAKABEL_IMAGE" --repo /repository init
```

### 5. Inspect, run, and read back snapshots

These commands use one-off controller containers before enabling the scheduled service. They share the private state and exact installation labels needed to launch the temporary worker. `plan` performs read-only discovery: no worker, upload or repository initialization.

```bash
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler --config /etc/bakabel/bakabel.yaml plan
# Review every target and its resolved database/mount before proceeding.
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler --config /etc/bakabel/bakabel.yaml run
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler --config /etc/bakabel/bakabel.yaml snapshots
```

Commands emit JSON on stdout and sanitized errors on stderr. A zero exit from `plan` is not backup success; an empty target list is not protection. `run` with no targets fails without refreshing the last result. Read back each exact final snapshot ID and `complete` status. A failed target can still have a snapshot ID: `partial` and `unknown` are not restorable through Bakabel. A multi-target run is not atomic.

Finish setup by performing and verifying an independent [restore drill](docs/restore.md). Leave retention disabled until that proof and explicit operator approval.

## Operator guides

- [Configuration and credential references](docs/configuration.md)
- [Source labels and support limits](docs/sources.md)
- [Compose / Swarm deployment examples](docs/deployment.md)
- [Independent restore and verification](docs/restore.md)
- [Scheduling, retention, failures and monitoring](docs/operations.md)
