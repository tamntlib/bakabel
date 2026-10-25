# B3 real isolated Swarm + S3 fixture

This package is opt-in and uses actual Docker Engine, Swarm services/tasks/nodes,
MinIO authentication, Restic 0.18.1, `pg_dump`, and `pg_restore`. It does not mock
Engine or S3 replies. It imports the current core APIs; it is **not** proof of the
parent agent's separately implemented CLI/scheduler integration.

## Reproduce

Run from the repository root. Requires Docker access, Python 3.12+ stdlib,
`taskset` on the host, the existing `golang:1.26.8-bookworm` and
`postgres:18.6-alpine3.24` images (missing images are pulled), and an actual
baseline Restic 0.18.1 executable. No host packages are installed.

```sh
# Only necessary when a compatible MinIO binary is unavailable.
# Downloads checksum-pinned upstream MinIO source and builds it in an owned
# Go container, CGO_ENABLED=0 GOAMD64=v1, taskset 0,1, GOMAXPROCS=2, go -p 2.
python3 tests/integration/fixtures/build_minio.py \
  --scratch "$TMPDIR/bakabel-minio-build-NEW"

python3 tests/integration/fixtures/run.py \
  --restic /absolute/path/to/restic-0.18.1 \
  --minio-binary "$TMPDIR/bakabel-minio-build-NEW/minio" \
  --runtime "$TMPDIR/bakabel-b3-run-NEW" \
  --worker
```

`--runtime` and `--scratch` must not already exist. All state is disposable.
`--worker` adds a second isolated daemon/node to prove rejection of an actual
**running off-node task**; without it that one test explicitly skips. The
ordinary sources are constrained to the manager, so their happy paths still
exercise the supported same-manager contract. No test calls host SwarmInit.

`go test ./tests/integration` without the explicit fixture environment skips
live tests. The runner compiles a static test executable and mounts the source
repository read-only; it makes no application/core/config/state edits.

## Isolation, resource limits, and credentials

- Own `docker:29.6.1-dind` engine containers run `--privileged --cpus 2` beneath
  the **rootless outer Docker daemon**. They use private scratch data roots and
  Unix sockets; actual daemon IDs must differ from the outer daemon before init.
- Outer network is a disposable `--internal` bridge. No `-p`/published host ports
  are used. MinIO binds only loopback **inside the manager network namespace**;
  test runner joins that namespace and inner file workers use inner host network.
  `http://127.0.0.1:9000` is an explicit isolated-fixture URL, not a production TLS
  exception. No global TLS verification setting is changed.
- `vfs`, `--bridge=none --iptables=false --ip-forward=false` avoid assuming
  nested overlay/default-bridge functionality. Nested containers and genuine
  Swarm services ran successfully on this host; no engine emulation was needed.
- Observed rootless warning: `No cpuset support`. Setting a CPU limit on an
  **inner** Swarm service failed with runc:
  `cannot enter cgroupv2 "/sys/fs/cgroup/docker" with domain controllers -- it is in threaded mode`.
  The working fixture does not set unsupported inner cgroup CPU limits. Instead,
  both outer engines' effective `cpu.max` are read back as `200000 100000`.
  Host `taskset` pins engine PID1, and a fixture-only static pre-exec affinity
  helper pins source/worker processes after runc startup. Actual source PG PID1
  affinity is read back as `0-1`. Builds and test runner use `taskset -c 0,1`.
  This is **not** a claim that rootless cpuset enforcement works, that every
  Docker exec retains source PID1 affinity, or that source load is limited by a
  separate worker cgroup. Nested execs remain within their outer engine quota.
- Synthetic provider credentials live in files. MinIO directly reads
  `MINIO_ROOT_USER_FILE` / `MINIO_ROOT_PASSWORD_FILE`; Restic uses
  `AWS_SHARED_CREDENTIALS_FILE` and `RESTIC_PASSWORD_FILE`. Neither provider keys
  nor decryption password are placed in argv or Engine `Config.Env`.
- Each file worker receives an **explicit read-only credential bind mount**;
  source mount RO flags and credential RO flags are inspected and asserted.
  Nothing assumes API-created workers inherit Swarm Secret mounts. A production
  operator must provide a trusted node-local RO credential-file volume/bind at
  the path the worker explicitly mounts. Scheduler/worker user ownership must
  match. This fixture's disposable synthetic files are mode 0444 inside a RO
  mount to permit the deliberately UID 1234 unreadable-file probe; this is not
  production credential-permission guidance.
- Explicit fixture-operator `restic init` creates the S3 bucket through the real
  MinIO API (Restic's backend calls MakeBucket) and initializes the repository.
  Core backup does **not** initialize inaccessible/missing repositories.
- Shared images are not pruned. Only exact owned IDs are deleted/read back.
  Inner manager cleanup is read back as zero containers/services/volumes; owned
  outer containers/network and private secrets/data/binaries/destination are
  removed. Metadata-only artifacts and test/result logs remain. The original
  outer Swarm stays inactive.

## What the tests prove

| Test | Actual evidence |
|---|---|
| `TestSwarmServiceMetadataAndPlacement` | Service/deploy opt-in labels (absent from task-container opt-in labels), tasks resolved to the same manager; adding files metadata changes discovered target count without a target list; replica 0/2, global mode, unschedulable placement, unsupported type, traversal, missing mount are rejected. Invalid-path services first reach running, avoiding false attribution to startup/pending errors. |
| `TestRealSwarmTaskReplacementInvalidatesFrozenSource` | Real service ForceUpdate replaces a task; logical source ID stays stable while old physical source/volume access is refused. |
| `TestRealOffNodeRunningTaskRefused` | Second real engine joins the isolated Swarm; service runs there, container is absent on the manager, and discovery returns unsupported placement. |
| `TestS3CredentialAndMissingRepositoryFailures` | Correct credential files read the real S3 repository; wrong key produces provider InvalidAccessKeyId; wrong Restic password and absent prefix fail. Restic retries InvalidAccessKeyId rather than treating it permanent, so the fixture deliberately cancels its retry loop after bounded deadlines and checks the actual provider diagnostic, not timeout alone. |
| `TestSwarmS3StreamingPostgresIndependentRestore` | 20,000 rows streamed from genuine online Swarm PG18.6 via `CreateDump`/`StreamDump` into `Repository.Backup --stdin-from-command`; exact complete S3 snapshot read back; independent writer finishes 100 updates; source StartedAt unchanged and RestartCount 0; missing-repo Backup fails without init. Source service/container and export checkpoint are removed before a separate PG cluster is created. Wrong DB owner/ACL is refused before exec checkpoint; operator prepares prerequisites; `restore.RestorePostgres` streams from S3 and verifies reader/import terminal success. Count/sum/ordered-content digest, object owners/ACL and DB owner/normalized ACL match; cluster identity differs. |
| `TestSwarmS3FilesCompleteUnknownPartialRestore` | Real local volume mounted RO to API-created worker, Restic reads directly to S3 without tar/staging. Complete readback; deliberately failing source postflight retains repository unknown; actual unreadable file under UID 1234 yields Restic exit 3 and exact partial receipt. Unknown/partial are refused by file restore preflight without changing destination. Source container removed; complete snapshot restored into a separate empty directory with 4,194,323 bytes, mode 0640, UID 1234/GID 2345. |
| `TestPinnedResticBaseline` | Actual executable reports Restic 0.18.1 and runs on the exposed CPU baseline. |

No full local repository mirror or PG dump is created in the worker/runner.
Only small JSON metadata/checkpoint/inspect files appear in `artifacts/`; the
harness inventories their sizes/hashes and rejects unexpected/large files.
The MinIO service's own disposable storage is the S3 fixture backend, not a
second mirror made by the application. Restored destination capacity is separate.

## MinIO availability and provenance

Actual attempts on this host:

- `docker pull minio/minio:RELEASE.2024-01-18T22-51-28Z`: pull access denied.
- Docker Hub `RELEASE.2024-10-29T16-01-48Z-cpuv1`: pull access denied.
- Quay corresponding tags: manifest HEAD returned 401 unauthorized.
- `https://dl.min.io/server/minio/release/linux-amd64/archive/minio.RELEASE.2024-01-18T22-51-28Z`: HTTP 410.
- `public.ecr.aws/bitnami/minio:2024.1.18`: not found.

Therefore this fixture builds the **unmodified upstream MinIO release source**
from GitHub instead of inventing a successful pull or using a fake provider:

```
https://codeload.github.com/minio/minio/tar.gz/refs/tags/RELEASE.2024-01-18T22-51-28Z
sha256 267c949e03f6d931f3b2da07c067f02483cb2b2604b627e1eb9b96acb0fd9192
```

The upstream default version string is honestly retained as `DEVELOPMENT.GOGET`
with Go 1.26.8. Source archive checksum and actual static binary checksum identify
the artifact; it is not misrepresented as an official release image. No MinIO
image was published. `build_minio.py` and the resulting binary were both exercised.

## Handoff to CLI integration

Core API seams are visible in `../swarm_s3_test.go`:

- `docker.NewClient(socket)` -> `Discover(DiscoveryOptions{Platform:"swarm",...})`.
- Frozen `Target.Source` + `Target.Database` -> `PreparePostgresDatabase` ->
  durable fixture intent/checkpoint -> `CreateDump` -> real executable helper
  `StreamDump` -> `Repository.Backup` -> exact `Snapshots`/`Restorable` readback.
- `PrepareFileVolume` -> RO mount at `files.WorkerPath` -> `files.Capture` ->
  `files.Backup`; restore `files.OpenRestore`/`Restore` to an explicit empty path.
- `restore.RestorePostgres` receives only repository/snapshot, target daemon,
  literal database/user and a durable restore-exec checkpoint callback.
- `run.py` owns engine setup, private transports, credentials and cleanup. CLI
  can replace the test runner call while retaining these real fixtures. A CLI
  runner must join the manager network namespace, mount only its isolated socket,
  use the explicit RO credential bind, and preserve the source physical identity
  and exact repository snapshot checks. The internal producer here is a test
  executable, **not** evidence that the CLI `_export` path has been integrated.

Compose replica-zero discovery limitation is unchanged: Docker container-only
Compose discovery has no persisted service registry for services with zero
containers. This fixture does not invent such a registry or claim that case.

## Deliberately not proved here

- Parent CLI `plan/run/snapshots/restore`, scheduler/serve/restart/adoption and
  production deployment examples/Swarm Secret delivery integration.
- S3 upload outage/disconnect/worker SIGKILL/source-export cancellation matrix,
  crash at the tag-finalization boundary, retention, disk-full behavior, large
  repository/resource peak accounting, or custom/network volume drivers.
- Whole-cluster PostgreSQL roles/globals/PITR or application verification beyond
  the fixture queries. Roles and database owner/ACL prerequisites are operator
  setup, not automatically repaired by Bakabel.
- A changed-worker second file backup's parent/zero-reread metrics are covered by
  the separate existing B2 fixture, not asserted by this B3 package.

See the result evidence selected by the parent for exact daemon/node/snapshot
IDs, image digests, SHA-256 values, cleanup readbacks and command output.
