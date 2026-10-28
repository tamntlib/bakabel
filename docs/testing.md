# Testing

Bakabel has offline regression tests, opt-in local integration fixtures and a
manual GitHub-hosted acceptance workflow. They answer different questions:
unit Engine seams are not real-daemon fault evidence, a selected fault is not a
full suite, and fixture success is not production certification. Run commands
from the repository root unless stated otherwise.

## Safety and prerequisites

- Use only disposable synthetic data and credentials. Do not read `.env`, pass
  credential values in arguments/labels, or mount production volumes. Keep raw
  runtime directories and private files outside the checkout and out of uploads.
- A Docker socket is root-equivalent even when mounted read-only. File-restore
  preflight inventories consumer backing storage; **never run its acceptance
  probes on a shared production daemon**. Use an exclusive disposable daemon
  whose entire storage topology is in scope.
- The supported adapter baseline is Linux Docker Engine **29.6.1**, direct API
  **1.55**; older API negotiation is not implemented. Hosted acceptance uses
  rootful Docker, cgroup v2, and **containerd image storage enabled**. The setup
  action's daemon config is `{"features":{"containerd-snapshotter":true}}`.
  Use its **returned socket**, not the machine's default Docker context: remove
  only an initial `unix://` when passing a socket filesystem path to Python;
  set `DOCKER_HOST=unix://<returned path>` for Docker CLI commands.
- Keep AppArmor/security policy, native Restic locks, ordinary image, worker
  ceilings and product deadlines intact. Do not use an unconfined profile,
  disable AppArmor, strip resource fields, filter consumer inventory, force
  unlock, or restart sources to obtain a passing result. Unsupported runtime
  prerequisites are failures, not permission for a workaround.
- Production worker resource defaults and fixture workload quotas apply to
  workers, not to build/test machines. The commands below impose no fixed CPU
  affinity or build parallelism policy. Check actual kernel enforcement of the
  worker ceilings rather than trusting requested Docker limits.
- Require fresh, nonexistent runtime/output directories, exact source/image
  identities and explicit cleanup ownership. Read back exact container/volume
  absence and private-path removal. Never broad-prune shared caches or resources.
  Fixture teardown is not proof that an export/import had already terminated.

## Offline regression tests

Use Python 3.12+. These commands need no Docker daemon, network or
production credentials. Some tests use real disposable child processes, Unix
sockets and Linux tracing/permission facilities; their prerequisites and skips
remain visible in the output.

```bash
python3 -B -m unittest discover \
  -s tests/integration/fixtures -p 'test_*.py' -v
python3 -B -m unittest discover \
  -s tests -p 'test_*.py' -v
```

The documentation tests execute only guarded setup fragments against disposable
files and a failing Docker stand-in. Release tests use synthetic GitHub/GHCR
responses; neither suite builds, publishes or deploys Bakabel.

For Go, use the toolchain pinned in [go.mod](../go.mod) and the
[CI workflow](../.github/workflows/ci.yaml). With dependencies already cached:

```bash
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  go test -race -count=1 -v ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
  go vet ./...
```

Missing cached dependencies fail rather than downloading in this offline
example. Real-Restic tests require the pinned **Restic 0.18.1** executable.
CI mounts it at `/usr/bin/restic` and sets both
`RESTIC_TEST_BINARY=/usr/bin/restic` and
`BAKABEL_FILES_RESTIC=/usr/bin/restic`; root ACL tests also need the CI capability
setup. A green Go run with these tests skipped is not equivalent coverage.
Opt-in Docker integration tests skip without their explicit fixture environment;
ordinary `go test` success is not hosted acceptance.

## Full GitHub-hosted acceptance

Use [Manual acceptance](../.github/workflows/acceptance.yaml) in GitHub Actions:
**Run workflow → reviewed branch/ref → scope `all` → case `all`**. This is the
mandatory full **ALL** run for acceptance, not a PR-triggered privileged job.
Confirm the checked-out commit is the intended reviewed revision.

Prerequisites are a fresh standard `ubuntu-24.04` GitHub-hosted **x86-64 VM**,
rootful Engine 29.6.1/API 1.55 with containerd image storage, cgroup v2, no
containers, inactive Swarm, at least **4 GiB RAM** and **12 GiB free
scratch**. Runners require root, a fresh child of `RUNNER_TEMP` and explicit
`--exclusive-hosted-daemon`. They refuse local/shared/self-hosted invocation
before opening the socket. Never spoof GitHub environment variables on a VPS.
The exclusivity flag does not bypass admission.

The selection job validates inputs before provisioning. Full ALL runs three
independent acceptance VMs, with `fail-fast: false`:

| Suite | Entry point | Expected scope |
|---|---|---|
| `core-resources` | `run_hosted_acceptance.py`, then `run_hosted_resources.py` | Compose and Swarm × local and authenticated S3 × PostgreSQL and files; scheduled lifecycle plus OOM/repository-space failures. |
| `capacity` | `run_hosted_capacity.py` | Larger mixed repository, unchanged and changed rounds, full data readbacks and independent PG restore. |
| `faults` | `run_hosted_faults.py`, then `run_hosted_storage_prereqs.py` | All **19** named fault cases and all **3** storage/prerequisite cases; neither suite is optional. |

All entry points are in [tests/integration/fixtures](../tests/integration/fixtures).
The workflow is the copyable runtime orchestration: it installs the pinned
Engine on the disposable VM, uses the returned socket, fetches pinned tools,
builds the ordinary Dockerfile image, and passes actual source hash/image ID to
every runner. Do not transplant those privileged commands to a shared host.

### Core and resource expected results

- Public `plan`, `run`, `snapshots`, `restore` and ordinary `_workflow` workers
  exercise online mixed backup without stopping/restarting/scaling sources.
  Swarm labels are on service objects, not duplicated onto task containers;
  actual task/node/daemon identity is checked. Swarm PG listens only on host
  loopback `127.0.0.1`, checked by SQL; no external database port is published.
- Both backends restore after source containers/volumes and old backup state
  have been removed. A different PG cluster/role OIDs must pass full data,
  object owner/ACL and operator-prepared database owner/ACL checks. Wrong
  prerequisites and an empty original source DB alias must be refused.
- File restore to a separate empty directory and unused option-free local volume
  must match bytes, mode `0640`, numeric UID/GID `1234:2345`. Physical source and
  consumer aliases, unsupported same-backing volume options, and unknown/partial
  snapshots must be refused before writes. Core status-refusal tests use real
  Restic retagging; they do not prove native backup exit 3.
- A second unchanged file backup must select its exact parent, add no new file
  data and pass full payload readback. Worker SIGKILL and actual S3 outage must
  fail without falsely complete PG snapshots. Exact export/session termination
  precedes ownership release. Earlier complete targets may survive a failed
  mixed run: a multi-target backup is not atomic.
- Scheduler tests use real minute cron, socketless/read-only health, same-worker
  adoption with byte-identical job/original deadline after scheduler kill, no
  overlap, failed/overdue reporting and unchanged last successful backup time.
  Source start/restart identities and read/write availability remain unchanged.
- Resource cases separately test **configured early 16 MiB OOM**, an ordinary
  **512→16 MiB** limit injection during PG lock-wait, and an owned **8 MiB**
  repository tmpfs ENOSPC. Positive exact-worker kernel `oom_kill` and terminal
  OOMKilled proof are required, not generic exit 1. Early OOM requires intent-only
  ownership, no source exec/dump event, zero matching sessions, failed result and
  empty snapshots; it is not supported low-memory export sizing. Preserve the
  fixed corpus, cap, ordinary swap policy and 20s/3s/45s observation/job windows;
  do not auto-tune, retry until lucky or substitute active injection.
- Repository ENOSPC requires repeated actual errno 28 on the inspected backing
  while the pipeline fails. Keep pressure until exact source/worker terminal and
  ownership proof. Remove only known fixture filler afterward so a normally
  locked snapshot listing can run; do not delete packs/indexes/locks or invent
  an empty result. Repository ENOSPC does not prove worker-temp/output ENOSPC.

### Capacity scope

The bounded corpus is **1 GiB / 8,192 files plus 400,000 PostgreSQL rows**. The
changed round replaces **1,024 files / 128 MiB**. Require real distinct
index/data growth, exact unchanged-parent reuse, native repository check, full
original and changed checksum sets read back without local archive staging,
fresh-target PG content/owner/ACL verification, online source identity and exact
cleanup. The smaller lifecycle workload is **256 MiB / 512 files plus 200,000
PG rows**; neither corpus establishes arbitrary repository scale. See
[resource sizing and limits](resources.md).

### Fault scope and expected results

| Cases | Required distinction |
|---|---|
| `producer-failure-after-output`, `streaming-worker-SIGKILL`, `docker-stream-drop` | Real partial output/stream interruption, no false completion, exact source-terminal proof before release. |
| `docker-stream-drop-status-unavailable-recovery` | Unavailable status keeps quarantine through a fresh scheduler; release only after subsequent exact terminal proof. |
| `worker-create-response-loss`, `worker-start-response-loss`, `dump-create-response-loss`, `dump-start-response-loss`, `restore-create-response-loss`, `restore-start-response-loss` | Actual side-effect/response-loss boundaries; no create/start retry. Lost create identity can require durable quarantine, not invented recovery. |
| `backup-vs-restore-and-retention`, `scheduler-restart-original-deadline` | Public overlap refusal and same job/worker/original deadline; no standalone maintenance CLI is implied. |
| `dump-persisted-before-start-worker-SIGKILL` | Kill after ID persistence, before start forwarding; preserve the exact unresolved quarantine. This is not terminal exec/ownership-release proof. |
| `restore-active-import-worker-SIGKILL` | Actual live import/COPY, independent import token, terminal import/session/process proof before release; failed partial target retained. Recovery by the original controller is not a fresh-controller restart test. |
| `restore-reader-failure-importer-zero` | Control and fault both have actual importer exit zero and full 300,000-row digest. Native reader control exits zero; fault reader is killed at its real `exit_group(0)` boundary. Public fault must fail despite valid imported data; preserve target and last backup success. |
| `restic-native-exit3` | Kernel-denied native read after real progress, actual Restic exit 3, full snapshot ID **and** error, fresh-state partial/unknown classification and pre-write restore refusal. No chmod/root-DAC assumption or retag substitute. |
| `unknown-commit-before-finalize-worker-SIGKILL` | Hold real committed-snapshot readback, independently classify exact unknown ID, kill authorized worker before finalize; preserve that unknown snapshot through fresh-state listing. |
| `finalized-before-report-worker-SIGKILL` | Hold result-temp creation after final complete readback, retain old/new IDs, then kill worker before report. Overall run fails; recovered target may correctly remain complete. |
| `file-truncate-during-native-read` | Hold native read after positive descriptor progress, truncate only owned payload, release read and retain actual native disposition. No predetermined success/failure or application-consistency claim. |

Storage/prerequisite cases use `run_hosted_storage_prereqs.py` and its separate
verifier:

- `temp-pack-ENOSPC`: fill only the pinned worker's original **64 MiB `/tmp`**.
  Require traced Restic temp-pack/index `write`/`pwrite64`/`writev` errno 28 and a
  separate same-backing probe; repository is a different device. Keep pressure
  through terminal proof, no complete snapshot. `--no-cache` remains in use.
- `restore-output-ENOSPC`: restore a real **32 MiB** file to an initially empty
  owned **8 MiB** output tmpfs. Require actual output-file write errno 28,
  failed public restore, retained allocated partial target and unchanged source
  checksum/incarnation. The probe inode is unlinked while its FD stays open so
  the destination really is empty; there is no product emptiness exception.
- `restore-missing-extension-binary-prerequisites`: hide only the owned target's
  `hstore.so`, retain its control file, and require actual failed native import.
  Restore the identical library, then retry the **same** fresh database/target
  without restart, repair, pre-CREATE EXTENSION or database replacement. Require
  successful native reader/import, 300,000-row extension-dependent digest,
  extension function/version and object/database owner/ACL readback. Missing
  roles or an already-installed extension are not substitutes.

Native permission cases require host `fanotify_init`/`fanotify_mark` permission
support and CAP_SYS_ADMIN. Marks are limited to owned payload/repository/output
objects; bounded queues/holds, exact inode/device and authorized worker identity
are mandatory. Queue overflow, expired holds or identity drift fail, not skip.
Reader tracing needs root CAP_SYS_PTRACE/permitted ptrace, pidfds,
`PTRACE_GET_SYSCALL_INFO`, x86-64 and visible host PIDs/cgroups. Storage tracing
needs installed `strace` and permitted attachment. No source agent, replacement
Restic binary, source-image install or host security-policy change is allowed.

The hstore failure verifier distinguishes complete EOF/exact diagnostics from a
narrow first-failed-import native fatal-prerequisite witness after upstream
reset. The latter retains `stderr_complete:false`, `total_error_count:null` and
original aborted capture; it proves an encountered native fatal prerequisite,
not a sole cause or complete stderr. Exact production command/environment/image
provenance, terminal import, quiescent observers, no target clients and unchanged
catalog are required before restoring only the library. It never substitutes
for the independent successful same-database retry or another fault case.

### Isolated diagnostic cases are not ALL acceptance

Use **scope `remaining-faults`, case `all`** only for seven independent F16–F22
VMs. Use **scope `single-fault`** with one workflow-listed case for one fresh VM.
The workflow also permits isolated reader-failure and unavailable-status recovery
cases. Bulk scopes reject a named case; `single-fault` rejects `all`.

`verify_hosted_selection.py` requires an exact one-case manifest, candidate
commit/source/image/daemon binding and the selected actual case verifier. A
scoped `selected_case_pass` must keep `fault_acceptance_pass` or
`storage_acceptance_pass` **false**, and `full_plan_acceptance_pass` **false**.
Even several green isolated cases do not replace a fresh full **all/all** run.

## Evidence and interpretation

- Acceptance requires runtime receipts **and** the corresponding verifier output:
  `verify_hosted_acceptance.py`, `verify_hosted_capacity.py`,
  `verify_hosted_faults.py`, `verify_hosted_storage_prereqs.py`, or the scoped
  selection verifier. `run_hosted_resources.py` orchestrates its resource
  summarizer/verifiers. Review their actual predicates; none is a universal
  integrity, availability or security certificate.
- Bind evidence to the actual checkout commit, core fingerprint, ordinary image
  ID, daemon and frozen runner/verifier bytes. A build, earlier PASS line or
  workflow success alone is not proof of all later gates. Changed production
  code needs a fresh build/acceptance; old images are not retroactively secured.
- Workflow artifacts `acceptance-<suite>-<commit>-<attempt>-<scope>-<case>` last
  **seven days**. Export only explicit projected receipts/candidate/verifier
  fields. Do not upload raw commands, Env/specs, stderr, state, repositories,
  private files, trace dumps or raw private metrics. Verify downloaded digests
  and receipt bindings; offline artifact review is not live Engine readback.
- Cleanup runs in `finally`, with exact owned absence readback required for
  acceptance. Abruptly killed/timed-out jobs cannot claim cleanup PASS; setup
  teardown and disposal of the entire VM are the final containment boundary.
  Keep failed/unknown attempts as failed/unknown; a later passing revision does
  not rewrite them. Resource projections cannot recreate unavailable private
  raw observations. Missing counters are not zeros.
- Existing JSON names such as `full_plan_acceptance_pass` are legacy evidence
  fields, not a reason to infer universal acceptance. Successful bounded suites
  still do not prove production readiness, physical I/O, universal RAM or RTO.
  Publishing is a separate gated process; see [releasing](releasing.md).

## Optional local integration fixtures

These are development tools, not an alternative release gate. Review each
runner before use and keep any configured source/image admission pins intact;
rejection of a different source is not permission to update a pin mechanically.
Use explicit verified binaries, nonexistent runtime directories, synthetic
credentials, and the same isolation/cleanup rules above.

### Isolated Swarm/S3 core API fixture

[run.py](../tests/integration/fixtures/run.py) requires Python 3.12+,
Docker, pinned Go/PostgreSQL/DinD images and Restic 0.18.1. Missing images may be
pulled. [build_minio.py](../tests/integration/fixtures/build_minio.py) downloads
unmodified upstream `RELEASE.2024-01-18T22-51-28Z` source with archive SHA256
`267c949e03f6d931f3b2da07c067f02483cb2b2604b627e1eb9b96acb0fd9192`
and builds `CGO_ENABLED=0 GOAMD64=v1`. The resulting `DEVELOPMENT.GOGET` string
is not an official release image or a production backend recommendation.

```bash
python3 tests/integration/fixtures/build_minio.py \
  --scratch "$TMPDIR/bakabel-minio-build-NEW"
python3 tests/integration/fixtures/run.py \
  --restic /absolute/path/to/restic-0.18.1 \
  --minio-binary "$TMPDIR/bakabel-minio-build-NEW/minio" \
  --runtime "$TMPDIR/bakabel-swarm-run-NEW" --worker
```

`--worker` adds a second isolated daemon/node for actual off-node refusal; without
it that test skips. The fixture never initializes outer-host Swarm, publishes
ports or reads production volumes. It uses owned internal networking, explicit
read-only credential files and real API/S3 replies. Core tests cover service
labels/replicas/placement, task replacement, wrong credentials/password/missing
repository, online PG independent restore, and actual unreadable-file exit 3.
These core API tests do not certify the public CLI/scheduler.

The rootless nested variant runs privileged owned Engine containers under an
outer quota. Unsupported inner CPU cgroups are an explicit functional-test
limitation, not individual worker resource-enforcement proof. It must not replace direct hosted acceptance.

### Isolated public CLI fixture

[run_cli_acceptance.py](../tests/integration/fixtures/run_cli_acceptance.py)
requires locally available `docker:29.6.1-dind`, `postgres:18.6-alpine3.24`, an
ordinary image built from the supplied Dockerfile, and explicit MinIO/Restic
binaries. Build using the [README](../README.md) instructions, then:

```bash
python3 tests/integration/fixtures/run_cli_acceptance.py \
  --runtime "$TMPDIR/bakabel-cli-acceptance-NEW" \
  --image bakabel:local \
  --minio /absolute/path/to/verified/minio \
  --restic /absolute/path/to/extracted/restic
```

This fixture uses a CPU-only relay after proving the inner daemon differs from
the host and its outer-quota admission checks pass. The quota is a
nested-fixture parameter, not build/test machine policy. It omits only
ContainerCreate `NanoCpus`, `CpusetCpus`, `CpusetMems`, logging every omission;
no identity/task/inventory/ACL responses are altered. It proves functional CLI
behavior under the outer aggregate quota, **not** production inner cgroup
limits. Hosted acceptance does not permit that relay. Save/load can change an
outer containerd index ID to an inner classic-store config ID; the fixture reads
and freezes the actual loaded ID, never invents one. It covers local/files and
Swarm/S3 mixed backup/independent restore, aliases/status refusal, worker kill
and provider outage, not the complete scheduler/capacity/fault matrix.

`run_compose_pg_acceptance.py` is a separate Compose local/S3 subset with no
public file restore or Swarm. It requires `--source`, `--runtime`, `--image` and
`--minio-binary`; matching counts do not make it the full CLI matrix.

### Local lifecycle/resource diagnostics

`run_resource_probe.py` uses an isolated source tree, explicit ordinary image,
verified MinIO, fresh runtime and optional explicit Unix `--socket`. It measures
the small mixed lifecycle workload described above. Cached PG/Restic/Go helper
images are separate overhead, not product image contents. Example after setting
`SOURCE`, `IMAGE`, `MINIO`, `RUN`, and the actual bound `SOURCE_HASH`/`IMAGE_ID`:

```bash
python3 tests/integration/fixtures/run_resource_probe.py \
  --source "$SOURCE" --runtime "$RUN" --image "$IMAGE" --minio-binary "$MINIO"
python3 tests/integration/fixtures/summarize_resource_probe.py \
  --runtime "$RUN" --output "$RUN/summary.json"
python3 tests/integration/fixtures/verify_resource_probe.py \
  --runtime "$RUN" --source "$SOURCE" --output "$RUN/verification.json" \
  --expected-source-sha256 "$SOURCE_HASH" --expected-image-id "$IMAGE_ID"
```

For separate disposable failure diagnostics, `run_resource_failures.py` accepts
those source/runtime/image/MinIO inputs and `--mode oom --memory-mib 16`,
`--mode oom-active --memory-mib 16`, or `--mode enospc`. Use a new runtime for
each. Hosted wrappers enforce the fixed early-OOM semantics above. Completed
active-OOM/repository-ENOSPC runs use `verify_resource_failures.py` with
`--source`, `--runtime`, `--output`, `--expected-source-sha256` and
`--expected-image-id`; an exit alone is not proof. Do not combine historical
failed configured caps with a later injected OOM to claim a passing early case.

`receipt.json` holds command/results/bindings and `metrics.json` holds raw local
observations; summaries distinguish sampled RSS/PSS from kernel high-water,
limits and logical PG/WAL counters. Rootless physical I/O may be unavailable.
Inspect actual enforcement; never treat named-file temp size as total tmpfs use
(open-unlinked Restic packs also consume it). No local fixture result proves
universal memory, large-data RTO or all supported storage topologies.
