# Current-candidate B4/B5 outer-rootless fixtures

Disposable synthetic acceptance/resource evidence, not deployment tooling. No Go/core/config/Dockerfile edits, daemon relay, host Swarm initialization, source stop/restart/scale, global prune or private production-volume access. Source discovery may list inventory; all subsequent inspection/process sampling/mounts are constrained to exact new fixture scope and durable worker identity.

## Required paths and image

- Existing isolated `--source` tree, including `PLAN.md`, `Dockerfile`, Go/module files.
- Existing unmodified upstream `--minio-binary` (launched only by the mixed lifecycle runner; failure runners fingerprint it only).
- Explicit `--image` ordinary current candidate, already present in the selected rootless daemon.
- NEW `--runtime` directory; never reuse a prior attempt or an existing backup destination.
- Optional explicit Unix `--socket`; otherwise the Docker CLI's selected context is used.
- Cached images `postgres:18.6-alpine3.24`, `restic/restic:0.18.1`, `golang:1.26.8-bookworm`. Only PG is launched as a fixture/helper; app Restic is taken from the actual candidate image. Helper image sizes are separately labeled, not merged into runtime image footprint.

```sh
IMAGE=bakabel-development:resource-candidate
SOURCE=/absolute/path/to/isolated/work
MINIO=/absolute/path/to/upstream/minio
RUN="$TMPDIR/new-bakabel-capped-run"

taskset -c 0,1 python tests/integration/fixtures/run_resource_probe.py \
  --source "$SOURCE" --runtime "$RUN" --image "$IMAGE" --minio-binary "$MINIO"
taskset -c 0,1 python tests/integration/fixtures/summarize_resource_probe.py \
  --runtime "$RUN" --output "$RUN/summary.json"
taskset -c 0,1 python tests/integration/fixtures/verify_resource_probe.py \
  --runtime "$RUN" --source "$SOURCE" --output "$RUN/verification.json" \
  --expected-source-sha256 SOURCE_HASH --expected-image-id sha256:IMAGE_HASH

taskset -c 0,1 python -m unittest discover \
  -s tests/integration/fixtures -p 'test_resource*.py' -v
```

The mixed runner leaves production worker defaults untouched. Current candidate workers have actual 2-CPU quota and 512MiB memory; no fixed CpusetCpus. Verification reads real `cpu.max`, `memory.max` and observed process affinity, not HostConfig alone. The fixture pins exact owned root processes/TIDs to CPUs0,1; PG is gated in a root shell before stock entrypoint/UID change. Rootless affinity has process-birth/independent-exec gaps: quota enforcement is not continuous affinity-from-birth proof.

## Mixed scheduled lifecycle acceptance

1. Real minute cron `serve`: mixed 256MiB random/512-file + 200k-row PG success, durable operation/finishedAt/lastBackupSuccessAt.
2. Independent socketless `health` with RO private state/config/credentials: healthy, no state changes.
3. Next minute reaches actual PG lock-wait. SIGKILL only scheduler; competing `run` is guard-blocked. New `serve` adopts SAME run/worker and byte-identical job/original CreatedAt/deadline, then succeeds when the fixture table lock is released.
4. Unchanged second file snapshot selects the exact parent: 513 files unmodified, zero new data blobs. Streamed S3 tar readback checks every512 payload SHA256s without file restore/full staging.
5. Fresh independent PG target imports actual backup: count/sum/content digest match.
6. Separate18s scheduled run survives scheduler restart but retains its original deadline; source exec/session/worker terminal, owner released, last success unchanged.
7. Scheduler stopped: separate RO/socketless health really reports failed+overdue, not an HTTP/self-monitoring claim.
8. Sources retain StartedAt/RestartCount and read/write availability.

## Controlled failures (separate short PG-only fixtures)

```sh
# Configured16 replacement candidate: UNPROVEN pending one fixed hosted attempt.
# Explicit configuration-small-cap diagnostic. It requires observed actual
# oom_kill and failed-before-source proof; a generic exit1 is NOT accepted.
# A very small cap may fail for another reason or die before a late barrier.
taskset -c 0,1 python tests/integration/fixtures/run_resource_failures.py \
  --source "$SOURCE" --runtime "$TMPDIR/new-early-oom" --image "$IMAGE" \
  --minio-binary "$MINIO" --mode oom --memory-mib 16

# Authorized REAL fault injection, not a production default/configured-early benchmark:
# same ordinary worker starts at effective defaults512MiB (zero=>defaults),
# reaches PG exec_started/lock-wait, then only its exact owned container gets
# Engine update Memory16MiB; actual memory.max and oom_kill must be observed.
taskset -c 0,1 python tests/integration/fixtures/run_resource_failures.py \
  --source "$SOURCE" --runtime "$TMPDIR/new-active-oom" --image "$IMAGE" \
  --minio-binary "$MINIO" --mode oom-active --memory-mib 16

# Actual ENOSPC on an8MiB local-driver tmpfs repository, never host filesystem:
taskset -c 0,1 python tests/integration/fixtures/run_resource_failures.py \
  --source "$SOURCE" --runtime "$TMPDIR/new-enospc" --image "$IMAGE" \
  --minio-binary "$MINIO" --mode enospc

# Use for completed oom-active/enospc receipts; it independently rechecks IDs,
# source/image/frozen-script hashes, kernel counters, source/worker terminal,
# no-complete snapshot readback, original deadline and exact resource cleanup.
taskset -c 0,1 python tests/integration/fixtures/verify_resource_failures.py \
  --source "$SOURCE" --runtime "$TMPDIR/new-enospc" \
  --output "$TMPDIR/new-enospc/verification.json" \
  --expected-source-sha256 SOURCE_HASH --expected-image-id sha256:IMAGE_HASH
```

ENOSPC is injected only AFTER the same real source exec and Restic pipeline reach lock-wait. The fixture fills only its inspected8MiB repository tmpfs with its own known filler, then releases its source lock. Repeated actual one-byte writes on that exact backing return errno28 while the real worker fails. Original full-capacity/zero-free observations and worker bind mapping are preserved. Ordinary `serve` must establish failed-not-complete, source exec terminal, matching sessions0, worker absent and owner release. Only AFTER that exact proof is the known filler removed to allow a normally locked native `restic snapshots --json` readback. No repository packs/index/snapshots/locks are deleted or unlocked. A fully filled repository can otherwise prevent the verifier's own read lock; do not call that a new backup defect or fake an empty list.

OOM failure mode does not relabel generic errors as OOM. If counters miss a short terminal interval, retain the failed attempt; a future replay needs an exact-container Docker oom-event subscription before workload/fault or another authoritative kernel observation, not a weakened counter assertion. Current retained run-oom-01 has actual configured32MiB oom_kill=1 but its old late-barrier harness exited1; run-oom-02 has no positive OOM proof. See the handoff attempt history.

The configured-early `oom` fixture now defaults to fixed16MiB instead of32;
explicit non16 caps are rejected before affinity changes or probe construction.
Hosted selection, producer limit validation and independent inspect/kernel
expectations all require16777216 bytes. This is a fixture correction, not
production tuning or proof that16 will OOM in the required phase. Standalone
`oom-active` remains16, `enospc` remains32, and production remains2CPU/512MiB.
The20s controller-exit wait,3s terminal observation and45s product deadline are
unchanged. Keep the same ordinary image,200000-row source, fresh empty native
Restic repository on128MiB and ordinary swap policy; no injected allocator,
active memory update, cap ladder, corpus change or retry-until-lucky is allowed.
Actual kernel positive `oom_kill`, terminal OOMKilled/Running=false/PID0,
strict intent-only bound owner history, no source/exec identity or dump event,
zero matching sessions, failed-not-complete, empty snapshots, online read/write
source identity, fatal observer errors/quiescence and exact cleanup all remain
mandatory. Existing active512→16 proof is separate. See the [current addendum
and retained failures](../RELEASE_GATE_LEDGER.md#configured-early-oom-fixture-correction).
Configured16 remains **UNPROVEN** until a single fixed exact-revision hosted
attempt and independent artifact/source/image/daemon-bound verification satisfy
every gate. If it fails, retain the failure and diagnose; do not auto-tune.

## Measurement and safety semantics

- `receipt.json`: actual CLI exits/logs, image/source/binary hashes, create specs, durable checkpoints, PG logical I/O/WAL, cleanup. `metrics.json`: exact owned `/proc` and raw kernel/Docker Stats. Failure receipts also retain frozen executed fixture, fast counter samples, source/worker terminal proofs and actual bounded-repository space observations.
- Sampled RSS/PSS aggregates include worker children. Kernel memory.peak is a high-water through last live sample, distinct from actual memory.max and not a universal RAM bound.
- Rootless `io.stat`/Docker physical block counters may be unavailable. Keep them unavailable; PG relation/WAL counters are logical I/O. Ordered content validation may create PG temp spills; report the combined import+verification window.
- Worker rootfs stays RO, `/tmp`64MiB tmpfs, Restic `--no-cache`. State/cache/tmp/log, repository backend, source/target DB and image/helper caches are separate categories. No full local dump/S3 mirror is introduced.
- Actual image-save compressed layers and merged regular-file export/allocation are measured separately; Engine29 store Image.Size is not unpacked footprint. Extract only safe regular members.
- All mutable resources have fresh owner names. Workers require exact durable daemon/ID/name/image/labels. Sampling exit races skip vanished PIDs/cgroups, never fallback-pin unrelated processes.
- Exact container/volume absence is read back after cleanup; synthetic credentials/data/binaries are removed. Failed attempts remain unchanged. No skills/memory are modified by these tests.

Not covered: universal/large-index RAM bounds, scheduler128MiB cap, one-vs-twoCPU comparison, retention/notifications (separate tests), broad B2/B3 CLI matrix, multi-node behavior, or unavailable physical block I/O.
