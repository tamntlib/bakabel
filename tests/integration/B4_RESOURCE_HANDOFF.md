# Current-candidate B4 lifecycle / B5 capped-failure-resource handoff

## Outcomes and bindings

- `run-capped-01`: real mixed scheduled lifecycle **exit0**, all8 gates independently verified. **Actual512MiB cap**, not the old uncapped baseline.
- `run-oom-active-01`: distinct real injected mid-run exhaustion **exit0**, independent verifier **exit0**. Same ordinary worker starts512MiB, establishes exact PG exec/lock-wait, then authorized exact-worker Engine update lowers memory to16MiB. Actual memory.max changes and oom_kill=2, failed-not-complete, source terminal/session0/owner released.
- `run-enospc-04`: actual bounded-repository ENOSPC **exit0**, independent verifier **exit0**. Same inspected8MiB tmpfs backing is full during the real backup;6282 actual one-byte write attempts return errno28; failed-not-complete, source terminal/session0/owner released. Native normally locked snapshot readback returns `[]` after only the known fixture filler is removed, after terminal proof.
- Explicit32MiB configured-worker exhaustion was **actually observed** in retained `run-oom-01` (memory.max33554432, oom_kill1, Engine OOMKilled=true), before observed source startup. Its harness later failed waiting for an unreachable late barrier; **that invocation remains exit1**, not relabeled PASS. `run-oom-02` has no positive OOM proof and remains failed/undetermined. Do not conflate either with the successful injected active-source case.
- Targeted fixture tests: **10 PASS**, exit0. Parent's fullrace/vet/other Python results were supplied context, not rerun here.

Frozen source fingerprint: `2fd683f92a52b244ac452356cb4fd6de3567366348259ece09619c912e8b07ee`.

Exact ordinary image: `bakabel-development:resource-candidate`, Id `sha256:ff1a6cd8e122b14c80da66396c6d14f06c22cc4c130e769def3a50520e9afca8`.

No Go/core/module/config/Dockerfile/CI changes, image rebuild/relay, skills/memory edit, Git/publication, production-volume access, global prune, host Swarm init, or source stop/restart/scale. Old `run-final-03` under the previous scratch root remains unchanged and is **not current-candidate evidence**.

## Exact artifact root / commands / exits

```sh
ROOT=/home/tamnt/.hermes/cache/scratch/bakabel-final-resources-a5i0v7sq
WORK=$ROOT/work
IMAGE=bakabel-development:resource-candidate
MINIO=/home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/minio-build-proof/minio
SOURCE_HASH=2fd683f92a52b244ac452356cb4fd6de3567366348259ece09619c912e8b07ee
IMAGE_ID=sha256:ff1a6cd8e122b14c80da66396c6d14f06c22cc4c130e769def3a50520e9afca8

# Actual complete mixed invocation, exit0; never reuse this runtime directory:
taskset -c 0,1 python tests/integration/fixtures/run_resource_probe.py \
  --source "$WORK" --runtime "$ROOT/run-capped-01" --image "$IMAGE" --minio-binary "$MINIO"
# Actual derivation and independent verification, both exit0:
taskset -c 0,1 python tests/integration/fixtures/summarize_resource_probe.py \
  --runtime "$ROOT/run-capped-01" --output "$ROOT/run-capped-01/summary.json"
taskset -c 0,1 python tests/integration/fixtures/verify_resource_probe.py \
  --runtime "$ROOT/run-capped-01" --source "$WORK" --output "$ROOT/run-capped-01/verification.json" \
  --expected-source-sha256 "$SOURCE_HASH" --expected-image-id "$IMAGE_ID"

# Actual distinct fault runs, each exit0:
taskset -c 0,1 python tests/integration/fixtures/run_resource_failures.py \
  --source "$WORK" --runtime "$ROOT/run-oom-active-01" --image "$IMAGE" \
  --minio-binary "$MINIO" --mode oom-active --memory-mib 16
taskset -c 0,1 python tests/integration/fixtures/run_resource_failures.py \
  --source "$WORK" --runtime "$ROOT/run-enospc-04" --image "$IMAGE" \
  --minio-binary "$MINIO" --mode enospc
# Same verifier invocation was executed for EACH of the two runtime paths, exit0:
taskset -c 0,1 python tests/integration/fixtures/verify_resource_failures.py \
  --source "$WORK" --runtime "$ROOT/run-enospc-04" \
  --output "$ROOT/run-enospc-04/verification.json" \
  --expected-source-sha256 "$SOURCE_HASH" --expected-image-id "$IMAGE_ID"

taskset -c 0,1 python -m unittest discover \
  -s tests/integration/fixtures -p 'test_resource*.py' -v #10 tests, exit0
```

Each runtime has actual `receipt.json` and `metrics.json`; successful runs have independent `verification.json`. Mixed run additionally has `summary.json`. Failure runs02 onward retain `executed_failure_probe.py`, hash-bound in the receipt, because fixtures evolved between attempts. Raw CLI commands/exits/output and kernel samples are in receipts, not reconstructed output. `$ROOT/FAILURE_DIAGNOSIS.md` gives exact early-OOM phase/counter timestamps and limits; `$ROOT/all-attempts-cleanup-readback.json` rereads every exact target across all8 attempts.

### Receipt / raw-metrics SHA256 bindings

| Run | receipt.json | metrics.json |
|---|---|---|
| capped01 | `162745ac42cbbae578ed2162f1cd0d21eaa1845ab4900749e9739bb3dbc64869` | `dc9c9f708fa4c8ad0f2c5f27ecdef13ac9f1489418587b5d168e63974c6f5a39` |
| activeOOM01 | `d2bf3fbeaf396ee25a48a381b4741098889962fe39dd00b207387b7e1d8651a9` | `499af6596739262598ff7011ba1cf73c3280823232ae345d34537e3bcf85f0e6` |
| ENOSPC04 | `fd4db1607fdc7383550c876be6af706c7c5cbcfa799164ba57041fd903f4a694` | `31f43f08e748fdac561406d1f44f97df614547dcc7fc820cfed2b9f65b072483` |

Runtime Bakabel SHA256 `710d72cf61dda0cda13e3b3a006d7904c3647016610c4de5c5635dd23bf50bce`; Restic0.18.1 `01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6`; unmodified MinIO `8d95c686a61111ed8a0e38a80b84423b164ef07499fe87416b1302a4e6f550e0`. Mixed executed probe SHA256 `b0d584040e1c52776ffbe1fac5be3d14e882cd387ca7b739a247fcb6befd7764`.

## B4 acceptance under the current actual cap

Real UTC minute cron produces mixed files/PG success and durable operation/finishedAt/lastBackupSuccessAt. Independent socketless RO health exits0 healthy without changing state bytes. Next scheduled run waits in real PG dump; source read/write to another table remains available. Exact scheduler SIGKILL leaves the SAME worker alive; concurrent `run` exits1 with launcher guard held; replacement `serve` adopts unchanged job/original CreatedAt/timeout and that same worker/run, then completes successfully after releasing only the fixture table lock.

Separate18s job repeats scheduler restart, preserves original deadline, and is terminal **1.491s after that original deadline**, not a renewed timeout. Exact source exec Running=false/exit1, matching sessions0, worker absent, owner released; lastBackupSuccessAt stays at the adopted success. Independent RO/socketless health with scheduler stopped really exits1 failed+overdue. Both source containers retain StartedAt/RestartCount; final fixture insert/read succeeds. A prior files target can legitimately remain complete in an overall failed mixed run; no whole-run atomicity is claimed.

## B5 measured workload / resources

256MiB incompressible random payload,512 files plus checksum manifest; sourcePG200000 rows /39.513MiB. Exact unchanged file parent,513 unmodified files and0 new data blobs. Full streamed S3 readback compares all512 SHA256s without file restore or local mirror. Fresh independent PG target restores actual snapshot and reads `200000|20000100000|b122c694ab9929bda9c7f67827c05172`.

All4 ordinary mixed-run workers: inspect Memory=536870912, NanoCpus=2000000000, CpusetCpus empty; actual memory.max=`536870912`, cpu.max=`200000 100000`. Zero worker_resources fields in the PG-only failure fixtures also resolve to those defaults. Restic child `/proc` observations directly confirm `GOMAXPROCS=2`; memory override32MiB was read back in the configured early-OOM fixture. No fake source-declared cpuset assertion remains.

| Mixed-run worker | Kernel high-water MiB | Sampled aggregate RSS/PSS MiB |
|---|---:|---:|
| First mixed backup |229.605|143.477 /140.344|
| Unchanged/adopted |44.277|74.340 /66.445|
| Fresh PG restore |42.668|68.543 /65.348|
| Deadline failure |50.406|68.695 /65.617|

5032 raw observations, no mixed sampler errors. Idle scheduler over19.947s: RSS6.773MiB/PSS6.770MiB, observed CPU delta0. Scheduler maximum kernel high-water45.246MiB; scheduler memory remains uncapped, so **128MiB scheduler recommendation is not validated here**. Actual worker cap512MiB is validated for this bounded workload, not arbitrary repository indexes/universal RAM bounds.

Source first-dump window76.073s including idle/controlSQL:1.940227 CPU seconds,2891776 logical relation-read bytes,376 DB blocks read/13295 hits,317060 WAL bytes, no PG temp. Fresh-target import+content-verification7.186s:1.259939 CPU seconds,18964480 relation-read bytes,33177600 relation-write bytes,29280063 WAL bytes.29319168 PG temp bytes include ordered verification spill; do not attribute all to import. Raw WAL preallocation is separately visible.

**Physical I/O unavailable:** rootless io.stat missing, Docker block counters null. PG logical counters are not physical device I/O. Affinity is read and exact owned root processes/TIDs pinned to0,1; stock PG root gate precedes UID change. Fast raw observations expose short root-process/independent-exec birth-to-pin gaps (some initial Restic affinity0-3), not continuous affinity-from-birth. All relevant actual worker quotas remain2CPU.

Sampled worker tmp/cache bytes0 and logs0; RO rootfs,64MiB tmpfs, Restic--no-cache. State2380B/4 files after successes,1915B/3 after failure; no worker at terminal checkpoints. No full local dump or S3 mirror introduced. Backend after adopted success285415501B (272.193MiB) is separate repository storage, not worker cache; MinIO separate kernel peak528.871MiB is not in the worker budget.

Actual compressed OCI layers14609488B; image-save14628864B; merged-export38953984B; regular-file payload38940611B; scratch extracted regular allocation38948864B. Export includes Docker-injected files; Engine containerd Image.Size is not unpacked size. Shared/helper images were not pruned or counted as app runtime allocation.

## Controlled failure details / bounded cleanup

**Active-source injected OOM:** worker `d7c43381efe7dcb19a3eddc6c39f97db8a498ad25d97bb2559a7f8f06dda661e`, source exec `44ae1e0e6ea57b4ae1da32d52dccd75ce2bc3aeda94ca8d667812d8f7b1b1506`. Initial512MiB, real exact-worker update16MiB, kernel memory.max536870912→16777216, oom_kill2, Engine OOMKilled=true/exit137. PG lock stayed held during fault/recovery. Ordinary serve reconciles failed/no complete; source exec exit1/session0, worker absent, owner released; snapshots[]. Release1.324s after worker terminal (1.523s measured from fault initiation through scheduler stop). This is exhaustion during a source export's lock-wait, not an active-byte-stream throughput test or config32MiB successful startup claim.

**ENOSPC04:** worker `5c6ca28fba611c0f5a02e3331268f02d91742639c3a8f6a946ad2c92018e9bd9`, source exec `0a1af1cb5dc461e41e5a0ab2f03986ef8ea4a889b6027ef0e619672e7a830290`. The real pipeline reached PG exec_started before fault; only the inspected local tmpfs repository was deliberately filled with known filler8376320B. Exact worker bind equals volume Mountpoint. Actual capacity8388608B/free0; repeated1-byte write errno28 from12:41:58.132792Z to12:42:41.018428Z, including actual backup execution. Overall worker exit1 at12:42:40.448896779Z; ordinary serve result failed/target unknown, source exec terminal exit0/session0 and ownership released. Last-result release occurs0.518s after original45s deadline /0.303s after worker terminal. The42.855s fault-to-stop interval includes waiting for the original job timeout; it is not42s of post-terminal recovery.

Only AFTER exact terminal/ownership proof and another real errno28/free0 read at12:42:41.030872Z is the known filler removed at12:42:41.031933Z. Packs/index/snapshots/locks untouched. Actual filesystem then12KiB used/8180KiB available; normal candidate `restic --no-cache snapshots --json` exits0/`[]`. No `--no-lock`, `unlock`, synthetic empty list, source kill, or full staging. Source StartedAt/RestartCount and read/write continuity verified.

## Retained failed attempts (all original receipt errors unchanged)

| Attempt | Actual outcome / limit |
|---|---|
| `run-oom-01` | exit1: real configured32MiB oom_kill1 + OOMKilled=true before observed source phase; harness wrongly waits85s for unreachable lock-wait. Original last-result failed/no owner was read live before cleanup. It remains a failed invocation with valid early-OOM counter evidence, not an active-source test. |
| `run-oom-02` | exit1: same actual32MiB; sampled oom_kill0, Engine OOMKilled=false, worker exit1/failed, last observed phaseintent. Last counter sample precedes exit~24ms; no post-exit cgroup sample. Cause undetermined, **not OOM proof**. No further OOM rerun followed; actual active-sourceOOM01 was reused. |
| `run-enospc-01` | exit1 after real backup failure/terminal recovery: invalid literal error-text assertion against empty sanitized worker logs. Repository.command intentionally discards Restic stderr. No core edit. |
| `run-enospc-02` | exit1: exact8MiB backing sampled, but no real errno28/minimum free4038656; refused to claim ENOSPC. Transient fill/delete remained a hypothesis. |
| `run-enospc-03` | exit1 **after real ENOSPC and exact terminal/ownership proof**: post-failure `repo-snapshots` verifier, not backup, cannot create its own native read lock while filler keeps repository full. This is the command that exposed actual raw synthetic-fixture ENOSPC. |
| `run-enospc-04` verifier-first | Full invocation exit0; first independent verifier erroneously compared total fault-to-stop42.855s with35s post-recovery budget. Targeted RED/GREEN timing regression corrected verifier to original45s deadline+20s cleanup and actual post-terminal release; readback rerun only, no workload replay. |

No positive core defect reproduced. No errors were changed into success merely to get green. `FAILURE_DIAGNOSIS.md` has exact early-OOM IDs/counters/timestamps; missing terminal counter samples are not assumed zero or invented.

## Exact cleanup and remaining limits

Later independent readback across all8 attempts: **70 exact containers absent,26 exact volumes absent** (including inherited anonymous fixture volumes); each fixture owner summary empty, state/private/backend/bin data absent; outer Swarm still inactive. No source stop/restart/scale except final exact disposable-fixture removal during cleanup. Only evidence, fixture source and preexisting images remain.

Not closed here: large-index/universal RAM growth, physical I/O attribution unavailable on this daemon, continuously pinned affinity from birth, scheduler128MiB cap,1-vs2CPU comparison, retention/notification delivery or broad B2/B3 CLI matrix. Early configured32MiB automated acceptance is not green; its first actual earlyOOM proof and second undetermined failure must remain distinguished. There is no ambiguous live source/ownership quarantine left in the successful failure cases.

## Exact source paths to merge (only these10)

- `tests/integration/B4_RESOURCE_HANDOFF.md`
- `tests/integration/fixtures/RESOURCE_PROBE.md`
- `tests/integration/fixtures/run_resource_probe.py`
- `tests/integration/fixtures/summarize_resource_probe.py`
- `tests/integration/fixtures/verify_resource_probe.py`
- `tests/integration/fixtures/probe_health_exit_race.py`
- `tests/integration/fixtures/test_resource_probe.py`
- `tests/integration/fixtures/run_resource_failures.py`
- `tests/integration/fixtures/verify_resource_failures.py`
- `tests/integration/fixtures/test_resource_failure.py`

Do not merge runtime directories/credentials or modify any production source to reproduce this evidence. Keep old baseline artifacts under their old bindings.
