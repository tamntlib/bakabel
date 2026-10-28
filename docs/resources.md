# Resources and sizing

Bakabel processes targets **sequentially in one temporary worker**, using the
same immutable image as its controller. PostgreSQL export and restore stream
under backpressure; file backup reads the selected read-only volume directly.
There is no full local dump, tar staging copy or S3 repository mirror. Streaming
does not make the source database, Restic indexes or restore destination free.

## Defaults and enforcement

| Component | Current behavior | Operational implication |
|---|---|---|
| Worker | **2 CPUs / 512 MiB** by default; omitted or zero `worker_resources` fields select these defaults. | Ceilings, not reservations or universal sizing. Inspect actual kernel enforcement on your daemon. |
| Worker root filesystem | Read-only; `/tmp` is a **64 MiB tmpfs**. | Open-unlinked files consume tmpfs even when a directory listing appears empty. tmpfs also consumes memory. |
| Restic | Pinned **0.18.1**, `--no-cache`; fixed **4 MiB packs** for backup and retention prune. | Smaller packs reduce observed concurrent temporary-pack pressure, at the cost of more repository objects. This is not an absolute temp-storage bound or a configurable pack-size mode. |
| Controller/scheduler | Sleeps between scheduled runs; worker settings do not cap it. | Measure it independently. A 128 MiB scheduler limit is not established by the fixture workload. |
| PostgreSQL | `pg_dump` and restore/control execs run in the source/target PG container. | Worker limits do not constrain PG CPU/RAM/I/O/WAL or all Docker exec activity. |
| Repository and restore target | Persistent backup data and full restored data, respectively. | Budget separately; neither is disposable worker cache. Local same-host storage does not protect against loss of that server. |

Change only a demonstrated resource need; see
[configuration](configuration.md#worker-resource-ceilings). Changes affect new
workers, not an already running/adopted worker. Resource exhaustion is a failure,
not permission to classify a partial backup as complete or release ambiguous
ownership. Keep native repository locks and retention disabled until an
independent restore and explicit deletion approval.

## What the bounded workloads cover

[Testing](testing.md) describes the reproducible procedures, required runtime,
entry points, expected results and evidence handling. The full acceptance suite
includes these finite workloads:

- Small scheduled lifecycle: **256 MiB incompressible data in 512 files plus
  200,000 PG rows**, unchanged file-parent reuse, full streamed payload checks,
  independent PG restore, scheduler restart/adoption/original deadline and
  read-only/socketless health.
- Larger capacity: **1 GiB in 8,192 files plus 400,000 PG rows**, first and
  unchanged rounds, then **1,024 replaced files / 128 MiB** changed data. Checks
  include actual index/data growth, native repository check, both complete file
  checksum sets and fresh-target PG data/owner/ACL readback.
- Distinct failure scopes: configured **16 MiB early OOM** before export,
  ordinary **512→16 MiB** active lock-wait injection, **8 MiB repository
  ENOSPC**, worker `/tmp` temp-pack ENOSPC and separate restore-output ENOSPC.
  Positive kernel/syscall and exact terminal/ownership proofs matter; a nonzero
  exit alone does not identify OOM or the exhausted filesystem. Early low-cap
  failure safety is not a supported low-cap success configuration, and lock-wait
  OOM is not evidence of pressure during active byte streaming.

These describe the last candidate's bounded fixture design, not measurements
from this documentation change. Results belong to their exact source/image,
runner, daemon and workload; a historical passing image cannot certify a changed
one. No numerical CPU/RAM peaks, physical I/O rates or recovery-time guarantee
are inferred here. Failed and unknown historical attempts remain failed and
unknown rather than being replaced by later success.

## Measure before operating at your scale

Keep these categories separate when recording a disposable drill:

1. Worker kernel `memory.max`, `cpu.max`, high-water through the last live sample,
   and aggregate child RSS/PSS. A configured cap, a sampled RSS peak and charged
   kernel high-water are different measurements. Missing exit-race observations
   are not zero usage.
2. Scheduler idle and active CPU/memory, state files and rotated logs. A short
   idle sample with no observed CPU delta is not a zero-CPU promise.
3. `/tmp` filesystem availability and open-unlinked packs, not just named-file
   sizes. `--no-cache` does not eliminate temporary packs, indexes or memory use.
4. Source export and destination import **plus verification** CPU, logical
   relation I/O, PostgreSQL temporary spill and WAL. If physical block counters
   are unavailable, report them as unavailable; logical counters are not device
   I/O and verification spill is not necessarily import overhead.
5. Persistent repository growth, restored data/index/WAL capacity and retained
   partial targets. Failed uploads may leave unreferenced repository blocks.
6. Compressed image transfer, image-save archive, unpacked regular-file allocation
   and shared/helper image/cache storage. Engine image size is not necessarily
   unpacked host disk allocation. Do not prune shared images to improve a report.
7. Exact source/worker identities and cleanup readback, with original deadlines.
   Observed fault/recovery duration is specific to that workload and host, not
   a general RTO.

## Limits to retain in capacity decisions

- No arbitrary repository-size or universal **512 MiB** sufficiency claim:
  Restic memory can grow with index/source shape despite bounded stream buffers.
- No established scheduler 128 MiB cap, precise physical-device attribution or
  large-data RTO. Requesting worker limits is not proof they were enforced.
  Worker/fixture quotas are not a CPU affinity or build/test machine policy.
- Default-local volumes and the tested PG baseline remain the supported scope;
  fixture data does not establish all host filesystem/permission topologies.
  File copying is not application consistency, and PostgreSQL is not PITR or a
  multi-source atomic checkpoint.
- Kernel tracing/permission fixtures and emitted public resource projections
  have explicit observation/trust limits. An offline artifact audit cannot replay
  unavailable private raw inputs or inspect a destroyed VM.

A successful drill informs capacity planning; it does not authorize production
backup, retention deletion or deployment. Keep recovery access and decryption
keys outside the source host, verify representative application reads after a
restore, and repeat the drill for material image, data-shape or runtime changes.
