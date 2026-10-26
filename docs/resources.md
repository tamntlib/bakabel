# Resource and failure evidence

These are bounded development-fixture observations, not production sizing or a universal memory bound. No image or release has been published. Inspect actual kernel enforcement on the intended daemon; a requested Docker limit alone is not proof.

## Measured resource baseline and scope

- Source fingerprint (sorted Go files plus `go.mod`, `go.sum`, `Dockerfile`): `2fd683f92a52b244ac452356cb4fd6de3567366348259ece09619c912e8b07ee`.
- Ordinary image-index ID: `sha256:ff1a6cd8e122b14c80da66396c6d14f06c22cc4c130e769def3a50520e9afca8`.
- This is the pre-security-review-fix baseline. Its measurements remain evidence for this exact source/image, not automatic certification or sizing of subsequent candidates. Astra implementation R1 rejected that baseline with actionable findings; later fixes and independent re-review are tracked separately.
- Runtime: baseline amd64 Go binary, Restic 0.18.1, scratch image; no shell, compiler, Python or Docker CLI in the product image.
- Real outer-rootless fixture: 256 MiB incompressible payload in 512 files, plus PostgreSQL 200,000 rows. Private authenticated S3-compatible backend and fresh PG restore target. No production data or credentials used.
- All four ordinary workers had actual `cpu.max=200000 100000` and `memory.max=536870912`. Source mounts and credential files remained read-only as required. Restic child environment readback confirmed `GOMAXPROCS=2`.

## Observed memory and disk

| Worker | Kernel cgroup high-water MiB |
|---|---:|
| First mixed backup | 229.605 |
| Unchanged backup / adopted worker | 44.277 |
| Fresh PG restore | 42.668 |
| Deadline failure | 50.406 |

These peaks include charged worker children/page cache through the last live observation; sampled RSS/PSS and configured limits are different quantities. Memory usage can grow with repository index/source shape. A 512 MiB ceiling worked for this workload, not necessarily a large repository. Scheduler memory was not capped; a 128 MiB scheduler ceiling has not been validated.

Over a measured 19.947-second idle sample, the scheduler's cgroup CPU delta was zero microseconds. This is not a promise of zero CPU over longer periods. Actual CPU quotas remain enforced; rootless cpuset declarations are not relied on. Exact fixture processes were pinned and checked, but process-birth/independent-exec affinity gaps remain disclosed.

Measured image accounting:
- OCI compressed layers: **14,609,488 bytes**.
- Actual image-save archive: **14,628,864 bytes**.
- Merged export's regular-file payload: **38,940,611 bytes**.
- Extracted regular-file allocation on the fixture filesystem: **38,948,864 bytes**.

Export includes small Docker-injected files. These values are not a complete Docker shared-layer/snapshot allocation inventory. Shared Go, PostgreSQL and standalone Restic images/caches were not pruned to improve the figures.

Sampled worker temp/cache and logs were zero bytes; rootfs stayed read-only, `/tmp` was a 64 MiB tmpfs and Restic used `--no-cache`. Small workflow state remained; no full local DB dump or S3 repository mirror was introduced. Backend repository storage and source/target database/WAL growth are separate from the worker footprint. PG logical I/O/WAL counters were recorded, but physical block I/O was unavailable on this rootless daemon; they are not interchangeable.

The zero temp/cache figure above counted named files only. It did not measure
filesystem availability or open-unlinked pack files and is not evidence of zero
temporary storage use.

## Pack storage correction and current candidate

Hosted run [40292564391](https://github.com/tamntlib/bakabel/actions/runs/40292564391)
at `c50cf16e9dd89796b9cf6f33b522620c762a3a48` passed the 44 core gates and all
12 implemented fault cases. Capacity completed its first and unchanged rounds,
but the changed file target failed with stage `backup`, Restic exit 1 and the
finite stderr classification `enospc`. That receipt alone does not identify the
exhausted filesystem. Scheduler first-success replay also failed; its cause is
not inferred from the separate capacity VM.

A separate local causal probe used the same pinned Restic 0.18.1, a 128 MiB
incompressible file corpus, real MinIO, 512 MiB memory, 64 MiB tmpfs and a fixed
4 MiB/s upload limit. With stock 16 MiB packs, Restic reported a failed write to
`/tmp/restic-temp-pack-*` with ENOSPC, tmpfs availability reached zero, five
open-unlinked pack files occupied all 67,108,864 bytes, exit was 1 and no snapshot
was created. Changing only pack size to 4 MiB completed with one snapshot;
sampled tmpfs usage peaked at 28,340,224 bytes. Exact owned containers/volumes and
private credential files were removed and absence checked.

Bakabel now passes the fixed `--pack-size=4` option to backup and retention prune,
the two paths that write packs. RAM/tmpfs limits, streaming, native repository
locks and retention's disabled default are unchanged. This trades more/smaller
repository objects for lower observed concurrent temporary-pack allocation;
there is no new configuration knob or full-data staging. These measurements are
not a universal storage bound, a proof of the historical scheduler cause, or
hosted certification of the changed candidate. A fresh exact-candidate replay is
required.

## Verified lifecycle and controlled failures

- Real scheduled mixed success; scheduler SIGKILL/restart adopted the same worker with the unchanged original job/deadline, rather than spawning another run.
- Independent read-only/socketless health observed success and later failed/overdue without refreshing the previous successful backup time. Sources retained their start/restart identity and read/write availability.
- The next unchanged file backup selected the exact parent, with 513 unmodified files and no new data blobs. Streamed S3 readback matched all 512 payload checksums; fresh PG import matched the fixture data.
- **Injected active-source OOM:** the ordinary worker started at 512 MiB, reached a real PG export lock-wait, then only that exact worker received a real Engine memory update to 16 MiB. Kernel `oom_kill` reached 2 and the worker exited 137. Ordinary recovery proved source exec terminal, matching sessions zero, worker absent and ownership released; no complete snapshot was published. This is not a claim that a configured 32 MiB worker reaches the export phase or that exhaustion during active byte streaming was tested.
- **ENOSPC:** an isolated 8 MiB tmpfs repository was deliberately filled only after the actual pipeline reached export. Repeated one-byte writes on the same inspected backing returned errno 28 while the backup ran. The workflow failed without complete snapshots. Source/worker terminal and ownership proof preceded removal of only the known fixture filler; normally locked Restic readback then returned an empty snapshot list. No repository pack/index/snapshot/lock was deleted or unlocked.

Failed attempts remain failed: one configured 32 MiB run proved early OOM but its harness waited for an unreachable later checkpoint; another had no positive OOM proof. Other failed fixture assertions are recorded, not relabeled as successful application runs. The checked-in-ready reproduction procedures and limits are in [the fixture guide](../tests/integration/fixtures/RESOURCE_PROBE.md) and [the candidate handoff](../tests/integration/B4_RESOURCE_HANDOFF.md).

## Configured early OOM replacement — unproven

The current configured-early fixture explicitly replaces32MiB with fixed16MiB
(16777216 bytes), including standalone default, hosted selection, producer
validation and independent inspect/kernel expectations.32 was a fixture value,
not a literal user/PLAN sizing requirement; PLAN §8 requires measured configurable
ceilings, not invented MB guarantees. The latest32 attempt (`40369174738` at
`3ca6aec`) failed the20s controller wait:2,831 samples had no positive oom_kill.
Last captured worker Running=true/PID66867 and a separate matched exec_started
owner are historical, not necessarily simultaneous or direct PG Lock-wait proof.
Earlier32 failures and their unknowns are preserved in the [release ledger](../tests/integration/RELEASE_GATE_LEDGER.md#configured-early-oom-fixture-correction).

Configured16 is **UNPROVEN**, pending one fixed exact-revision hosted attempt
and independent bound verification of every unchanged before-source, terminal,
positive-kernel-counter, failed/empty-snapshot, online-source and cleanup gate.
The same ordinary image,2CPU/production512MiB defaults,200000-row workload,
fresh empty native128MiB repository, ordinary swap policy and20s/3s/45s windows
are unchanged. No cap ladder, retry-until-lucky, injected allocator or weakened
predicate is introduced. Active512→16 injection and repository ENOSPC remain
separate unchanged evidence; neither proves configured-early16 or supported
active-export sizing. No new runtime PASS is claimed by this correction.

## Remaining acceptance boundary

This measured baseline's broad B2/B3 CLI replay on Docker-in-Docker is **blocked**: memory512MiB is preserved in requests/inspect, but the nested runtime cannot start the first worker because its parent cgroup is threaded. The separate native-rootless alternative also failed before worker execution because it could not read/load the Docker AppArmor profile; it was cleaned without disabling AppArmor or changing production/user-manager policy. Its failed precursor also requested a shell unavailable in the scratch image, so it is explicitly not ordinary-worker support proof. Historical baseline 11-gate success does not certify this or later candidates. The [Compose/local+S3 PostgreSQL subset](../tests/integration/COMPOSE_PG_CLI_HANDOFF.md) passed on source2fd683f9/imageff1a6cd8 without file restore or Swarm; its eleven subset checks are not the original full11gate matrix. Full replay and independent approval of the security-review fixes remain separate release gates.

Also unproved: universal/large-index memory growth, scheduler128MiB cap, precise physical I/O, continuous affinity from process birth and large-data RTO. Fixture completion does not authorize real-data backup, retention deletion, deployment or publication.
