# Remaining release acceptance ledger

**Release: NOT READY.** This ledger maps requirements to evidence; it does not turn implementation, offline tests, or a successful process exit into runtime acceptance.

The historical Astra R3 core fingerprint is `6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8`. Production Go is now changing to repair frame-boundary suffix-loss acceptance; see [the completion protocol and limitations](../../docs/streaming.md). R3 review/runtime evidence does not certify this changed candidate. Every fresh hosted result must bind its exact source fingerprint, Git commit, actual image ID and disposable daemon. The previous complete core acceptance was run `40236930603` at commit `f3be77e36d1be73d9f3c8b706ec4f386b96a4a9c`; it does not certify later source or fixture revisions.

## Evidence already credited within its boundary

| Evidence | Boundary |
|---|---|
| Hosted core 44 gates: 21 Compose / 23 Swarm; local/S3 × files/PostgreSQL | Public online backup, exact parent/data readback, source/history-independent PG and file directory/volume restores, owner/ACL and alias refusals. See `HOSTED_ACCEPTANCE_RESULT.md` and the final-head run above. |
| Actual lock-wait worker kill and S3 outage | Terminal source/session proof before ownership release; **not** proof of a kill after dump bytes have streamed. |
| Historical R3 lifecycle/resource, active 16MiB OOM, configured early 32MiB OOM and repository ENOSPC | Retain existing evidence; current hosted replay still needs an independent verified result. Early OOM does not prove supported active-export sizing. |
| Current unit/subprocess tests | Durable phase/concurrency, launch reconciliation, metadata/parser/preflight refusals, result/notification and retention-default semantics. Unit Engine seams are not real daemon fault evidence. |
| Older real Engine/API failure fixtures | Valid historical evidence, including some source replacement, credential and exit-3 instances; an old `Prepare`/`Authorize` path is not automatically proof of the current public-worker orchestration. |

## Current-workflow fault instances

The first twelve rows passed on hosted run `40292564391` at commit `c50cf16e9dd89796b9cf6f33b522620c762a3a48`, core fingerprint `87ae2798a7c388c0eaad4d17e7604758000db052d34dc08c73282f3b8fabf9ac`. Parent reran every case verifier and the aggregate verifier against the digest-checked artifacts. This is retained evidence for that candidate, not certification of subsequent production changes. `fixtures/verify_hosted_faults.py` defines the exact case identities and fail-closed assertions.

| ID | Required instance | PLAN reference | Evidence / remaining action |
|---|---|---|---|
| F01 | Producer fails after real partial dump output | §5.2; §10 | `producer-failure-after-output`: PASS on `c50cf16`, run above. |
| F02 | Worker SIGKILL during active output | §5.2; §10 | `streaming-worker-SIGKILL`: PASS on `c50cf16`, run above. |
| F03 | Docker exec stream disconnect | §5.2; §10 | `docker-stream-drop`: PASS on `c50cf16`, run above. |
| F04 | Exact exec status unavailable, quarantine survives fresh scheduler, then real recovery | §5.2; §7 | `docker-stream-drop-status-unavailable-recovery`: PASS on `c50cf16`, run above. |
| F05 | Scheduled/current worker create response lost after real side effect | §7 | `worker-create-response-loss`: PASS on `c50cf16`, run above. |
| F06 | Worker start response lost | §7 | `worker-start-response-loss`: PASS on `c50cf16`, run above. |
| F07 | Dump exec-create response lost before ID persistence | §5.2 | `dump-create-response-loss`: PASS on `c50cf16`; durable quarantine, **not** ownership recovery. |
| F08 | Dump exec-start response lost after persisted ID | §5.2 | `dump-start-response-loss`: PASS on `c50cf16`, run above. |
| F09 | Independent restore-import create response lost | §6; §7 | `restore-create-response-loss`: PASS on `c50cf16`; durable quarantine, not recovery. |
| F10 | Restore-import start response lost | §6; §7 | `restore-start-response-loss`: PASS on `c50cf16`, run above. |
| F11 | Backup versus public restore / retention-configured run | §7; §10 | `backup-vs-restore-and-retention`: PASS on `c50cf16`. No standalone maintenance CLI is invented. |
| F12 | Controller kill and two scheduler restarts preserve original deadline/worker/job and last success | §7; §10 | `scheduler-restart-original-deadline`: PASS on `c50cf16`, run above. |
| F13 | Kill exactly after persisted exec ID but before start forwarding | §5.2 | `dump-persisted-before-start-worker-SIGKILL`: PASS on `97b9611`, hosted run `40365486870`; exact retained quarantine, **not** terminal exec success, ownership release or production fencing. See the preserved attempt below. |
| F14 | Restore reader failure with otherwise valid import | §6; §10 | Current reader/import exit-status unit/API coverage retained; current public fault experiment still missing. |
| F15 | Worker dies during observable active import; independent import-token terminal recovery | §6; §10 | Current orchestration experiment still missing; retain existing API cancellation evidence. |
| F16 | Genuine Restic exit 3: snapshot ID **and** error, partial/unknown refusal | §5.4; §10 | Historical real exit-3 and current status tests retained; current-workflow generated partial receipt still missing. Operator retagging is not this case. |
| F17 | Crash after unknown commit, before finalization | §5.4; §10 | Fresh-state repository classification and exact snapshot IDs required; wrapper/tag failure is not a process crash. |
| F18 | Crash after finalization, before report | §5.4; §10 | Fresh-state complete classification and old/new ID mapping required; not yet exercised as a current-workflow crash. |
| F19 | Actual temp/buffer storage ENOSPC | §7; §10 | Repository ENOSPC is separate; exercise bounded disposable temp storage. Persistent Restic cache is not applicable (`--no-cache`). |
| F20 | Actual restore-output ENOSPC | §10 | Bounded disposable output filesystem required; preserve partial target and failure result. |
| F21 | File changes/truncates while being read | §10 | Mount/unreadable tests are not this literal instance. Record actual Restic disposition; do not promise application consistency. |
| F22 | Snapshot requires unavailable target extension binaries, then correct prerequisites | §6; §10 | Missing-role and preexisting-nonempty-extension tests are separate; missing-binary prerequisite experiment still needed. |

Source-task replacement, wrong credentials, wrong repository password, missing repository, unsupported replicas and unsupported nodes have older real API evidence (`fixtures/README.md`; `swarm_s3_test.go`). Keep each boundary explicit when mapping these to the final current CLI: historical evidence must not be discarded, but no current CLI execution is claimed here. No-target, path traversal, corrupt/stale state, unsupported metadata/client versions and conninfo input also retain their focused source/unit proofs; they are not multiplied into another full hosted Cartesian product merely to inflate gate counts.

## Resource and capacity instances

| ID | Requirement | Current implementation / acceptance boundary |
|---|---|---|
| R01 | Real scheduling, restart/adoption, original deadline, readonly failed/overdue health | `run_hosted_resources.py --case scheduler`, eight named verifier gates; hosted replay pending. |
| R02 | Active-export OOM failure safety | `--case oom-active`, actual 16MiB injection; hosted replay pending. |
| R03 | Configured small-cap early OOM | `--case oom`, fixed configured16MiB replacement candidate; **UNPROVEN**, before-source failure safety only. Actual hosted attempt and independent verification pending; historical32 failures remain failed. |
| R04 | Actual repository ENOSPC | `--case enospc`, 8MiB bounded repository; hosted replay pending. Does not close F19/F20. |
| C01 | Larger mixed repository and distinct index entries | `run_hosted_capacity.py`: declared 1GiB/8192-file corpus plus 400000 PG rows; actual decoded index/stats and repository check. Hosted run pending. |
| C02 | Unchanged backup selects exact parent, zero new file data | Independent second worker, full identity/summary assertions; hosted run pending. |
| C03 | Changed backup adds actual distinct data/index growth | Third worker, 1024 replaced files / 128MiB changed payload; hosted run pending. |
| C04 | Entire original and changed file versions read back | Both full checksum sets streamed without local archive staging; hosted run pending. |
| C05 | Fresh-target PG readback and source/restore CPU, logical I/O and WAL | Full ordered payload/owner/ACL checks and bounded before/after windows; hosted run pending. |
| C06 | Source remains online and identity unchanged | Read/write during lock wait and unchanged StartedAt/RestartCount; hosted run pending. |

Capacity reports must retain worker/scheduler/source/restore scope separately, actual image/binary/helper-image overhead, sampled tmp/state/log footprints, persistent S3/source/target storage and exact cleanup. Missing counters and exit-race observations are not zero measurements. Host physical-device attribution, continuous process-birth affinity, arbitrary repository size, universal 512MiB sufficiency, scheduler-128MiB sufficiency and universal RTO are **not** requirements or promises established by these fixtures. PLAN §8 explicitly forbids invented premeasurement RAM thresholds.

## Configured early OOM fixture correction

The current fixture explicitly changes32→16MiB, not a production sizing
requirement or a verifier-only repair. The earliest Git-recorded standalone
default32 is `ac2d0a6` (accepted range16..128); `04cc2ca` fixed hosted selection
and inspect/kernel expectations at32, and `3a36f6b` recorded R03. PLAN §8
requires configurable measured ceilings and forbids invented MB thresholds;
it does not prescribe32 or promise OOM at any cap. Independent read-only
contract review of `3ca6aec9c42115980902be98ee3f939734b21d21` accepted16 only
as an unproved candidate. This correction does not reinterpret historical32
attempts, the R3 evidence above or the B4 handoff.

Configured16 remains **UNPROVEN** pending one fixed hosted attempt on the exact
reviewed revision and independent source/image/daemon/artifact-bound verification.
All substantive gates remain: positive exact-worker kernel `oom_kill` plus
terminal OOMKilled=true/Running=false/PID0; legitimate monotonic prebinding to
exact bound intent-only owner history; no source/exec identity or pg_dump event;
matching sessions0; durable failed-not-complete and empty native snapshots;
unchanged source StartedAt/RestartCount with real read/write availability;
fatal observer errors, quiescent observers and exact cleanup. Preserve the
ordinary image/core,2CPU,200000-row corpus, fresh empty128MiB repository,
ordinary swap policy and20s controller/3s terminal/45s job windows. Active
512→16 and ENOSPC are unchanged separate cases. No cap ladder, automatic retry,
corpus/deadline relaxation or gate weakening is permitted. If16 fails, R03
stays red; a future16 PASS would not relabel32 or establish production sizing.

## Preserved new failed attempts

Run `40369174738` at `3ca6aec9c42115980902be98ee3f939734b21d21`
remains **FAIL** overall. Configured early32 failed the unchanged20-second
controller-exit wait before its verifier (`run_resource_failures.py:471` →
`run_resource_probe.py:390,360`). Its2,831 samples had maximum `oom_kill=0`,
inspect OOMKilled=false and actual33554432 bytes. The last captured worker
was Running=true/PID66867; separately the last identity-matching owner was
exec_started with start authorization true and source/exec present. These
historical captures are not necessarily simultaneous or the failure-time/current
state. No direct PG Lock-wait proof was retained; exit0 is not completion or
terminality proof. Public receipts emitted scheduler/active-OOM/ENOSPC verified
results, not a fresh private-input/Engine re-verification. Earlier133/97
terminality and non-OOM causes remain unknown as recorded below. Retained
parent audit SHA-256:
`1a8d23db56ae37158119095731494aec0ffe2b1a54f80b0b115976bb6284bb3b`.

Run `40365486870` at `97b9611bf38672281a430e03b28cd68b751dbb26`
remains failed overall; CI `40365486241` passed. The exact frozen fault
verifier accepted all 13 cases, the aggregate and its CLI (exit 0), including
F13's actual persisted-before-forwarding interruption. Its one held request
contained 261 bytes; all correlated starts remained unforwarded and unanswered.
Three exact exec observations retained raw nullable exit state, while the owned
worker was observed live and then terminal with exit 137. A fresh scheduler
remained blocked without creating a replacement or changing last success/result;
the source remained online with restart count zero. Exact fixture cleanup
recorded 10 containers and one volume absent and retained quarantine state.
This closes F13 only within the tested Compose/local boundary.
The audit also validated core's 44 public gates, all six capacity gates and
the recomputed 2,798-sample capacity summary. Resource receipts emitted verified
scheduler eight-gate, active-OOM and repository-ENOSPC results; ENOSPC recorded
6,574 real errno-28 observations. Raw private resource inputs were not uploaded,
so that part of the independent offline audit checks public consistency, not a
fresh execution of private verification or Engine cleanup.
Configured early 32MiB OOM again failed the 20-second **controller-exit wait**
before reaching the early verifier. Its 2,965 samples recorded no positive
`oom_kill`; the projected worker exit zero does not prove termination or backup
completion because Running/PID were omitted. Its execution stage and cause of
non-OOM remain unknown. Retained audit SHA-256:
`ee4186dc65c0c31db384104bc6026e9fc97d8f0311512d1b41f5675ec67ee375`.

Run `40360630725` at `133dcf0ac9985dcf2add006b2e7bd8e510b7df3b`
also remains failed overall despite successful CI `40360629715`, core 44,
capacity six, faults 12 and emitted scheduler/active-OOM/repository-ENOSPC
verification. Early 32MiB OOM hit the same 20-second controller-exit wait
before its verifier; 2,837 sampled observations had no positive `oom_kill`.
Worker terminality and the cause of non-OOM are unknown, not inferred from the
public exit-zero placeholder. This is distinct from the earlier owner-history
KeyError. Retained audit SHA-256:
`5150b18b31c4347c9d7dfd6a09bac9d84469889eccab6fdf8c2104820e6a9dcf`.

Run `40343287948` at `a81622e3e17dda0abb830614dadf320f3aa2b2b1`
retains independent core 44, capacity six, faults 12, scheduler eight,
active-OOM and repository-ENOSPC PASS evidence. The ENOSPC public receipt
records 7,281 real errno-28 observations and terminal source/worker recovery;
the hosted verifier recorded exact cleanup of eight containers and three
volumes. Capacity validates 2,870 samples, both full 8,192-file/1 GiB readbacks,
and a matching 400,000-row PostgreSQL restore.
The run remains failed: configured early-OOM verification raised `KeyError`
at the owner-history expression on exact-source line 159, not the cap lookup
on line 161. Its worker OOM and positive sampled counter do not bypass that
failure. The missing key/private owner rows were not uploaded. A source-grounded
regression reproduces missing `workerContainerID` for legitimate initial intent
saved before worker creation; this is a proven mechanism, not identification
of the unavailable historical key. A separate regression reproduces partial
terminal limit rows; neither correction relabels the retained failed run.

Run `40331046893` at `88d41bc73dbd77607439b92acfc46d3b4159b2c8`
remains failed overall, but now has independent core 44 and capacity C01–C06
PASS receipts, plus successful hosted scheduler eight-gate and active-OOM
verification. Capacity has 2,808 samples, both full 8,192-file/1 GiB checksum
readbacks, a matching fresh 400,000-row PostgreSQL restore, zero sampler
errors, and independently recorded cleanup of 37 containers and five volumes.
The active-OOM update was accepted, effective RAM was 16 MiB with zero swap,
the source was unlocked, kernel oom_kill reached two, and terminal OOMKilled
was true; exact worker/source recovery and cleanup passed. This is the stated
mid-run lock-wait injection, not proof that OOM began after dump bytes streamed.
The repository-ENOSPC case then failed the observer-error gate, after a failed
worker and recorded cleanup of eight containers and three volumes. Its public
projection does not retain which observer failed or its exception type/frame;
the historical cause is therefore unknown. Early configured OOM was not run.
The new PASS receipts do not relabel older failures or close F13–F22, and the
overall resources/full-plan release gate remains failed.

Run `40324792653` at `db1c946ee9924d422ebaa3292ce533f9d859602c`
remains failed. The faults job passed; the core runner completed its 44 runtime
checks, but its independent verifier rejected a Compose sampler `OSError`
with errno 19 (`ENODEV`) at the shared cgroup read. Capacity completed all six
runtime checks, including full original/changed file readback and fresh-target
PostgreSQL restore, but its independent verifier rejected another errno-19
sampler error at the same shared read. No `capacity-verified.json` was produced.
These completed runtime checks are not independent acceptance PASS. Resource
cases were skipped after core verification failed, so this run supplies no new
scheduled-lifecycle, active-OOM, repository-ENOSPC or early-OOM certification.
The artifacts identify the failing observation path, not the historical timing
or cause of the cgroup disappearance; genuine live observation errors must not
be suppressed or rewritten as zero measurements.

Run `40314807189` at `b90d768bea7a32df9c8560935bc0ebb369cd4e33`
passed core 44, faults 12/12 and all eight independently verified scheduler
gates. Capacity completed all three mixed backup rounds (every worker exit 0),
but its fixture parsed human-readable `restic check` progress as JSON, before
full readback/restore. The active-OOM fixture remained failed: terminal exit 1,
OOMKilled false and no observed positive cgroup oom_kill. Repository ENOSPC and
configured early OOM were not reached. The check-parser regression is corrected
locally; historical OOM is not relabeled as success and its assertions remain.

Run `40292564391` at `c50cf16` passed core 44 and faults 12/12, but remains failed:
scheduler did not reach its first scheduled success, and capacity's third
(changed-data) file backup returned stage `backup`, Restic exit 1, reason `enospc`.
First and unchanged capacity rounds completed, but their success does not close
the full C01–C06 gates or missing readback/restore. Hosted OOM/repository-ENOSPC
cases were not reached. The separate local temp-pack failure and 4 MiB pack
correction are documented in [resource evidence](../../docs/resources.md);
the changed candidate needs fresh exact-source hosted replay.

| Run | Actual boundary |
|---|---|
| `40263772226` | Core CLI step succeeded; independent verifier rejected unclassified sampler errors. Resource cases skipped. |
| `40264921665` | Safe diagnostics identified `FileNotFoundError` in footprint `is_file` → `stat` observation. Resource cases skipped. |
| `40265884540` | Footprint fix applied; verifier instead retained `OSError` while reading a cgroup control file. Recorded diagnostics lacked errno, so this historical exception is **not** asserted to have a proven errno. Resource cases skipped. |

The unlink race has a deterministic RED→GREEN regression and explicit missing-observation counters. The earlier cgroup guard handled ENODEV after one confirming inspection and allowed PID-change resolution. The current shared sampler instead settles ENODEV/ENOENT/ESRCH within one absolute second, accepting only exact owned absence/stoppage or complete fresh kernel readback. Live PID or identity drift and unexplained live errors fail. Numeric diagnostics exclude arbitrary messages and locals; these rules do not establish historical exit timing.

## Completion rule

Manual acceptance now separates `core-resources`, `capacity` and `faults` onto independent fresh hosted VMs with `fail-fast: false`, preserving per-VM image/daemon bindings and uniquely named allowlisted artifacts. Implementation and local tests do not close the runtime rows above. Before declaring release-ready, verify the exact final remote HEAD and every required receipt/artifact, retain failed attempts, close or explicitly resolve each remaining contract instance, and complete independent review on the final revision. No registry publication, release, retention activation or production deployment is authorized by this ledger.
