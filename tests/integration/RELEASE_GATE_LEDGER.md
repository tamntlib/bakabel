# Remaining release acceptance ledger

**Release: NOT READY.** This ledger maps requirements to evidence; it does not turn implementation, offline tests, or a successful process exit into runtime acceptance.

The historical Astra R3 core fingerprint is `6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8`. The later frame-boundary suffix-loss repair is documented in [the completion protocol and limitations](../../docs/streaming.md). The current additive fixture candidate preserves the `b46b95d` production/core fingerprint `c143839dbdf75e409e927d087575c4ebd6201eb521594ed5dced7d6a8bb18293`; no Go, Dockerfile, dependency, pin, worker default or production deadline changes are included. R3 review/runtime evidence does not certify this candidate. Every fresh hosted result must bind its exact source fingerprint, Git commit, actual image ID and disposable daemon. Older core acceptance run `40236930603` at commit `f3be77e36d1be73d9f3c8b706ec4f386b96a4a9c` does not certify later source or fixture revisions.

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
| F14 | Restore reader failure with otherwise valid import | §6; §10 | Current `8d7b2b4` evidence **FAILED / closure pending**: hosted `40490097174` failed its control before fault execution. Historical F14 PASS at `865d1db` is retained, not current certification. Tracer race is reproduced; the historical hosted cause remains unknown. |
| F15 | Worker dies during observable active import; independent import-token terminal recovery | §6; §10 | `restore-active-import-worker-SIGKILL`: actual hosted PASS on `b46b95d`, run `40448351015`, independently audited below. Recovery scope is the original public restore controller, independent of the killed worker, not a fresh-controller restart claim. |
| F16 | Genuine Restic exit 3: snapshot ID **and** error, partial/unknown refusal | §5.4; §10 | Full gate **pending**: historical `865d1db` reached the functional boundary but failed owned-volume cleanup; `8d7b2b4` did not reach F16. Its owned-volume/Options repair has offline review/tests, not hosted confirmation. No operator retag substitute. See `NATIVE_FAULT_GATES.md`. |
| F17 | Crash after unknown commit, before finalization | §5.4; §10 | Additive `unknown-commit-before-finalize-worker-SIGKILL` fixture implemented provisionally: hold real committed-snapshot readback, classify exact unknown ID, then actual owned worker kill. Offline proof checks are not crash evidence. Hosted runtime **NOT RUN**. |
| F18 | Crash after finalization, before report | §5.4; §10 | Additive `finalized-before-report-worker-SIGKILL` fixture implemented provisionally: hold native result-temp create after complete final readback; require actual SIGKILL, exact old/new mapping and fresh complete classification despite failed overall run. Hosted runtime **NOT RUN**. |
| F19 | Actual temp/buffer storage ENOSPC | §7; §10 | Additive `temp-pack-ENOSPC` fixture and offline regressions implemented; exact owned 64MiB worker `/tmp`, actual traced Restic temp-pack/index write errno28, terminal source/worker proof required. Hosted runtime **NOT RUN**. Repository ENOSPC remains separate; persistent cache is not applicable (`--no-cache`). See `STORAGE_PREREQUISITES_HANDOFF.md`. |
| F20 | Actual restore-output ENOSPC | §10 | Additive `restore-output-ENOSPC` fixture implemented; separate initially empty owned 8MiB output tmpfs, actual output-file write errno28, retained allocated partial target and unchanged source required. Hosted runtime **NOT RUN**. |
| F21 | File changes/truncates while being read | §10 | Additive `file-truncate-during-native-read` fixture implemented provisionally: positive native descriptor/read boundary, literal owned-file truncation, actual disposition retained without application-consistency claims. Offline protocol/file tests only; hosted runtime **NOT RUN**. |
| F22 | Snapshot requires unavailable target extension binaries, then correct prerequisites | §6; §10 | Additive `restore-missing-extension-binary-prerequisites` fixture implemented; hide only owned target `hstore.so`, require actual import failure, restore identical library and retry same target/DB without restart or deletion. Hosted runtime **NOT RUN**. Missing-role/preexisting-extension cases remain separate. |

Source-task replacement, wrong credentials, wrong repository password, missing repository, unsupported replicas and unsupported nodes have older real API evidence (`fixtures/README.md`; `swarm_s3_test.go`). Keep each boundary explicit when mapping these to the final current CLI: historical evidence must not be discarded, but no current CLI execution is claimed here. No-target, path traversal, corrupt/stale state, unsupported metadata/client versions and conninfo input also retain their focused source/unit proofs; they are not multiplied into another full hosted Cartesian product merely to inflate gate counts.

## Resource and capacity instances

| ID | Requirement | Current implementation / acceptance boundary |
|---|---|---|
| R01 | Real scheduling, restart/adoption, original deadline, readonly failed/overdue health | PASS on `e886bef`, run `40379260708`: eight named scheduler verifier gates. |
| R02 | Active-export OOM failure safety | PASS on `e886bef`, same run: actual 512→16MiB injection with accepted zero-swap limits, positive kernel counter and terminal/recovery proof. |
| R03 | Configured small-cap early OOM | PASS on `e886bef`, same run: first fixed configured16MiB before-source attempt. Historical32 failures remain failed; no active-export sizing claim. |
| R04 | Actual repository ENOSPC | PASS on `e886bef`, same run: 8MiB bounded repository. Does not close F19/F20. |
| C01 | Larger mixed repository and distinct index entries | PASS on `e886bef`, same run: declared 1GiB/8192-file corpus plus 400000 PG rows; actual decoded index/stats and repository check. |
| C02 | Unchanged backup selects exact parent, zero new file data | PASS on `e886bef`: independent second worker, full identity/summary assertions. |
| C03 | Changed backup adds actual distinct data/index growth | PASS on `e886bef`: third worker, 1024 replaced files / 128MiB changed payload. |
| C04 | Entire original and changed file versions read back | PASS on `e886bef`: both full checksum sets streamed without local archive staging. |
| C05 | Fresh-target PG readback and source/restore CPU, logical I/O and WAL | PASS on `e886bef`: full ordered payload/owner/ACL checks and bounded before/after windows. |
| C06 | Source remains online and identity unchanged | PASS on `e886bef`: read/write during lock wait and unchanged StartedAt/RestartCount. |

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

Configured16 was **UNPROVEN** when selected. The first fixed hosted attempt and
independent bound audit subsequently passed on `e886bef`, as recorded below.
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
stays red; the scoped16 PASS does not relabel32 or establish production sizing.

## Latest retained bounded hosted PASS — b46b95d

CI `40448350899` and acceptance `40448351015` passed at
`b46b95d51ff9ac5437dc047b7d8f5c7f2e93230b`, tree
`8e4ce0f596702a490277b4930160e22b4c8d313b`, unchanged core
`c143839dbdf75e409e927d087575c4ebd6201eb521594ed5dced7d6a8bb18293`.
The independent frozen-source audit checked retained ZIP/API-digest bindings,
exact extracted bytes and per-VM commit/image/daemon linkage. It reran core's
44 public criteria, all six capacity gates and summary, and all fourteen fault
cases, aggregate and frozen verifier CLI. All four resource cases emitted
verified projections; private raw resource inputs were not uploaded, so those
checks are typed public consistency, not private-verifier reexecution. No fresh
authenticated API lookup or Engine cleanup readback is claimed by that audit.

F15 was the actual `restore-active-import-worker-SIGKILL` case: a live target
COPY session/process with independent import token was observed, the exact
authorized worker was killed and terminal exit137 proved, and the actual import
exited1 with matching sessions0/processes0 before nonforce worker DELETE and
ownership release. Public restore exited1, failed/unknown with exact logical
source/snapshot and `restore failed`; last backup success was preserved and the
partial target retained. Its receipt SHA-256 is
`49e4437450f16da0323cd6184c4a8e463b8a1537aa383181da47d1db4fdc0068`.
This proves original-controller recovery independent of the killed worker,
not fresh-controller restart. F13 separately retained its exact quarantine
boundary; a prekill running worker's exit-zero placeholder is not terminality.

Independent audit SHA-256:
`89c4b13d0a6ec0a9e428d36e4edd0c70ff557f2bb7fcf0f06437a1dd3b910322`.
The original fourteen-case prefix and its safety assertions remain intact.
The additive candidate appends F14/F16/F17/F18/F21 to that fault suite and runs
F19/F20/F22 as a separate mandatory storage/prerequisite suite with its own
independent verifier and allowlisted export. At `b46b95d`, all eight new gates
were runtime **NOT RUN**; later F14/F16 attempts are recorded above and below.
Offline tests are not hosted receipts. Final independent review
of the exact integrated candidate (including the requested real Astra review),
separately authorized hosted execution and exact artifact verification remain
required. Previous review fingerprints are stale for this changed fixture tree.
This is not full PLAN release readiness, publication or deployment approval.

## Previous bounded hosted PASS — e886bef

CI `40379259970` and all three jobs of acceptance `40379260708` passed at
`e886befa2134ea8bae8c9f460e757e5541bad1a8`, tree
`d4c224c904db0d4a03d744347e8bba3d99058f78`, core
`c143839dbdf75e409e927d087575c4ebd6201eb521594ed5dced7d6a8bb18293`.
The independent frozen-source audit verified all three ZIP digests, extracted
bytes and commit/image/daemon bindings; core's 44 public criteria and hosted
independent record; all six capacity gates with recomputed summary and runner
hashes; and all 13 fault cases, aggregate and frozen verifier CLI.

All four resource cases emitted verified results. The first fixed configured16
attempt retained 18 cgroup samples at the sole sampled cap16777216, positive
`oom_kill` maximum1, OOMKilled=true and historical Running=false/PID0. Its
matching owner projection remained intent-only without source/exec identifiers;
the hosted verifier required the full owner history, no source execution,
sessions0, failed-not-complete, empty snapshots, online source and exact cleanup.
The active512→16 case separately retained accepted limits/effective swap0 and
kernel kill maximum2. Repository ENOSPC retained 6,403 errno28 observations.

Audit SHA-256:
`b42b4c4e109adf26302dc2687cb16af643b45ccb3e937c39f8f2de02bc257f2a`.
Offline resource checks cover emitted verification plus typed public consistency;
private-resource verifier inputs were not uploaded, and no fresh Engine cleanup
readback was performed by that offline audit. This bounded workflow PASS closes
R01–R04/C01–C06, not F14–F22 or full PLAN release readiness. No image publication
or production deployment was performed.

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

## Current F14 blocker and independent remaining-gate scheduling

Retained `8d7b2b45d7154eb23315c5d98dc15a6daaee83bb` runs: CI `40490096248`,
acceptance `40490097174`. Core/resources and capacity passed, but acceptance
remains **FAIL**: F14 control failed before F16; F16–F22 were not reached.
Historical F14 PASS at `865d1db` does not close current F14, and that attempt
failed F16 cleanup. A reproduced tracer race does not establish the cause of
the historical hosted failure. Stop consecutive tracer patches; retain F14
**FAILED / closure pending** and release **NOT READY**.

Manual `scope=remaining-faults` schedules exactly seven independent hosted VMs,
one each for F16–F22, without F14 or the three default jobs. Each retains fresh
exclusive rootful preflight, the ordinary pinned build and its original case
assertions/cleanup stop rules. The independent single-case verifier requires
an exact selection manifest and candidate/source/image/daemon binding, calls
the unchanged actual case verifier, and rejects aggregate acceptance claims.
The subset report keeps its suite aggregate false and `full_plan_acceptance_pass:
false`; a green scoped job is only that selected gate, never full release PASS.
The default `scope=all` retains mandatory F14 and both full fault aggregates.
No new runtime result is credited by this scheduling-only candidate. See
[manual usage](HOSTED_ACCEPTANCE.md#independent-f16f22-scope).

## Completion rule

Manual acceptance now separates `core-resources`, `capacity` and `faults` onto independent fresh hosted VMs with `fail-fast: false`, preserving per-VM image/daemon bindings and uniquely named allowlisted artifacts. Implementation and local tests do not close the runtime rows above. Before declaring release-ready, verify the exact final remote HEAD and every required receipt/artifact, retain failed attempts, close or explicitly resolve each remaining contract instance, and complete independent review on the final revision. No registry publication, release, retention activation or production deployment is authorized by this ledger.
