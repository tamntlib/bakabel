# Implementation status — verified R3 candidate

## Verdict

- **Production Go implementation: Astra R3 static PASS for actionable High/Medium** in the supplied source:0High/0Medium. All eleven mandatory R1 entries and all three residual R2 findings closed at their stated code/contract/docs boundaries. This is not a proof that no unknown defect exists.
- **Release: NOT READY.** Full current-candidate Swarm/file-restore and the remaining fault/capacity/hosted-CI gates below are not certified. No publish/deploy/remote/commit/push has been performed.
- R3 also reported one Low: CI skipped the new eight-case Restore launch regression because its Restic path differed from production. After review, CI now mounts/sets `/usr/bin/restic` and emits verbose test output. A new Python guard was observed RED→GREEN; the exact current CI race/vet shell block ran locally and all eight subcases ran/PASS, not SKIP. **This CI/Python/docs-only follow-up was locally verified, not re-approved by Astra or run on hosted CI. Production Go and the image are unchanged.** Optional legacy B1 lifecycle removal remains deferred.

## Exact binding

| Artifact | Identity |
|---|---|
| Core fingerprint (all Go files, go.mod/go.sum/Dockerfile) | `6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8` |
| Ordinary local image-index ID | `sha256:0b8607d95720ffcebcf90d181ffcb663c38accaab2aabfaa150666688152dc1f` |
| Local development tag | `bakabel-development:review-candidate-r3` |
| PLAN revision4 SHA256 | `ee1a05be3f47b98dd32c635d77a3fb26cf5320637bdb94ba3661e5e2f93f8cbb` |
| Astra exact returned model | `gpt-6-astra` |
| Astra response | `resp_023ee39ed161dd67016ade20890c1087d0abe071d2d31a5713` |
| Immutable103-file review input SHA256 | `5d023cfcf67de00aa2800545969d1b62c40e58dd75a5274e3c5e85dfdbb56a70` |
| Review text SHA256, excluding final file newline | `113676ff12ed761b71bb45bebdc98d6ae2f537c6931feb8acad256c747be935a` |

The request completed with exact model/input/source binding, no model/provider fallback. The reviewer read all production Go, all new/changed Go tests since R1 and selected existing safety tests/docs/fixtures; omitted unchanged tests, base Python harness/verifiers, raw runtime/image contents were not independently reviewed by Astra. See [the verbatim review](../../ASTRA-IMPLEMENTATION-REVIEW-R3.md) and remediation ledgers [R1](ASTRA_R1_FIXES.md), [R2](ASTRA_R2_FIXES.md).

## Implemented and exercised

The approved MVP remains stateless, one schedule/repository and one temporary sequential worker, metadata-driven Compose/Swarm placement, online PostgreSQL export streamed to Restic, independent empty-target restore, bounded durable ownership/recovery and readonly health. Compose only guarantees failure for marked services whose container metadata remains observable; a service whose final container was removed is not discoverable. Existing marked Swarm services without a running task still fail. No desired-state registry/watcher, new infrastructure service or user config knob was added.

Security/lifecycle repairs include exact worker-generation fencing, preserving invocation RunID on wait failure, shared backup/restore ambiguous-launch reconciliation, owner retention until exact worker removal/readback, adopted-ID crash recovery, restore intent at the actual exec-create boundary, normalized role-name ACL comparison, duplicate-key metadata rejection, bounded HTTP-client lifetime and health that does not mask last failure with an active run. Physical exclusions cover mount roots plus actual referenced password/AWS/notification/config files; only metadata is captured, hard-linked regular credentials/symlink or unprovable identities are refused. CLI config provenance is not a YAML knob or worker JSON field.

### Current-candidate runtime groups

All rows below executed on the exact R3 image/core; parent verifiers read back exact owned containers/volumes against the real primary Engine.

| Group | Verified result | Boundary |
|---|---|---|
| Compose/local and authenticated disposable S3 subset | Eleven named subset checks PASS: mixed online PG/files backup, stable file parent/no new file data/complete payload readback, source alias refusal, source/history-absent20,000-row PG restores with different role OIDs and exact owner/ACL policies, worker SIGKILL and S3 outage with exact source terminal/session proof before release | Not the historical full11gate matrix; does not exercise Swarm or public file restore |
| Protected file bind aliases | Password/config aliases refused; locked repository snapshots `[]` | Synthetic owned files/volumes only |
| Credential directory + external hard-link | Refused before worker/ownership launch; snapshots `[]` | Real old R2 RED published a complete synthetic snapshot; preserved as failure evidence |
| Valid metadata ACL reordering | Public PG Restore100-row readback PASS | Ordering reproduction, not a measured cross-collation claim |
| Scheduler/resources | Eight gates PASS: actual schedule, scheduler SIGKILL/restart adopts same worker/original deadline, no overlap, readonly/socketless failed+overdue health, source continuity,256MiB512-file full readback/unchanged parent,200,000-row PG restore | Four workers with actual kernel2CPU/512MiB limits; bounded fixture, not universal sizing |
| Active OOM | Exact worker limit lowered512→16MiB during PG source lock-wait; actual kernel oom_kill/OOMKilled; failed-not-complete, source exec/session terminal before release | Controlled Engine update, not configured32MiB active-export/during-byte-stream proof |
| ENOSPC | Actual same-repository8MiB tmpfs exhaustion; observed errno28 through failed backup; failed-not-complete/terminal proof/bounded recovery; snapshots[] after only owned filler removed | Real disk pressure within owned tmpfs, not host disk exhaustion |
| Configured low-cap OOM | Actual32MiB worker limit and early-intent oom_kill=1/OOMKilled; no source dump/session, failed result/snapshots[] | Failure-safety only;32MiB not supported success sizing or active-export proof |

Nine current scoped attempts were cleaned and independently checked: **113 unique containers and31 unique volumes absent**, private fixture data/credentials/binary copies removed, primary Swarm inactive. Shared caches/local development images remain intentionally available.

### Other current-source checks

- Full `go test -race -count=1 ./...` and `go vet ./...` PASS. CI-equivalent run with real Restic and verbose output also PASS, including all eight public Restore lost-create/start and terminal/unknown-proof cases. No external Docker daemon or real import was simulated as a runtime acceptance claim by that unit Engine seam.
- Actual minute scheduler + controlled Unix-Engine outage test PASS: one identified failure, owner retained, scheduling stops blocked. Not real-daemon network-fault proof.
- Real Restic/native file-directory contract PASS after lost source/fresh state, including visible versus unknown consumer handling, bytes/mode0640/numeric uid1234/gid2345. Inventory is a unit Engine seam; not Docker-volume/public-file-restore certification.
- **22 fixture +4 documentation/CI Python guards PASS**, actionlint PASS. Docker Go test entrypoint was explicitly taskset to CPUs0,1 with readback; hosted CI was not executed.

### Bounded resource observations

On the256MiB/512-file +200,000-row workload: scheduler idle RSS6.57MiB, observed CPU delta0 over19.96s; maximum recorded worker kernel high-water through the last live sample214.41MiB. Ordinary workers had `memory.max=536870912`, `cpu.max="200000 100000"`, no fixed Engine cpuset; Restic GOMAXPROCS2. Image compressed layers13.94MiB, merged regular-file payload37.16MiB. These are observations, not a RAM/idle-CPU/RTO guarantee. Source/target PostgreSQL exec use is outside the temporary worker's cgroup; process-birth affinity gaps and unavailable physical block-I/O attribution remain disclosed.

## What remains before release

Local manual [GitHub-hosted acceptance](HOSTED_ACCEPTANCE.md) now supplies a direct-rootful-Engine route for the core Compose/Swarm × local/S3 × PostgreSQL/files CLI matrix, synthetic MinIO, exact source/image binding and filtered evidence. It has not run on GitHub and does not close any runtime release gate merely by existing. Repository creation/commit/push/dispatch are not authorized or performed.

Local workflow verification: **35 fixture tests +4 documentation tests, actionlint, eight Bash blocks and three embedded Python blocks PASS**; the real local guard refuses execution with exit2 before opening its socket. Independent bounded read-only re-review `deleg_1b10bba9` returned **PASS, no actionable High/Medium** after three medium findings were fixed with RED→GREEN regressions (Swarm PG loopback listener, runtime-only image inventory/guarded partial initialization, exact platform receipt binding). This is not Astra or hosted-runtime approval. Final code manifest/logs: `/home/tamnt/.hermes/cache/scratch/bakabel-hosted-final-8wj5egab/verification.json`; production core fingerprint remains unchanged.

1. Supported **disposable Docker daemon** for full current Swarm/local+S3 and public file directory/volume restore replay, with all consumer backing storage in scope. Do not run public file restore on the shared production daemon: its safety preflight inventories/mirrors consumers. Historical full matrix633192cb/image568e907b is not R3 certification.
2. Complete B1 fault mapping onto the current public workflow, including remaining real-daemon disconnect/stream/creating gaps and scheduled launch-loss/restore-import-loss specifics. Unit seams and normal successful imports do not substitute for those fault gates.
3. Capacity evidence appropriate to deployment: large-index RAM, precise physical I/O and large-data RTO are not measured. Continuous affinity from process birth is not proven. Do not promote low-cap early OOM into active-stream support.
4. Hosted CI/provenance after an explicitly authorized repository/remote/push workflow. Local CI parity does not create a GitHub run.

Nested threaded-cgroup and native AppArmor attempts remain failed/blocking, not relabeled PASS. No security policy was weakened or source application stopped/restarted/scaled. No production/user-data backup was taken. The earlier failed nonstream Astra transport, anonymous-volume404 harness failure, native invalid-shell precursor, configured-OOM timestamp400 and hard-link fixture signature/RED failures remain preserved separately.

## Evidence entry points

- Current build/receipts/metrics/verifiers: `/home/tamnt/.hermes/cache/scratch/bakabel-review-r3-candidate/`.
- Combined fresh cleanup: `all-attempts-verification.json`; core/review binding: `review-final-binding.json`.
- Scoped proofs: `verification.json`, `resources-01/parent-verification.json`, `{oom-active-01,enospc-01}/parent-verification.json`, `configured-oom-verification.json`.
- Exact CI shell-block result and full test output: `ci-parity-verification.json`, `ci-race-vet.log`.
- Exact-model R3 input/review/receipt: `/home/tamnt/.hermes/cache/scratch/bakabel-implementation-review-r3-20261025/`.

Next operator prerequisite: authorize a GitHub repository/commit/push for the [manual hosted workflow](HOSTED_ACCEPTANCE.md), then run and verify its exact commit-bound evidence. No separate VM needs to be supplied for that route. Do not change this VPS's AppArmor or primary Swarm to bypass the blocker. Existing [setup](../../README.md), [restore](../../docs/restore.md) and [operations](../../docs/operations.md) instructions remain the entry points, not permission to deploy them now.
