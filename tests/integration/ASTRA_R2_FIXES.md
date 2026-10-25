# Astra implementation R2 — final remediation candidate

**Pending re-review, not approval.** R2 exact-model review completed on source `b0c7508e9fa0c4fca1f6e1287606c2f30a596fe56665e31a62788b9f81689646` / image `sha256:1ec5e349232a3a8953f91a215f7b19a5295be03491ae56e34c0e231ffa2c3c23`: ten mandatory R1 entries closed, H01 partial; actionable residual1High/2Medium. Evidence: `/home/tamnt/.hermes/cache/scratch/bakabel-implementation-review-r2-20261025/{REVIEW.md,receipt.json}`. Input/source remained unchanged; no fallback.

## Candidate R3

- Core SHA256 `6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8`.
- Ordinary local image-index ID `sha256:0b8607d95720ffcebcf90d181ffcb663c38accaab2aabfaa150666688152dc1f`.
- Local tag `bakabel-development:review-candidate-r3`; build/source/image binding at `/home/tamnt/.hermes/cache/scratch/bakabel-review-r3-candidate/CANDIDATE.json`.
- PLAN revision4 remains `ee1a05be3f47b98dd32c635d77a3fb26cf5320637bdb94ba3661e5e2f93f8cbb`.

## Repairs, not independent closure

### R2-H01: referenced files inside directory mounts

`WorkflowStart` retains mount-root physical exclusions and also captures the actual referenced repository password, AWS shared credentials, notification endpoint file and loaded CLI config file, using the existing metadata-only O_PATH/no-symlink/hard-link refusal. No recursive secret-directory walk, secret bytes in state or new user setting. `Config.SourceFile` is internal CLI provenance: `yaml:"-" json:"-"`; `loadConfig` records its absolute filename, and worker configuration does not serialize it.

- Real RED on frozen R2 source/image: owned credential-directory mount, same-filesystem password hard-link in a separate owned default-local source volume. Old CLI exited0/published complete snapshot `779ee384c00e0da2dd0c5d55664646d4f4f515bef0a37b19d28f3b31a5728bd7`; refusal regression exited1. Evidence `bakabel-review-r2-candidate/hardlink-red-02`. The earlier red-01 failed in the harness because a keyword-only base method received positional arguments; it is not the defect reproduction and remains a failed attempt.
- Intermediate fixed-image GREEN: sourcef69f6ce7/imagef1effd11 refuses before ownership/worker launch with `protected runtime identity unavailable`; locked snapshots `[]`. Evidence `bakabel-review-r2-h01-fix/hardlink-green-01`. Final R3 replay is separate, not assumed.
- Added permanent internal-config-provenance test: path retained locally, excluded from worker JSON, rejected as a YAML key. Existing file metadata/no-read/symlink/hard-link tests remain.

### R2-M01: waiter always returns its invocation identity

`WorkflowWait` restores only its supplied handle's RunID on every early-error return, including failed wait/cleanup inspection; it never infers identity from a newer/current owner. No release or cancellation policy is relaxed.

- Actual RED: successful create+start followed by API503 in both wait and cleanup kept durable owner but returned an empty result RunID.
- GREEN: exact original RunID, owner unchanged, create1/start1/delete0.
- Explicit permanent opt-in `TestServeStopsAfterScheduledOwnedWaitOutage` ran the actual minute scheduler with the unit Unix-Engine seam under race detector. It emitted exactly one identified failure, returned `errRecoveryBlocked`, and did not schedule/create another worker. This is not a real-daemon network outage acceptance claim.

### R2-M02: common backup/restore launch-error reconciliation

Extracted the existing exact-run bounded launch handler into `reconcileWorkflowLaunch`. `Run` and both branches of public `Restore` use the same handler: no create/start retry, fresh bounded cleanup, preserve launch error/handle, retain owner if proof unavailable; never remove target data. Successful launch still uses the same waiter/deadline path.

- Permanent opt-in `TestRestoreReconcilesExactWorkerAfterLaunchResponseLoss` exercises PUBLIC `Restore` with real disposable Restic snapshots and a controlled Unix-Engine seam: volume and PG, each lost create/start response, each known-terminal and unavailable-proof variants. Eight cases actually RED with empty invocation identity/unreconciled worker, then all GREEN with race detector. Preflight reachability is asserted through create1 and four read-only PG control execs; source/consumer inventory replies are explicitly UNIT fixtures, not runtime acceptance evidence.
- Known terminal: exact owner and adopted ID remain durable during nonforce deletion; owner released after readback, create1/start<=1/delete1.
- Unavailable inspection after lost response: owner retained, no delete and no retry. The initial synthetic wrong-label start case never reached POST start, so the test was corrected to a genuine inspection503 AFTER start; the earlier failed fixture expectation is retained in transcript.
- Existing restore recovery tests still cover independent import token and source exec/process/session checkpoints. A real ambiguous restore-start fault during import is not newly claimed by the seam.

## Current verification boundary

Full Go race/vet passed after all production repairs and final test changes; Docker Go commands explicitly taskset their entrypoint to CPUs0,1 and read it back (the first RED command only requested cpuset and saw0-3; it is not affinity proof). Dedicated real-Restic eight-case test and real-minute scheduler test passed separately. Latest Python22fixture+3documentation tests passed before the new hard-link runner; it adds no discovered test module. Local actionlint and hosted CI are separate gates.

Final R3 Compose/local+S3 subset, aliases/hard-link, ACL, scheduler/resources and OOM/ENOSPC replays were started against this exact image; only completed and independently verified receipts count. Their results may follow submission and are not fabricated here. Prior R2 runtime receipts remain baselines, not R3 certification.

R2 configured32MiB OOM now has actual early-intent kernel `oom_kill=1`, worker OOMKilled, zero source dump events/sessions and snapshots[], plus fresh cleanup; active OOM16MiB and actual8MiB repository ENOSPC separately passed. A failed configured-OOM attempt remains exit1 due to the harness's unsupported timestamp query. Fixture-only RED/GREEN repairs use outward Unix event bounds and inspect BOTH Docker Action and execCommand (the latter is absent on this Engine); they did not change product code. This is not configured32MiB reaching active export or pressure during streaming-byte proof.

Full current Swarm/file-restore still needs a supported disposable daemon with all backing in scope; no source stop, main Swarm initialization, AppArmor weakening, production modification, publication, remote, commit or push is authorized/performed. Large-index RAM, physical I/O, from-birth affinity, large-data RTO and complete current-workflow B1 fault mapping remain unproved. Legacy lifecycle removal remains optional/deferred.
