# F14 ordinary public CLI reader-failure candidate — NOT runtime accepted

Base: `b46b95d51ff9ac5437dc047b7d8f5c7f2e93230b`, tree
`8e4ce0f596702a490277b4930160e22b4c8d313b`.
Production/core fingerprint remains
`c143839dbdf75e409e927d087575c4ebd6201eb521594ed5dced7d6a8bb18293`.
No Go file, Dockerfile, module file, production image or production option changes.
This is an additive fixture candidate requiring final integrated review and a
separately authorized hosted execution. F14 remains OPEN until that execution.

## What the candidate executes

`run_hosted_faults.py` selects the additive `F14Mixin` only for the new named case
`restore-reader-failure-importer-zero`. The other fourteen cases retain their
original implementations and order. The mixin uses the inherited ordinary image,
public `plan`, `run`, `snapshots`, and two public `restore` commands, one control
and one fault, with distinct fresh PG targets and workers. The existing 300000-row
corpus, 2 CPU / 512 MiB worker defaults, 45-second workflow timeout, native locks,
source-online policy and exact cleanup rules are unchanged.

The host observer sees the actual restore-start request BEFORE forwarding its
unchanged bytes. At this point the reader goroutine may already be writing into
the synchronous pipe, but the Docker input pump has not started. A reader too
small/fast to remain observable is a failed prerequisite, never a successful
fault. No archive padding, wrapper replacement, Restic binary/path override,
agent in the Source, fabricated API response, or production-image modification
is used.

`hosted_f14_reader.py` runs on the disposable host. It binds the one direct-child
`/usr/bin/restic --no-cache dump <exact snapshot> <exact metadata path>` process to the
strictly authorized durable owner, exact worker Engine ID/image/PID, executable,
argv, /proc start ticks, and worker cgroup. It attaches all observed reader threads
using `PTRACE_SEIZE`, follows thread clones and traces syscalls. It waits for the
**entry to the real x86-64 `exit_group(0)` syscall**. Only then does the fault arm
send SIGKILL through that reader's pidfd. All application writes have already
happened; this avoids guessing the archive's final byte or changing its contents.
The control observes the same boundary without signalling. The tracer never
changes registers or syscall return values. A natural nonzero reader exit is
rejected rather than relabeled as the intended injected case.

The reader's actual wait status must be exit zero in the control and SIGKILL in
the fault; a CLI exit alone is not reader evidence. The target's real Engine exec
inspect must independently report importer exit **zero** in BOTH attempts, with
zero matching processes and sessions. The SQL readback must match all 300000 rows,
min/max/sum and an ordered full-content digest. The ordinary public CLI must
report control `restored/restored` exit 0, but fault `failed/unknown`, exact
logical source ID/snapshot ID, `error="restore failed"`, exit 1. It must retain
the target, preserve last backup success, and release only the exact worker.
The fault's valid data is NOT application/restore success.

At the real nonforce DELETE request, before forwarding and before durable owner
release, the observer retains fresh importer-zero/session/process proof, stopped
worker exit 0 or 1, and the completed host tracer status. Normal restore has
already reset its active exec checkpoint via `AdvanceExport`; the retained owner
is the same strict authorized worker/run in `intent`, NOT a fabricated still-active
exec. The old exact exec checkpoint remains in the evidence for terminal queries.
The independent verifier checks this distinction, exact canonical nonforce query,
create/persist/start/remove order, contradictory correlated exec/removal records,
public logical ID versus owner SHA-256, and cleanup identities.

## Production trace and historical evidence

* `internal/app/workflow_worker.go` defines `postgresPath(logical)` as
  `/bakabel/postgres/<SHA256(logical source ID)>/database.dump`. The backup's
  `--stdin-filename` and `workflowMetadata.Paths` both use that definition.
  F14 freezes the public plan and exact complete public snapshot first, requires
  one metadata path matching that logical-source hash, then passes the read-back
  path into reader discovery and binding. The verifier independently recomputes
  the layout and exact reader argv digest. The old B1 `/postgres.dump` is not
  an ordinary-workflow path. Owner `targetID` remains the hash, not the logical ID.
* Successful restore workflows emit overall `restored`, and the controller
  explicitly rejects overall `complete` for restore jobs. This does not change
  snapshot status `complete`, control target status `restored`, or fault
  `failed/unknown`. Reader/importer/data/session/removal criteria are unchanged.
* `internal/app/workflow_controller.go` fixes the production Restic binary at
  `/usr/bin/restic`; no PATH-only reader wrapper can cover the ordinary CLI.
* `internal/restore/postgres.go` creates/persists the independent import token and
  exec before launching `Repository.Dump` into an `io.Pipe`. The combined gate at
  lines 141–155 checks both the independently awaited reader error and importer
  outcome. `internal/platform/docker/restore_stream.go` propagates input errors
  while still half-closing the real importer stream. No production defect was
  demonstrated by this work, so no Go fix or Go test was added.
* Historical APP/API-only validation retained reader 17/importer 0, 300 correct
  rows, correct/final exits 0 and deliberate masking-mutant exit 1. Its verification
  SHA-256 is `bb1719a4d73d925e40ebaa19bcc293e8be0d5217166e65aca213aedef2eac454`.
  It used an injected test repository wrapper and is NOT ordinary CLI acceptance.
  Its mutant suppressed BOTH readerErr and propagated importErr; it was not an
  isolated test of only readerDone. These facts are preserved, not upgraded.

## Offline evidence and limitations

All new functionality was developed with retained RED/GREEN logs outside the
source tree. Offline tests cover real harmless owned-child ptrace/kernel exits
(control 0, fault SIGKILL, exact bytes preserved), a nonleader exit with thread
clones, final authorization drift detaching without signalling, exact binding
mutation refusals, real Unix relay pre-forward/byte preservation, actual fixture
public-command orchestration with explicitly synthetic observation seams,
false-restored result rejection, JSON-roundtripped adversarial receipt mutations,
and an in-memory verifier mutation proving the importer-zero gate is causal.
Synthetic receipt builders are test inputs only and are never hosted receipts.

Cycle-2 production-contract regressions replay the actual `F14Mixin` on a
`FaultProbe` subclass with explicitly synthetic Engine/CLI observation seams.
Distinct logical IDs produce distinct real-layout paths; wrong layouts/hashes,
foreign metadata sources, selected annotation conflicts, snapshot/argv mismatch
and invented control `complete` are refused. The real tracer startup method
is also exercised through discovery, binding and its private binding file,
without attaching to a container. Production-shaped control/fault attempts and
the independent JSON-roundtripped verifier pass offline. Retained RED logs show
the original runner/verifier rejecting valid contracts and accepting the wrong
control contract. No hosted acceptance is inferred.

Historical leaf offline fixture discovery passed **355 tests** (original 341 plus 14 F14
regressions); documentation discovery passed **4 tests**. No Docker, network,
source-service probe, real Restic/PG restore, image build, Git stage/index/ref
write, commit or hosted invocation was performed. Historical Go/core tests were
not rerun or relabeled. An initial multithread tracer regression exposed clone
stop delivery before the parent's clone event; the fix waits only authorized
known tids until the parent event admits the clone. A first full-suite run also
caught two old inventory tests that assumed exactly fourteen direct base cases;
they now preserve the F15 position and exercise the actual class selector.

## Hosted prerequisites and integration

Requires an explicitly exclusive **fresh GitHub-hosted rootful Linux x86-64 VM**,
root host observer with CAP_SYS_PTRACE / permitted ptrace policy, pidfd support,
`PTRACE_GET_SYSCALL_INFO`, visible worker host PIDs/cgroups, Python 3.10+, ordinary
pinned candidate/PG images and the existing inherited daemon preflight. No host
policy change, package install or Source install is performed by the fixture.
The fixture must fail/retain diagnostics if these prerequisites are unavailable;
never silently skip or replace reader failure with importer failure. Host helper
attachment has a 20-second bound; arming has a 5-second observation bound. These
are observer bounds, not increases to the existing product deadline. Measured
hosted syscall-tracing overhead and Restic/PG timing remain UNPROVEN.

Integrate the four new fixture modules/tests and the small runner/verifier hooks.
The two existing-test edits are inventory/dispatch updates, not removals of F15
safety assertions. Other children adding cases must reconcile the selector and
aggregate CASES inventory once; do not replace their modules or change old case
semantics. The existing workflow discovers all Python tests and iterates CASES,
so this branch does not edit the workflow. Retain all new helper/verifier bytes
in the final commit/source evidence; add their exact hashes to any parent runner
manifest that otherwise lists only the old two fault scripts.

After integrated final review and authorization, the inherited hosted command
can select `--case restore-reader-failure-importer-zero` for diagnosis; a subset
must NOT set aggregate `fault_acceptance_pass`. The normal no-`--case` run includes
all named cases and its frozen offline verifier. Do not run this host helper
standalone against a shared daemon. A change to any Go test/source would alter
the current core fingerprint and require renewed build/review certification;
this candidate avoids that expansion. Parent must call the real final Astra
review after integration/runtime gates; this child makes no Astra verdict claim.
