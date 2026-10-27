# Native hosted fault gates F16/F17/F18/F21

**Implementation status: provisional. Hosted runtime: NOT RUN.** Offline tests
exercise protocol peers, real disposable file descriptors/truncation, and the
runner/verifier routing. They are not evidence of a kernel fanotify event, a
native Restic exit, a Docker worker crash, or release acceptance.

Base: `b46b95d51ff9ac5437dc047b7d8f5c7f2e93230b`, tree
`8e4ce0f596702a490277b4930160e22b4c8d313b`. No Go, Dockerfile, dependency, image
pin, worker limit, production timeout, capacity corpus, or existing fault branch
changes are needed. These four cases use the existing Compose/local backend.

## Native boundaries and expected evidence

| Gate | Hosted case name | Injection and acceptance boundary |
|---|---|---|
| F16 | `restic-native-exit3` | Deny a real native Restic **read**, after a previous permitted read advanced its exact descriptor offset. Require the ordinary public run to fail and retain both a full snapshot ID and `backup failed`, with observed `resticExitCode: 3`. Repository/public fresh-state status must agree as partial or unknown; incomplete restore must fail before any new worker/destination write. |
| F17 | `unknown-commit-before-finalize-worker-SIGKILL` | Hold the native post-backup `restic snapshots` open of an already committed canonical snapshot file. Independently decode that exact run/target's unknown snapshot using the pinned native Restic. Revalidate the live authorized worker and held inode, then actually send worker SIGKILL before finalization. Require terminal 137 before nonforce worker removal; fresh public repository classification must preserve that same unknown ID. |
| F18 | `finalized-before-report-worker-SIGKILL` | First observe the genuine unknown snapshot and permit readback/finalization. Hold the ordinary `_workflow` process opening its result temp file in the run's output directory. This is **after** `Repository.Backup` returned, including its final native metadata/status readback, but **before** `result.json` publication. Independently read back the complete snapshot, retain distinct exact old/new IDs, and actually SIGKILL the worker. The public controller must report a failed run; its target may correctly be complete with the recovered exact snapshot ID and `backup failed`. A fabricated Restic exit is not emitted for the crash. |
| F21 | `file-truncate-during-native-read` | While the next real native Restic read is held, truncate only the owned fixture payload to the already-observed positive descriptor offset. Then permit that read. Preserve the actual native/public disposition: complete, partial/unknown failure, or failed/no snapshot. Never assert application consistency or demand a predetermined Restic outcome. |

These are kernel **permission** faults, not substituted providers, replaced
Restic executables, shell exit-code wrappers, operator retags, or `chmod 000`
assuming a root worker loses DAC override. The source volume stays on its
ordinary local filesystem; no FUSE, loop device, mount-policy change, source
agent, or source-image installation is involved. Host permission decisions do
not change the worker image, user, capabilities, mounts, or Engine requests.

## Why these boundaries match the application

- `internal/files/files_linux.go:54-70` deliberately rejects FUSE/opaque
  filesystems. The fixture therefore marks a real option-free local volume
  rather than disguising a synthetic filesystem as a supported source.
- `internal/backup/restic.go:139-178` starts unknown, invokes the pinned native
  backup, then reads snapshots by exact run identity, preserving a real backup
  error and ID. Lines 185-211 finalize partial on backup error or complete on
  success, then independently read the final ID/status/metadata back.
- `internal/app/workflow_worker.go:162-178` preserves the native diagnostic exit
  and finite reason, while lines 244-249 publish the worker result only after
  all target/finalization work and retention handling returned.
- `internal/app/worker.go:48-80` opens `.record-<digits>`, writes/syncs it, then
  links it to `result.json`. F18 holds the native open of that empty temp file;
  it does not claim the public result has been written.
- `internal/app/workflow_controller.go:209-240` and its failure path may recover
  exact repository classification for a failed worker. Consequently F18 must
  not mislabel a complete target as unknown merely because its overall run
  failed. Neither crash is a wrapper/tag-command-failure surrogate.

The independent reader is the existing unchanged `/usr/bin/restic` operator
container in the same exact candidate image. It is not in the worker cgroup, so
its real repository reads are permitted while the worker's read is held.
Selection is by `runID + '-' + SHA256(logical target)` and exact IDs, never time
ordering, `latest`, or local history. A fresh controller uses the initially
empty `fresh-state` mount for public `snapshots` and incomplete restore refusal.

## Hosted prerequisites and fail-closed operation

Use only the already-authorized manual acceptance workflow on an explicitly
exclusive rootful GitHub-hosted VM. The existing runner rejects local/shared
invocation before opening the Engine socket. Host Linux/glibc must support
`fanotify_init`, `fanotify_mark`, and permission events, with host
CAP_SYS_ADMIN; no capability is added to an application or worker container.
Missing initialization/mark support blocks the gate. Unexpected protocol,
queue overflow, changed identity, expired hold, or classification errors cannot
be turned into PASS or silently replaced with chmod/polling/retagging.

Marks are limited to the one owned payload, the owned repository snapshot
directory, and (F18 only) this run's owned output directory before worker start.
The queue remains bounded; at most 4096 events and a 10-second individual hold
are admitted. The production 45-second workflow timeout is unchanged.
Directory opens are passed through; no recursive state/source inventory is
marked. The kernel may spell an event fd's path in the worker mount namespace:
acceptance therefore requires actual host/event inode+device equality, not a
matching pathname or basename alone.

Only the exact currently authorized worker can receive SIGKILL. Prekill checks
re-read owner, literal boolean authorization, worker identity/running state,
held PID incarnation/executable/cgroup, inode/size, daemon ID, and result-file
absence. A watchdog expiry grants no later kill authority. A fatal signal may
cancel the kernel permission wait before FAN_DENY reaches it; receipts retain
`kernel-canceled` separately from a delivered `denied`. Both still require real
terminal 137 before the actual nonforce DELETE is forwarded and ownership is
released. Fixture teardown is never crash/terminal/source-availability proof.

No force-unlock is used. Restic snapshot listing/public classification remain
read-only even if the killed native backup left a stale lock. Source container
ID, start time, restart count and online `/data` access are checked before
fixture teardown; no stop, restart, or scale-down is used as an injection.

## Integration and evidence

`run_hosted_faults.run_case` lazily selects `NativeFaultProbe` for these names.
`verify_hosted_faults.CASES` appends the names after the unchanged original
14-case prefix, and `verify_case` dispatches their additional semantic checks.
The existing manual workflow's `CASES`-based allowlisted exporter therefore
exports all four receipts without a workflow/dependency-install change. Its
real export shell is covered by the extended offline workflow regression.

Native observations retain bounded typed IDs, enums, descriptor offset/size,
UID/CapEff, real native diagnostic exit if present, old/new mapping, permission
outcome and causal event order. They do not export argv, environment, raw
stderr, snapshot payloads, or `/proc` dumps. An unobserved original snapshot ID
in the non-crash cases is null rather than invented. Progress observations are
retained separately from PASS proof, including on later validation failure.

Safe offline verification (already executed; see the external handoff logs):

```sh
taskset -c 0,1 python3 -B -m unittest discover -s tests/integration/fixtures -p 'test_*.py' -q
taskset -c 0,1 python3 -B -m unittest discover -s tests -p test_documentation.py -v
```

The existing manual workflow automatically includes these cases. A diagnostic
hosted subset can use its unchanged runner command with repeated `--case`
arguments and explicit source/image/daemon binding; a subset is never a full
fault-suite acceptance PASS. Do not trigger hosted execution without the
parent's separate authorization, exact-candidate review and image binding.

Remaining release gates: real hosted exercise of every case; inspect native
exit/disposition and kernel hold/cancellation behavior on that VM; recompute
receipt verification; then independent blocking review of the final merged
candidate. No Astra review, hosted PASS, or PLAN closure is asserted here.
