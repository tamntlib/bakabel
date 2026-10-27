# Additive F19/F20/F22 hosted gates — runtime NOT RUN

This is an implementation handoff, **not hosted acceptance or release approval**.
The candidate was developed in a Git archive of
`b46b95d51ff9ac5437dc047b7d8f5c7f2e93230b`. No production Go, Dockerfile,
Restic pack size, worker resource default, timeout, image pin or cache policy
was changed. The production source fingerprint remains
`c143839dbdf75e409e927d087575c4ebd6201eb521594ed5dced7d6a8bb18293`.

## Separate additive suite

`fixtures/run_hosted_storage_prereqs.py` and the independent
`fixtures/verify_hosted_storage_prereqs.py` define three additional gates:

- **F19 `temp-pack-ENOSPC`:** ordinary public `run` and `_workflow`, actual
  pg_dump lock wait, actual `--no-cache backup --pack-size=4` process readback.
  Pin the exact worker's original 64 MiB `/tmp` tmpfs by descriptor. Fill only
  that owned bounded filesystem, leaving production configuration unchanged.
  Require actual traced `write`/`pwrite64`/`writev` errno 28 on a Restic temp-pack
  or index FD, distinct repository device, and a separate actual one-byte
  errno-28 probe. Keep pressure through terminal source/worker readback before
  canonical nonforce worker removal and ownership release. Read native
  snapshots by the exact run/target token; none may be complete. Persistent
  cache remains inapplicable: production still uses `--no-cache`.
- **F20 `restore-output-ENOSPC`:** genuine file-volume backup, then public file
  restore of a 32 MiB synthetic random file into an initially empty, separately
  owned 8 MiB host tmpfs directory. Trace the exact worker before its ordinary
  preflight inventory request is forwarded. Require a real output-file write
  errno 28, failed CLI, frozen job/snapshot/logical-source binding, allocated
  partial files retained after failure, and unchanged source checksum and
  source incarnation. The production CLI must not remove the partial target.
  Fixture teardown unmounts it only after exact Engine cleanup succeeds.
  Before invoking public restore, the exclusively created one-byte probe's
  directory entry is identity-checked and unlinked while its FD stays open.
  The destination is therefore strictly empty, with no production exception.
  Sampling still writes to that same pinned zero-link inode on the bounded
  filesystem; it never reopens or deletes a replacement pathname. The helper
  rechecks zero links before sampling and closing. F19/R04 retain the original
  named-probe behavior unless this explicit F20-only operation is called.
- **F22 `restore-missing-extension-binary-prerequisites`:** create a trusted
  backup with an actual `hstore`-typed column using the existing pinned PG18
  fixture. Prepare target roles first; keep its extension catalog empty. In
  only the separately owned target container's writable layer, rename exactly
  `/usr/local/lib/postgresql/hstore.so` to an owned hidden sibling. Keep its
  extension control file present. Require actual import creation/start and a
  nonzero exact terminal import, no surviving matching sessions/processes,
  failed result, and no installed hstore or payload. The operator fixture then
  puts the identical upstream library back, without creating the extension,
  deleting/recreating the database, replacing the target, or restarting either
  PG service. Repeat public restore into that same still-fresh target and
  require extension functionality, full ordered extension-dependent data
  checksum, table owner/ACL and database-policy readback.

A missing role or a preexisting extension is **not** credited as F22. A full
repository is **not** credited as F19. A full filesystem or a stderr phrase
without an actual traced output write failure is **not** credited as F20.
If the pinned runtime fails earlier (including an allocation-only failure),
that attempt remains failed; do not weaken the write gate to manufacture PASS.

## Admission, observation and teardown

The additive runner refuses local/shared execution before opening the socket.
It requires root, explicit exclusivity, GitHub-hosted environment, a fresh
rootful daemon, cgroup v2, fresh RUNNER_TEMP child, exact reviewed core source
and candidate image, and the existing PG image digest. It neither pulls an
image nor accepts an arbitrary helper image. Actual hstore-library availability
and the target override have **not** been exercised in this offline task;
`library_hash` fails closed if the pinned image does not supply the expected
file. There is no production extension installer or prerequisite bypass.

`fixtures/hosted_storage_trace.py` is host-only. It uses installed `strace`
with zero-length write-buffer formatting and no saved raw trace. It must be
allowed to attach to the freshly verified task-owned process; inability to
attach is a failed gate, not permission to change daemon/security policy.
The only retained syscall fields are PID, FD, finite syscall name, errno 28
and finite path class. Filesystem paths are transient classification input.
Per-TID unfinished syscall pairing, record bounds, observer shutdown and
errors are fail-closed. Error diagnostics use finite allowlists and null for
unknown type/frame identifiers, never exception text or raw stderr.

All normal application work still uses the ordinary public CLI/image and
`_workflow`; no mock binary or fabricated Engine reply is used at runtime.
Source PostgreSQL full ID, StartedAt and RestartCount must remain unchanged,
with successful read/write probes. Source teardown is only post-gate owned
fixture cleanup, never cancellation evidence. Exact source/exec/session and
terminal worker observations are recorded while strict durable ownership is
still present, before byte-identical nonforce DELETE forwarding.

## Integration surface

The existing fourteen-case `verify_hosted_faults.CASES`, all its existing
assertions, and its aggregate report are unchanged. Shared runner changes are
limited to a read-only `inventory_all` observation annotation and optional
case-verifier / error-projector callbacks, retaining their original defaults.
The manual workflow runs the additive suite after the original faults suite
on the same exclusively disposable faults VM. Both verifiers remain mandatory.
The additive report is `hosted-storage.json`; export includes only that report
and `storage-<allowlisted-case>.json`, never runtime trees or raw traces.

A parent integrating other F14/F16–F18/F21 work should merge those small shared
runner/workflow hunks, retain their default behavior, and rerun all offline
fixture/documentation tests. If production Go changes during integration,
this unchanged-core admission pin must not be updated mechanically: review
and rebind the new core, then perform fresh hosted execution and independent
artifact review of the exact integrated revision. This leaf is SOL work,
not a GPT-6-Astra review.

## Verification boundary

Cycle-2 controls compose the actual `exercise_output` method and real
`OwnedSpaceProbe` on an ordinary scratch directory, with Engine, mount and
statvfs seams explicitly doubled. They assert an empty destination and a live
zero-link probe FD at the public controller call and terminal boundary, then
exercise the actual one-byte write without pressure. Separate syscall-error
controls verify typed write-stage errno 28, not creation failure; entry/directory
drift, symlink/hardlink/collision and foreign replacement controls preserve
ownership-safe cleanup. These are offline regressions, not actual tmpfs ENOSPC.
The owned stat/unlink check is not atomic against hostile concurrent root
administrators; the exclusive disposable-host prerequisite remains mandatory.

Offline regressions exercise the real strace attach/detach lifecycle and a
real kernel `/dev/full` errno 28, real Unix peer forwarding with the actual
additive terminal callback, the actual workflow export shell, adversarial
receipt mutations, and fail-closed local admission. Synthetic receipt tests
are expressly offline fixtures, not emitted hosted receipts. These checks do
not establish that bounded Docker tmpfs faults or the extension recovery
passed. No Docker, network, GitHub, commit, index, ref, deployment or hosted
runtime action was performed for this handoff. F19/F20/F22 remain runtime
**NOT RUN** until the parent hosts and independently verifies this candidate.
