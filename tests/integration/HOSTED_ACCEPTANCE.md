# Manual GitHub-hosted acceptance

Entry point: [`.github/workflows/acceptance.yaml`](../../.github/workflows/acceptance.yaml), **Manual acceptance** → **Run workflow**. It is manual-only (`workflow_dispatch`), not a PR-triggered privileged workflow.

## Execution boundary

- Standard `ubuntu-24.04` GitHub-hosted **VM**, rootful Docker **29.6.1**, cgroup v2, fresh daemon with no containers and inactive Swarm. Direct Engine API 1.55; no Docker-in-Docker, rootless relay, removed resource fields or AppArmor relaxation.
- The Python runner refuses local/shared/self-hosted execution before opening a Docker socket. `--exclusive-hosted-daemon` does not bypass that check. Never spoof GitHub environment variables on the production VPS.
- Requires CPUs 0/1, at least 4 GiB VM memory and 12 GiB free scratch. Builds/fixtures use at most two CPUs. Ordinary worker requests remain 2 CPU / 512 MiB and require actual kernel readback. Existing create-to-pin/short-exec affinity gaps remain disclosed; this is not continuous process-birth affinity proof.
- Only synthetic fixtures and credentials. No repository secrets, production mounts, registry push, release or deployment. Source applications are not stopped for backup. Deliberate source deletion happens only after backup, to prove source-independent restore on the disposable VM.
- Swarm PostgreSQL uses the runner host network but listens only on `127.0.0.1`; its effective `listen_addresses` is checked with SQL. No source database port is published or opened on external interfaces.

## What it exercises

Runs both Compose-labelled containers and real Swarm services against local Restic and authenticated real MinIO S3:

- Mixed online PostgreSQL/file backup through the ordinary public CLI/worker; source read/write while dump waits, unchanged start/restart identity.
- Second file snapshot reuses its parent, no new file data, full fixture payload readback.
- Exact worker SIGKILL and S3 outage failures: source exec/session terminal before ownership release; no complete PostgreSQL snapshot for the failed target.
- Source containers/volumes and scheduler backup history removed, then PostgreSQL restore to a different cluster with different role OIDs and exact owner/ACL readback.
- Public file restore to an empty directory and unused default-local volume: exact bytes, mode `0640`, numeric UID `1234` / GID `2345`.
- Physical source/consumer aliases, a same-backing non-default local volume and `unknown`/`partial` snapshots refused. Incomplete statuses are produced by real operator Restic retagging, **not** a claim of inducing a Restic backup exit 3. The non-default-volume case proves refusal at the supported-driver boundary, not necessarily its later alias branch.
- Swarm opt-in is on the service object, not copied onto task containers; actual running task, node, daemon and start identity are checked.

Completeness is fail-closed: both source kinds for both backends and every named required gate, no duplicates. A separate verifier binds each receipt to its expected platform directory and actual Swarm-exercised flag, then rereads exact owned container/volume absence, inactive Swarm, removed private paths, source/image/daemon bindings and sampled worker kernel limits. Construction errors also produce a failed platform receipt and remove partially created credential paths; initialization never creates Engine resources. Runtime image inventory requires only the candidate and PostgreSQL, not auxiliary build images.

This is a **core runtime matrix**, not the entire PLAN acceptance suite. Remaining creating/stream/disconnect/import-loss fault mapping, capacity/RTO/large-index memory and physical-I/O evidence remain separate release gates. Even a successful workflow leaves `full_plan_acceptance_pass: false`.

## Provenance and evidence

- Checkout/setup/upload actions are pinned by commit. Go, Restic and PostgreSQL images are digest-pinned; the candidate records exact checked-out commit, core source fingerprint, ordinary image ID and daemon identity. No historical development image is assumed to exist on the runner.
- Real, unmodified MinIO source archive `RELEASE.2024-01-18T22-51-28Z` is verified against SHA256 `267c949e03f6d931f3b2da07c067f02483cb2b2604b627e1eb9b96acb0fd9192`, then compiled with the pinned Go image, `CGO_ENABLED=0`, `GOAMD64=v1`. This historical synthetic test backend is not a production MinIO/security recommendation; its development version string is not a release-image claim.
- The uploaded artifact `acceptance-<suite>-<commit>-<attempt>-<scope>-<case>` is retained seven days. Only explicit projected receipts/candidate/verifier fields are exported. Raw command output, container specs/Env, state, repositories, private files and raw metrics are **not** uploaded.
- Owned fixture cleanup runs in `finally`; successful acceptance requires independent exact absence readback. Upload runs on failure too. An abruptly terminated/timed-out job cannot claim cleanup PASS; setup action teardown and disposal of the entire hosted VM are the final boundary. No broad prune or Docker-context fallback.

## Independent F16–F22 scope

Choose **Run workflow → scope → remaining-faults** for the reviewed revision.
Default **all** keeps the original three jobs (`core-resources`, `capacity`,
`faults`), mandatory F14, and the full 19-case fault/3-case storage aggregates.
`remaining-faults` runs only seven matrix jobs, one fresh disposable VM for each
F16/F17/F18/F19/F20/F21/F22; it never continues behind F14 on the same daemon.
All jobs retain fail-fast false, preflight, pinned ordinary-image/tool builds,
2-CPU limits, deadlines and original cleanup/assertion rules. Targeted offline
prechecks run selection-verifier and documentation tests, not F14's live kernel
tracer suite; default all still runs the complete fixture suite.

Each selected runner receives exactly one existing `--case`. A separate
`verify_hosted_selection.py` invocation checks the exact one-case manifest,
source fingerprint and candidate image/daemon binding, then invokes the existing
actual case verifier without weakening it. Candidate metadata and artifact names
include scope/suite/case; only named receipts and `native-selected-verified.json`
or `storage-selected-verified.json` are exported. These explicit scoped verdicts
use `selected_case_pass`, never an aggregate/full-release claim. Original subset
reports must retain `fault_acceptance_pass: false` or `storage_acceptance_pass:
false`, and `full_plan_acceptance_pass: false` even when the selected case passes.
Missing/duplicate/unexpected cases, binding drift and cleanup failure fail closed.

F14 stays **FAILED / closure pending**; even seven green jobs cannot make the
release ready. No dispatch, new runtime PASS, publication or deployment is
claimed by this scheduling change. Current retained failure is recorded in the
[release ledger](RELEASE_GATE_LEDGER.md#current-f14-blocker-and-independent-remaining-gate-scheduling).

## Isolated manual fault recheck

Choose **scope → single-fault** and exactly one named **case** to run only that
case on a fresh VM. For the pending independent rechecks, use
`restore-reader-failure-importer-zero` (F14, suite `reader`), `temp-pack-ENOSPC`
(F19), or `restore-missing-extension-binary-prerequisites` (F22). The selector
also permits the other five F16–F22 cases. A small validation-only job checks
scope/case before any Engine setup, fetch or build; it does not run fault gates.
Invalid combinations fail closed: bulk scopes require `case: all`, and
`single-fault` requires a named case. Default `all/all` and
`remaining-faults/all` preserve the original three/seven acceptance VM matrices.

The reader suite passes its single `--case` to the unchanged fault runner and
actual `verify_hosted_faults.verify_case`, including all F14 assertions. It does
not invoke the full fault or storage suites. Its allowlisted receipt is
`faults-restore-reader-failure-importer-zero.json`, with
`reader-selected-verified.json`; scope/suite/case remain in metadata/artifact
identity. All scoped prechecks avoid the live F14 tracer test suite, but the
selected F14 runtime gate itself is mandatory, not waived. Scoped aggregate and
full-plan flags remain false. This selector is not runtime PASS evidence and
does not close F14 or authorize publication/deployment.

## Current state

The authorized source repository is public at [tamntlib/bakabel](https://github.com/tamntlib/bakabel). The [first successful hosted run](https://github.com/tamntlib/bakabel/actions/runs/40236034625), commit `64725f740c3c512e9edaefa58a9d994c28ea508d`, passed 21 Compose and 23 Swarm required gates plus independent cleanup readback. Its downloaded artifact digest, source/image/daemon bindings, gate completeness, worker defaults and cleanup receipts were checked again by the parent; see [results and preserved failures](HOSTED_ACCEPTANCE_RESULT.md). CI also passed at that commit. No image publication, release or production deployment was performed; remaining PLAN fault/capacity certification is still pending.
