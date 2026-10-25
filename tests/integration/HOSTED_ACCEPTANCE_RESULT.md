# Hosted acceptance — first verified PASS

## Binding

| Field | Verified value |
|---|---|
| Source repository | https://github.com/tamntlib/bakabel (public) |
| Acceptance run | https://github.com/tamntlib/bakabel/actions/runs/40236034625 |
| CI run | https://github.com/tamntlib/bakabel/actions/runs/40236033715 |
| Exact run commit | `64725f740c3c512e9edaefa58a9d994c28ea508d` |
| R3 core fingerprint | `6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8` |
| Hosted ordinary image ID | `sha256:7d9702b7d70db6ff912c86a7b94927cb75c2bd1791c6ce3caef3e863c51ba53c` |
| Disposable Engine ID | `edbb05c9-f352-46d3-a0a8-d6c3a9ca4a2c` |
| Uploaded artifact ID | `12615366436` |
| Uploaded ZIP digest | `sha256:e3703dee076403e543fd383c31687a7e53d20c59c8d5096b590230e5d32827b3` |

This is the first successful runtime milestone, not an assertion that future documentation commits or new images automatically inherit acceptance. The unchanged production core is the Astra R3 core; the hosted image was actually built and recorded by this run, not substituted from the historical local image ID.

## Verified outcome

Both hosted workflows completed with `success`. The acceptance job used a standard `ubuntu-24.04` VM, pinned rootful Engine 29.6.1, direct API 1.55, cgroup v2 and actual unchanged worker limits.

| Platform | Required gates | Source/backend cells | Recorded workers | Exact owned containers absent | Exact owned volumes absent |
|---|---:|---|---:|---:|---:|
| Compose | 21 | PostgreSQL + files, local + S3 | 17 | 79 | 19 |
| Swarm | 23 | PostgreSQL + files, local + S3 | 17 | 79 | 19 |

The gates exercise public-CLI online mixed backup, file parent/no-new-data/full payload readback, source/history-independent PostgreSQL restore with owner/ACL and different role OIDs, file restore to a directory and unused default-local volume with bytes/mode/numeric ownership readback, physical source/consumer aliases, same-backing unsupported-volume refusal, unknown/partial snapshot refusal, worker SIGKILL, S3 outage and exact source-terminal proof before ownership release. Swarm additionally proves service-level opt-in and actual running task/node identity.

The independent verifier ran on the VM before daemon teardown. It reread exact owned container/volume absence, inactive Swarm, removed private paths, image/core/daemon bindings, required gates and sampled kernel limits. Every recorded ordinary worker used the bound image, `_workflow`, 2 CPU and 512 MiB; no resource request fields were stripped.

After completion, the parent downloaded the actual artifact ZIP and independently verified its SHA256 against GitHub's artifact digest, its exact five-file allowlist, commit/core/image/daemon bindings across receipts, platform-specific required gates, complete cell coverage, worker resource fields and cleanup assertions. The parent did not pretend to re-inspect a VM that had already been destroyed.

Local parent copy: `/home/tamnt/.hermes/cache/scratch/bakabel-hosted-pass-j9_pnp5g/parent-verification.json`. GitHub's uploaded artifacts expire after seven days; run logs and this durable binding are separate evidence, not a promise of permanent artifact hosting.

## Preserved failed attempts

| Run | Actual result / root cause |
|---|---|
| [40234145561](https://github.com/tamntlib/bakabel/actions/runs/40234145561) | Acceptance stopped in preflight: setup-docker-action returned a `unix://` URI, but the fixture treated it as a filesystem path. The same initial commit's CI also exposed a test-only hard-coded Hermes scratch path. Both portability fixes have RED→GREEN regressions. |
| [40234316552](https://github.com/tamntlib/bakabel/actions/runs/40234316552) | Local positive restores and alias refusals passed; later operator retagging failed. No complete matrix claim. |
| [40234842971](https://github.com/tamntlib/bakabel/actions/runs/40234842971) | Safe exception/source-location diagnostics identified the same failing Restic `tag` operation. A real killed Restic container reproduced a residual young shared lock and exclusive-tag exit 11. Status retagging was moved before deliberate fault injection; no force-unlock was added. |
| [40235383900](https://github.com/tamntlib/bakabel/actions/runs/40235383900) | All 21 Compose gates passed; Swarm init failed because the fixture tried to override Docker's required default cluster name. The override was removed, initialization intent made cleanup-owned before POST, and leave readback retained. |

Failed attempts stay failed. Their scoped results do not become full-matrix PASS because a later run passed. All code changes during hosted debugging were workflow/Python fixtures/tests; production Go/config/Dockerfile remained unchanged.

## Release boundary

`runtime_matrix_pass: true`; **`full_plan_acceptance_pass: false`**.

The remaining current-workflow create/stream/disconnect/import-loss fault mapping and deployment-appropriate large-index/RAM/RTO/physical-I/O capacity evidence are still release work. This result does not establish universal 512 MiB sufficiency, continuous process-birth affinity or production readiness. No registry image, release or production deployment was published; the VPS primary daemon's Swarm and security policy were not modified.
