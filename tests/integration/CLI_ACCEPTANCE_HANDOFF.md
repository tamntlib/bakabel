# Retained B2/B3 CLI acceptance — explicit fixture CPU boundary

This records the original isolated acceptance image and original runner hashes,
not a certification of later application changes. The parent copy subsequently
made image/MinIO/Restic paths explicit CLI arguments and added input unit tests;
use `fixtures/CLI_ACCEPTANCE.md` for the current invocation. Fresh image-bound
acceptance is required after changes to the application path.

## Outcome

Final full invocation returned **exit 0**, with all eleven asserted gates passed.
The ordinary image built from the copied repository's actual `Dockerfile` was
used for every controller and worker, without `b1fixture` or runtime affinity
instrumentation. No application, core, state, config, scheduler, resource-default,
Dockerfile or existing test file was edited. No Git, push or publication occurred.

Workspace/root:

```
ROOT=/home/tamnt/.hermes/cache/scratch/bakabel-cli-acceptance-4q7qqxvh
WORK=$ROOT/work
```

## Copy ONLY these new repository paths

- `tests/integration/fixtures/cli_relay.py`
- `tests/integration/fixtures/test_cli_relay.py`
- `tests/integration/fixtures/run_cli_acceptance.py`
- `tests/integration/fixtures/CLI_ACCEPTANCE.md`
- `tests/integration/CLI_ACCEPTANCE_HANDOFF.md` (this file)

Existing `tests/workflow_files_cli.py`, `tests/workflow_cli.py`, B3 integration
handoff/runner/README and source CLI handoff were read, not modified. A generic
container-runtime procedural-memory lesson was also updated outside the repo;
there are no application changes to merge or production defects to fix.

## Exact commands and artifacts

Executed from `$WORK`:

```sh
docker build --build-arg BUILD_CPUSET=0,1 --cpuset-cpus 0,1 \
  --cpu-period 100000 --cpu-quota 200000 \
  -t bakabel-cli-acceptance-4q7qqxvh:production .
# exit 0

taskset -c 0,1 python tests/integration/fixtures/run_cli_acceptance.py \
  --runtime /home/tamnt/.hermes/cache/scratch/bakabel-cli-acceptance-4q7qqxvh/run-final \
  > /home/tamnt/.hermes/cache/scratch/bakabel-cli-acceptance-4q7qqxvh/run-final.log 2>&1
# exit 0

taskset -c 0,1 python -m unittest discover \
  -s tests/integration/fixtures -p test_cli_relay.py -v
# Ran 4 tests; OK; exit 0
```

The runtime directory must be NEW for reproduction; do not reuse `run-final`.

Evidence retained outside the source tree:

- `$ROOT/run-final/receipt.json`: actual command argv/exits/stdout/stderr, images,
  frozen source identities, fault checkpoints, gate outcomes and cleanup readbacks.
- `$ROOT/run-final/relay.jsonl`: every real ContainerCreate and every omitted CPU
  key/value; eleven workers, eleven distinct run IDs, all exactly `_workflow`.
- `$ROOT/run-final/relay.jsonl.http`: actual request methods/paths/response status;
  no inventory or task/identity/ACL response manipulation.
- `$ROOT/run-final.log`: actual final CLI outputs/PASS lines.
- `$ROOT/relay-unit-tests.log`: final four transport/mutation unit tests.
- `$ROOT/verification.json`: independent programmatic receipt assertions, actual
  host resource readbacks, image history, source and receipt SHA-256s, attempts.

Receipt SHA-256:
`95ee3e6116427324e160aa4550622af62eb03ba4bd426d96b9e41e3633eeac39`.

Final runner SHA-256:
`88811e9a6da7214baae1e80122ec81d23b0fc4bc0929f19e5586dfba22ebcb46`.

## B2 verified

- Real file CLI `plan`, two `run`s, fresh-state `snapshots` and both restore modes.
  Exactly one unmodified `_workflow` create per overall backup run, stable
  hostname/path grouping and correct second-run parent, `files_unmodified=1`,
  `data_blobs=0`.
- Original source container and volume plus old state deleted before restoring
  into an independent explicit daemon-native directory and an operator-created,
  new unused **option-free default-local volume**. Both full payload, mode
  `0640` and UID/GID `1234:2345` read back inside the real engine.
- Exact complete local snapshot:
  `f013604812ed59a5c613f6c367df86e7dc4018d2db589de147ca28e663f7041c`.
- Snapshot-source physical alias refused: remove its only source consumer, empty
  its data, bind its same physical backing at an unrelated native target path;
  actual CLI fails without writes. No consumer or lexical-overlap shortcut.
- Separate actual consumer bind alias refused with destination unchanged.
- Different volume names actually mounted and stat-read as the same backing inode;
  restore into the alias volume refuses its bind driver options. This is correctly
  an unsupported-volume refusal, not a claim that bind-option aliases are valid
  supported local destinations.
- Actual Restic snapshots retagged unknown and partial are both refused by the
  CLI before destination writes. These are real repository classifications,
  **not** a claim that this CLI fixture generated Restic exit 3; actual exit-3
  partial generation remains the already-passed B3 core fixture's evidence.
- Real consumer metadata mirrors, filesystem descriptors and physical-source
  checks stayed enabled. No inventory filtering or production-root mount.

## B3 verified

- Genuine isolated Swarm service-level labels (no task-container opt-in copies),
  running tasks on the manager, frozen exact daemon/container/StartedAt identities
  and node placement; one mixed PG/files workflow to authenticated MinIO S3.
- **Real inner bridge works**, gateway `172.17.0.1`; no bridge-to-host mapping,
  published port, iptables dependency or production networking change.
- Password and AWS credentials explicitly mounted RO into the real worker;
  Engine Env and argv contain references, not credential values. Synthetic-value
  scan over commands/inspect/create/receipt evidence passed.
- Complete PG S3 snapshot:
  `79afe0d388ab7b417a8cc3117258a81b90b776bbcb088eaa1f7f43e54366cd11`.
- Complete files S3 snapshot:
  `a833d68db103d647df52bd37e5d6121637d1935c6c0cf2345b262901d8626f7d`.
- Source services/containers/volumes and old state removed before independent
  restore. PG target with wrong owner/ACL refused before import; after explicit
  operator prerequisites, restore reads back all **20,000 rows**, sum
  **200,010,000**, ordered content MD5 `e99cdd17463d67790009b9454d33067b`,
  table/database owner `fixture_owner`, and no PUBLIC CONNECT. Files restore
  reads back full contents and `0640 1234 2345`.
- Worker SIGKILL during an actual authorized PG dump waiting on a source lock:
  stopped controller preserves durable owner, replacement CLI returns
  `durable run owner exists` without worker creation; resumed original CLI
  performs recovery and returns exit 1 / `status=failed` in **5.129 seconds**.
- Actual MinIO stop after source export starts; unlock the source while S3 is
  down, exercise original immutable **18-second timeout**, restart S3 inside
  cleanup budget. Replacement CLI returns `state launcher guard is held`;
  original returns exit 1 / `status=failed` in **22.206 seconds**.
- Both fault runs: exact exec `Running=false` (exit 1 for SIGKILL case; exit 0
  for source producer in outage case), zero matching SQL sessions/processes,
  durable owner released only after terminal recovery, no complete snapshot.
  Source exit 0 does **not** synthesize overall success when upload failed.
- Recovery here is actual CLI `WorkflowWait` cleanup by the original controller,
  not a new public recovery subcommand or a separate fresh-controller API test.

## Real identities, images and resource boundary

- Host daemon: `0aa014bc-f231-498e-8ff3-31c6b80841ef`, Swarm **inactive** before,
  after and independent final readback.
- Owned inner daemon: `fdf18e34-858e-4406-90e7-bbd97830f87c`.
- Owned Swarm node: `qv85vebl9h27gjf70oz5v40vn`.
- Before enabling relay: measured outer engine `cpu.max=200000 100000` and PID1
  affinity `0-1`, actual inner ID unequal to host ID. Builds/runner/operator
  Restic pinned to CPU `0,1`.
- Fixture relay changes ONLY ContainerCreate `HostConfig.NanoCpus`, `CpusetCpus`,
  `CpusetMems`, logging every omission. Actual worker creates all requested the
  unchanged production `NanoCpus=2000000000`, `CpusetCpus=0,1` defaults.
- This is **honest functional proof under the outer aggregate two-core quota**,
  not inner individual cgroup enforcement or every Docker exec's affinity.
  No Engine/S3 replies, identity/placement/ACL or consumer gates are fabricated.
- Built image retained for parent reuse: `bakabel-cli-acceptance-4q7qqxvh:production`.
  Outer manifest-index ID:
  `sha256:d23144ad5d2a2540fd8421c1d925961609e45150fbd0253b8d82bf2e3f2ab8bb`.
  Actual inner loaded config-image ID frozen into worker config:
  `sha256:70a30ab3c53a4f49ddc5bbe20b7c0bc37b10de219992848ae28c048f87cdd147`.
  These reflect real containerd/classic-store identity differences, not different
  executable payloads. Build used actual pinned scratch Dockerfile, no test build tags.
- Reused original MinIO/Restic binaries unchanged, hashes respectively
  `8d95c686a61111ed8a0e38a80b84423b164ef07499fe87416b1302a4e6f550e0` and
  `01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6`.

## Failed attempts preserved, diagnosed and resolved

- `run-01`: fixture relay initially closed attach on client stdin half-close,
  losing real CLI stdout. Fixed transport half-close and added regression test.
  Upgrade parser additionally avoids buffering away initial raw stream bytes.
- `run-02`: worker create HTTP 404 because fixture froze outer manifest-index ID
  instead of reading actual inner image ID after real save/load. Fixed fixture
  identity lookup. No image response spoofing.
- Early cleanup `/services` on inactive engines returned real 503; fixture now
  checks actual Swarm state before that endpoint. Outer exact engines/data were
  nevertheless removed for the failed attempts; receipts retain original errors.
- `run-03`: actual SwarmInit rejected fixture's non-default spec name; corrected
  fixture to API-required `default`. B2 CLI positives/negatives had already passed.
- `run-04`: discovery correctly refused service names not following stack's
  `<namespace>_<service>` convention; corrected fixture names, not app discovery.
- `run-05`: full suite exit 0. `run-final`: reran full suite with extra direct
  snapshot-source physical-alias and global one-worker assertions; exit 0.

No unresolved application/core bug was reproduced and no core patch was needed.

## Cleanup and intentionally unperformed matrix

Final actual inner readback: containers `[]`, services `[]`, volumes `[]`.
Exact owned outer engine/network/cleanup containers absent; independent owned-name
container/network queries empty. Backend/state/restored bytes, copied binaries
and all disposable secret files removed; obsolete own Unix socket placeholders
removed after final verification. Only metadata/logs and the built CLI image remain.
No private production volume was mounted or read. No global prune/host SwarmInit.

Not performed here: B4 serve/schedule/retention/notifications (explicitly deferred),
fresh-controller API recovery replay, multi-node/off-node/catalog/task-replacement
matrix (existing B3 core evidence), production secret-delivery integration,
per-inner CPU enforcement, disk-full/peak/large-load/retention and full-cluster
roles/globals/PITR. No outstanding blocker remains for the requested B2/B3 CLI
acceptance gates under the explicitly authorized fixture boundary.
