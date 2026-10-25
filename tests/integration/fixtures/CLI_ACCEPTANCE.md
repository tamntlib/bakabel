# Actual CLI acceptance on an owned isolated Engine

`run_cli_acceptance.py` exercises the copied, merged application through its real
`--config plan`, `run`, `snapshots` and `restore` CLI. It creates an entirely new
Engine, real Swarm services and authenticated MinIO; it never initializes host
Swarm or mounts host/private production volumes. No provider or Engine reply is
fabricated. All contents and credentials are synthetic.

## Run

From the repository root, provide the actual fixture binary paths explicitly:

```sh
docker build --build-arg BUILD_CPUSET=0,1 --cpuset-cpus 0,1 \
  --cpu-period 100000 --cpu-quota 200000 \
  -t bakabel:acceptance .
taskset -c 0,1 python -m unittest discover \
  -s tests/integration/fixtures -p 'test_cli_*.py' -v
taskset -c 0,1 python tests/integration/fixtures/run_cli_acceptance.py \
  --runtime "$TMPDIR/bakabel-cli-acceptance-NEW" \
  --image bakabel:acceptance \
  --minio /absolute/path/to/verified/minio \
  --restic /absolute/path/to/extracted/restic
```

The runtime path MUST NOT already exist. Images `docker:29.6.1-dind` and
`postgres:18.6-alpine3.24` must be locally available. The MinIO baseline-compatible
binary must come from the pinned upstream fixture build documented in the sibling
fixture README; extract Restic from the pinned image. Missing inputs fail rather
than falling back to a developer's private scratch path. No credentials are
arguments: the explicit operator Restic init and actual application use file
references. Credentials and restore/state/backend data are deleted at exit;
small JSON receipts, create-resource omissions and HTTP status logs remain.

## Deliberate fixture-only boundary

This rootless nesting supports an outer Engine container quota but cannot create
inner CPU-constrained cgroups. Before enabling `cli_relay.py`, the runner asserts:

- actual owned inner daemon ID differs from actual host daemon ID;
- actual outer `cpu.max` equals `200000 100000`;
- actual outer daemon PID1 affinity equals `0-1`.

The relay removes ONLY `HostConfig.NanoCpus`, `CpusetCpus`, `CpusetMems` from real
ContainerCreate requests, records each omitted key/value and forwards all real
requests/replies. It does not filter inventory, consumer roots, task/placement,
source identity, ACL, status or physical alias checks. The production source's
2-CPU defaults and `_workflow` entrypoint remain unchanged. The image is built
from the actual scratch Dockerfile without test instrumentation or a build tag.

This proves functional behavior under an outer aggregate two-core limit, NOT
per-inner-container cgroup enforcement or affinity for every Docker exec. Real
inner bridge networking reaches MinIO at the bridge gateway; no bridge-to-host
mapping and no network-default production modification is needed. No host ports
are published. The outer network is an owned internal bridge.

A Docker save/load crossing the host containerd image store into an inner classic
store may change inspect `.Id` from the outer manifest index to the inner config
image ID. The runner reads the actual inner image ID after loading and freezes
that immutable ID in its config. It never substitutes an absent image ID.

The HTTP relay supports bidirectional upgraded streams with half-close and
prevents response-header buffering from consuming the first raw stream bytes.
Unit tests exercise those transport invariants and narrow CPU-only mutation.

## Cases

- Two real local-file CLI backups; exactly one unmodified `_workflow` worker per
  overall run; stable path/hostname parent and unchanged-file/no-new-data result.
- Source and old state deleted, fresh-state snapshots and independent explicit
  daemon-native directory and new unused option-free local-volume restores;
  full payload plus mode `0640`, UID/GID `1234:2345` read back in the real engine.
- Snapshot source's actual backing is emptied after deleting its only consumer;
  the same backing bound at an unrelated native pathname is refused by the CLI,
  proving the snapshot physical-identity gate independently of lexical names or
  active-consumer overlap.
- Real consumer bind alias is refused with an unchanged empty destination.
- Two volume names genuinely resolve to one backing inode; the configured
  bind-option alias is refused as an unsupported restore volume.
- Actual Restic operator retags create unknown/partial repository classifications;
  the CLI refuses both before destination writes. This is a status-refusal test,
  not a claim of generating Restic exit 3 (already covered by B3 core fixtures).
- Service-level Swarm labels without task-container opt-in labels, actual
  same-manager tasks, frozen container/incarnation/daemon identity and one mixed
  PostgreSQL/files workflow to real authenticated S3 using explicit RO credential
  file mounts and unchanged real bridge mode.
- Source services, source volumes and old state deleted, independent PostgreSQL
  restore: wrong owner/ACL refused, operator prepares roles/owner/ACL, then all
  20,000 rows/count/sum/ordered-content digest and table/database ownership plus
  PUBLIC CONNECT ACL read back. File payload/ownership also read back from S3.
- Worker SIGKILL while a real PG dump waits for a fixture SQL lock: stopped
  controller retains durable owner; replacement CLI cannot create a worker;
  resumed original CLI performs bounded concrete recovery and reports failed,
  not success. Exact exec terminal, no matching sessions/processes, no complete
  snapshot and owner release are asserted.
- Actual MinIO stop after an authorized/started source export: unlock source
  while provider is down, original immutable timeout is exercised, restore
  provider during the bounded cleanup budget, then check the same terminal,
  ownership and no-false-success assertions.

`receipt.json` and the actual run log are the evidence; merely building the image
or reaching an earlier PASS line is not acceptance of later cases. Failed attempts
are retained and must not be presented as whole-suite success.

Not included: B4 serve/schedule/retention/notification, multi-node catalog replay,
production secret delivery, per-inner cgroup support, resource peak accounting,
production datasets, retention/disk-full or full cluster/PITR restores.
