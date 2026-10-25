# B3 handoff — verified core APIs, isolated Swarm and authenticated S3

## Outcome and files to merge

Merge **only** these new repository paths:

- `tests/integration/swarm_s3_test.go`
- `tests/integration/fixtures/run.py`
- `tests/integration/fixtures/build_minio.py`
- `tests/integration/fixtures/README.md`
- `tests/integration/HANDOFF.md`

No existing app/state/config/core file was edited. No commit, push, publication,
production credentials, host SwarmInit, published port, or global prune occurred.

Latest full fixture invocation returned exit **0**, all live tests PASS, including
actual second-node placement refusal and task replacement. Also passed:
`go test -p 2 ./...`, `go vet -p 2 ./tests/integration`, and
`go test -race -p 2 ./tests/integration` in a two-CPU/taskset Go container. Ordinary
non-opt-in test runs skip live fixtures; these are not substituted for the real
run below.

## Evidence and reusable binary

Workspace:
`/home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/work`

Live result/log/metadata:
`/home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/run-final/`

- `result.json`: actual commands, images, daemon IDs, effective CPU quota/affinity,
  MinIO inspect/startup, cleanup readbacks, synthetic-secret scan, artifact sizes.
- `tests.log`: actual PASS output and exact snapshot IDs.
- `artifacts/`: snapshot readbacks, explicit file jobs/worker mount inspections,
  terminal restore checkpoint. Total JSON metadata is **15,036 bytes**; no dump,
  tar, or local repository mirror. Restored fixture destination and backend data
  have been removed after verification.

Actual CPUv1-compatible MinIO binary:
`/home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/minio-build-proof/minio`

Build provenance: adjacent `build.json` / `build.log`. `build_minio.py` actually
ran successfully and its produced binary was used in the final live run. Source
and module build-container data were cleaned; the reusable binary/results remain.

Existing Restic binary supplied by parent:
`/home/tamnt/.hermes/cache/scratch/bakabel-b1-restic-cb8mtyxm/restic`

## Exact final identities and results

- Outer daemon `0aa014bc-f231-498e-8ff3-31c6b80841ef`: Swarm **inactive** before
  and after; remains inactive in independent final readback.
- Isolated manager daemon `02f47f4e-ef2d-40ef-86cd-0ef0f84ecc23`, node
  `7cwmfm6fys3mhng4wy77mrwlk`.
- Isolated worker daemon `87789ac9-84f7-4055-8dd6-089cc6b4e875`, node
  `1uibfdmkx5nnfzc8o21cylc8p`.
- Both outer engine containers: actual `cpu.max=200000 100000`, PID1 affinity
  `0-1`; actual source PostgreSQL PID1 affinity also `0-1`.
- PostgreSQL exact complete S3 snapshot:
  `89c2099f7c96d789023c72900731ecb879114ba819ff9c504c2badd52af14b39`.
  Restored **20,000 rows**, sum(id) **200,010,000**, matching ordered content
  digest and object/database owners/ACL into an independent cluster after source
  deletion. Online writer made 100 updates; source RestartCount remained 0 and
  StartedAt unchanged.
- Files complete:
  `da7987718f70290476365069233db62adbee934888a32ad6e48b287ac82eefe8`.
- Files unknown:
  `e714f4bf6f5e347adf5fc62564c2ef0d442eada1dca05a3b9c308fda5912e9b3`.
- Files partial, actual Restic exit 3:
  `ae1497c3d8d76ffec4211e369ff601f9ca5c1051d3caa4ac4c33a2d5569a5a7c`.
- Unknown/partial refused before restore writes; complete restored **4,194,323
  bytes**, mode **0640**, UID/GID **1234:2345** to an independent empty directory.
- Wrong S3 credentials produced actual `InvalidAccessKeyId` diagnostic. Restic
  retries this error; test bounds/cancels retries explicitly instead of claiming
  it naturally exits quickly. Wrong Restic password/missing repository exited
  with failure without deadline exhaustion. Real core Backup against missing
  prefix also failed without automatic init.
- Final inner manager readback: containers `[]`, services `[]`, volumes `[]`.
  All exact outer fixture containers/network absent; private data/secrets gone.
  Initial exploratory engine/build containers were separately removed and
  independently verified absent. Final `docker ps -a --filter name=bakabel-b3`
  and owned-network filter returned no resources.

## Pinned artifacts

Actual image identities read back from Docker:

```
docker:29.6.1-dind
  docker@sha256:66d292e5c26bd33a6f6f61cacb880de2186339a524ecba1ce098dbbaceed6515
postgres:18.6-alpine3.24
  postgres@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792
golang:1.26.8-bookworm
  golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107
```

Binary/source SHA-256:

```
MinIO binary  8d95c686a61111ed8a0e38a80b84423b164ef07499fe87416b1302a4e6f550e0
Restic binary 01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6
MinIO archive 267c949e03f6d931f3b2da07c067f02483cb2b2604b627e1eb9b96acb0fd9192
```

Official old MinIO Docker Hub pulls failed, Quay returned 401, and old binary
URL returned 410. Alternative used unmodified upstream release-tag source with
verified archive SHA and actual baseline static build/startup. Its honest version
string is `DEVELOPMENT.GOGET`, not an invented official image/version result.

## Re-run now

From this workspace, with a **new** runtime directory:

```sh
python3 tests/integration/fixtures/run.py \
  --restic /home/tamnt/.hermes/cache/scratch/bakabel-b1-restic-cb8mtyxm/restic \
  --minio-binary /home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/minio-build-proof/minio \
  --runtime /home/tamnt/.hermes/cache/scratch/bakabel-swarm-s3-wd9t1kj2/run-NEW \
  --worker
```

To hand fixtures to the CLI, retain `run.py`'s explicit engine/socket/network,
operator initialization and credential mounting. Replace only the test-runner
entrypoint with the actual CLI once merged. See README for actual API seams,
auth delivery, nested-cgroup limitation, Compose-zero limitation and acceptance
not proved. No CLI or scheduler success is claimed by this handoff.
