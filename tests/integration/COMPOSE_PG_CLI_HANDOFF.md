# Current-candidate Compose/local + S3 CLI subset

This is a development proof, **not the historical full 11-gate Compose/Swarm/file-restore matrix**, and not release approval. The subset happens to contain eleven named checks; the counts are not interchangeable.

## Provenance

- Core source fingerprint (sorted Go + go.mod + go.sum + Dockerfile): `2fd683f92a52b244ac452356cb4fd6de3567366348259ece09619c912e8b07ee`.
- Ordinary candidate Engine29 image-index ID: `sha256:ff1a6cd8e122b14c80da66396c6d14f06c22cc4c130e769def3a50520e9afca8`.
- Runner SHA256 at successful execution: `5f83bb87491e82c7987687030140aefafcb688e3738538d65b8db787eb9c5e8d`.
- Successful receipt SHA256: `520a7bc2c7eeb3f7bd989ada19396dc5404136c3e6fc876154a6c6e98c7da5cf`.
- Evidence root: `/home/tamnt/.hermes/cache/scratch/bakabel-compose-cli-current/`.
- Parent independent verifier: `verify.py`; readback report `parent-verification.json`.

## Actual results

`run-02` exited0; parent verifier exited0. Both local and authenticated disposable S3 backends exercised:

- Public `plan/run/snapshots/restore` with ordinary `_workflow` candidate workers, no relay or runtime-policy workaround.
- Mixed PostgreSQL/file backup while a source database write succeeds during the dump's controlled lock wait. Sources retain StartedAt and RestartCount throughout backup/fault stages.
- Second file backup reuses the exact first parent, one unchanged file, zero new data blobs; complete payload is read back using Restic. **No file restore** was invoked.
- Worker SIGKILL fails closed; competing run refused, exact source exec terminal and matching sessions zero before ownership release; no complete PG target snapshot for that failed run. Earlier completed file-target snapshots may legitimately remain.
- Restoring an empty original database through its physical identity is refused without writing.
- Source containers/volumes and old backup state are deleted deliberately only for the independent restore stage. Fresh target roles have different OIDs. Incorrect initial database owner/ACL is refused before import; prepared owner/ACL permits real20,000-row restore with checksum, object owner/SELECT privilege and database owner/ACL readback.
- Local database ACL exercises NULL/default semantics. S3 exercises PUBLIC CONNECT revoked and a named-role CONNECT grant option, not raw OID comparison.
- S3 outage additionally fails without false PG completion and obtains exact terminal/release proofs.

Observed fault durations were7.840s local worker SIGKILL,8.119s S3 worker SIGKILL and22.588s S3 outage. These are fixture observations, not universal recovery promises.

All nine successful-attempt workers had live samples of `cpu.max=200000 100000` and `memory.max=536870912`; no sampler errors. Exact sampled process affinity was pinned using the inherited resource-probe method. Rootless cpuset/startup gaps remain: this does not prove continuous from-birth affinity or aggregate all-process CPU quota.

## Boundaries and cleanup

The existing rootless Engine was used only for scoped synthetic sources/operator containers and exact-owned cleanup. It was not reconfigured/restarted, no Swarm init was performed, and no production volume was mounted/read. File-restore preflight inventories all daemon consumers and can mount backing paths; therefore that path was intentionally **not** exercised on the shared Engine. Swarm and full file restore still need a supported isolated runtime.

Parent fresh exact readback confirms45 containers/9 volumes absent for run-02 and16 containers/4 volumes absent for run-01, private data/credentials/binary copies absent, and primary Swarm remains inactive. Counts include already-removed exact owned anonymous volumes. Shared toolchain/image/module/build caches are retained.

`run-01` remains exit1 with four completed subset checks: Docker already removed an anonymous image volume during `DELETE container?v=true`, and the harness incorrectly demanded a subsequent volume DELETE return success rather than accepting404. A focused regression was run RED, the cleanup now allows only missing exact owned volumes and still reads back absence, and all Python tests passed. This was not a core backup/restore defect and the failed attempt was not relabeled PASS.

## Reproduction

From the Bakabel source root, use a fresh disposable output directory and locally verified baseline-compatible MinIO binary:

```sh
taskset -c 0,1 python3 tests/integration/fixtures/run_compose_pg_acceptance.py \
  --runtime "$NEW_RUNTIME" --source "$PWD" \
  --minio-binary "$VERIFIED_MINIO" --image bakabel-development:resource-candidate
```

The runner fails closed on the exact current source/image fingerprints. It is not a generic user-data backup command. Default unit tests do not contact Docker; actual runner execution is explicit opt-in. Never interpret this subset as Swarm or file-restore acceptance.
