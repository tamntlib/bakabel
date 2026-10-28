# Restore drill and recovery

A backup is not accepted until a separate restore has been checked. Recover repository access and its decryption key from outside the lost host. Keep the reviewed Bakabel image/build source available too. Neither the source container nor old scheduler state is required: provision fresh private state, explicit repository/credential mounts, Docker access and the matching controller labels on the recovery host. The config schema still requires `platform`/`scope`, but restore does not rediscover the source.

Allow capacity for the full restored data and PostgreSQL database/WAL/index growth. Streaming avoids a full **dump staging copy**, not the destination's storage requirement. Do not point a drill at a live application's storage or switch traffic automatically.

## Select one exact complete snapshot

With the mounted recovery configuration, use:

```bash
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler --config /etc/bakabel/bakabel.yaml snapshots
```

`snapshots` itself reads repository metadata without source containers, a Docker socket or old state. The Compose wrapper includes the runtime mounts needed for later restore. Review the source, type, timestamp, status and metadata; copy the exact final **64-character lowercase hexadecimal** `snapshotID`. Finalization can change an ID, so never use a pre-finalization receipt or infer the newest snapshot. `partial`, `unknown`, unsupported or ambiguous metadata is refused; there is no `latest`/force bypass.

Only restore **trusted archives**: PostgreSQL dumps can execute code during import. Below, replace `FULL_64_HEX_SNAPSHOT_ID` and target names yourself; the placeholders are deliberately not valid snapshot IDs.

## PostgreSQL: operator prerequisites, then import

1. Provision a separate trusted stock PostgreSQL **18.6** target container on the same Docker daemon, with its fixed `psql`/`pg_restore` tools and local `/var/run/postgresql:5432` superuser authentication. Supply its explicit container ID/name, literal database name and PostgreSQL user; no connection URI, password-value flag or remote client helper is implied.
2. Create a **fresh empty database**. The trusted baseline is a fresh stock template0-style catalog; Bakabel checks all non-system schemas/objects and supported extension baseline, not merely zero tables in `public`. Keep all application writers/DDL out of this target for the entire operation.
3. Recreate required roles/memberships, tablespace prerequisites and extension binaries separately. These are operator prerequisites, **not** backed-up globals or automatic role creation. Object owners and ACLs in the dump are preserved: no remapping or silent ownership/ACL stripping.
4. Read `metadata.postgres.owner` and `metadata.postgres.acl` from the selected snapshot. As operator, prepare the **database itself** with that owner and equivalent normalized ACL **before import**. Match role names, grantor, grantee, privileges and grant options, not cluster-local role OIDs. An empty metadata `grantee` means `PUBLIC`. PostgreSQL ACL `NULL` means its default ACL (including default PUBLIC privileges), not an empty permission set. Do not grant PUBLIC CONNECT just to bypass a mismatch.
5. Preflight must prove target cluster system identifier + database OID differ from the source fingerprint. A different hostname/name is not proof, and an empty source database is still forbidden. Unreadable identity, wrong owner/ACL, wrong version or nonempty target is a refusal before import. Operator changes to database owner/ACL are never applied automatically by Bakabel.

After satisfying and independently inspecting those prerequisites:

```bash
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler \
  --config /etc/bakabel/bakabel.yaml restore \
  --snapshot FULL_64_HEX_SNAPSHOT_ID \
  --postgres-container NEW_TARGET_CONTAINER \
  --database recovered_app --user restore_superuser
```

The database name is literal; it is not a libpq connection string. Import streams the exact dump into the explicit target and checks both repository reader and importer. No `--clean`, `--create`, drop/recreate, overwrite, role-remap, PITR/WAL or whole-cluster restore is offered. Database owner/ACL is read back after import; other database settings/comments are not implicitly cloned.

`restored` means the import met Bakabel's checks, **not** application acceptance. Verify representative row counts/content, schema, indexes, object owners/ACLs and database owner/ACL (including PUBLIC restrictions), then run application-level read tests. Record the exact snapshot/target identities and drill outcome before approving retention. A failure may leave a partially populated target: preserve diagnostics and do not rerun into it, delete it, or claim rollback automatically. Operator approval is required for any subsequent target replacement.

## Files: explicit empty native target

Use an exclusive disposable daemon for file-restore acceptance: the safety preflight inventories/mirrors consumer backing storage. Do not run these probes on a shared production daemon or weaken visibility/resource/security checks to make an unsupported topology pass. See [testing](testing.md) for the full directory/volume matrix and expected readbacks.

Choose exactly one:

- `--directory`: an operator-prepared, existing, empty **daemon-native absolute directory**, outside source, consumers, repository, state, config and credential storage. It is not a path translated from the controller's writable layer.
- `--volume`: an operator-created, unused, empty, option-free `local` Docker volume. Missing volumes are not automatically created. Do not mount it into an application before restoring.

```bash
# Choose ONE command, after preparing the corresponding isolated empty target.
docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler \
  --config /etc/bakabel/bakabel.yaml restore \
  --snapshot FULL_64_HEX_SNAPSHOT_ID --directory /srv/recovery/empty-files

docker compose -p bakabel-backup -f deploy/compose.example.yaml run --rm --no-deps scheduler \
  --config /etc/bakabel/bakabel.yaml restore \
  --snapshot FULL_64_HEX_SNAPSHOT_ID --volume operator-created-empty-volume
```

Physical source/target identity, aliases, nesting, emptiness and consumers must be provable. Same-storage aliases, network/plugin volumes, unsafe/global mount topology, inaccessible consumer roots or system-root mirrors fail closed. The worker mirrors only exact inspected consumer roots **read-only for metadata checks** and binds the explicit target writable; it does not mount host `/`. Do not weaken this proof when an unsupported topology is refused.

The stored per-source worker prefix is removed so file contents land at the requested target root. Verify content/checksums, path mapping, numeric UID/GID, modes and required metadata on the actual target. Runtime/filesystem permission capabilities are limits, not a promise of every platform's metadata semantics. Failed restores can leave partial data; no automatic overwrite, deployment or application mount switch occurs.
