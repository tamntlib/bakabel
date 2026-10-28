# Deployment examples

These are independent backup deployments, **not** application manifests. Updating Bakabel must not redeploy sources. Start with the [README one-shot workflow](../README.md); do not run any backup against real data merely to validate a manifest.

## Compose

[deploy/compose.example.yaml](../deploy/compose.example.yaml) uses project `bakabel-backup` in the README, while config scopes the existing application project `myapp`. Set the exported `BAKABEL_IMAGE` and config `worker_image` to the same locally inspected immutable ID. Controller **container** labels must be `bakabel.role=scheduler` and `bakabel.installation=backup-main`, matching config exactly. Do not override its hostname: the controller resolves its own container through Engine inspect.

Prepare all absolute bind sources first, including private state and explicit read-only config/password files. `BAKABEL_HOME` selects their host parent directory (default `/srv/bakabel`); `DOCKER_SOCKET` selects the local socket bind source (default `/var/run/docker.sock`). Set the latter to the actual inspected socket for rootless Docker. Internal config paths stay unchanged. The example disables automatic bind-path creation. It publishes no port. Docker logs rotate; log rotation is not a backup history or an alert.

The service runs `serve`. Use the documented `compose run` overrides for `plan`, `run`, `snapshots` and an independent restore drill before starting the scheduled service. See [operations](operations.md) for the implemented `health` command and independent monitoring; a scheduler process cannot detect its own death. Use [testing](testing.md) for full acceptance and its limits; manifest validation alone is not runtime evidence.

## Swarm

[deploy/swarm.example.yaml](../deploy/swarm.example.yaml) is a separate backup stack. Before use:

1. Change config `platform` to `swarm` and scope it to the **application stack**, not the backup stack.
2. Replace `REPLACE_WITH_EXACT_MANAGER_NODE_ID`; constrain the controller and each selected single-replica source to that exact manager. Local volumes must already exist there. No cross-node relocation or primary guessing is supported.
3. Prepare the same absolute host paths **on that node**. Keep the locally built image available there, use its immutable ID for config and service, and avoid registry resolution for a local-only image. For a GHCR publication, first verify the actual package digest/access and pin the same immutable image for controller and worker; see [releasing](releasing.md).
4. Keep the controller's `labels` at container level even in Swarm. By contrast, **application source** labels belong in `deploy.labels`; see [source fragments](sources.md).
5. Perform a one-shot backup and independent restore drill before scheduling. A stack/config syntax pass does not establish backup, restore or lifecycle acceptance.

Swarm native secrets are **not** automatically inherited by the temporary worker. These examples deliberately use explicit operator-managed read-only credential **bind files**, which the controller can inspect and map for workers. A managed credential volume is another explicit mechanism; it must contain the real files and be inspectable. Do not replace it with an unexplained `secrets:` declaration and assume delivery works. Keep secrets out of Compose interpolation, Config.Env values, commands and labels.

## Offline parsing, without touching an Engine

After exporting a real local image ID, validate syntax against a deliberately absent Unix socket. Docker CLI/plugins may attempt `HEAD /_ping` even for parsing, so do **not** point these commands at the production context. The chosen absent path must remain absent; the example does not create a socket or contact an Engine.

```bash
export BAKABEL_IMAGE="${BAKABEL_IMAGE:?set from the earlier local image inspect}"
test ! -e "$PWD/deploy/ABSENT-validation.sock"
env -u DOCKER_CONTEXT DOCKER_HOST="unix://$PWD/deploy/ABSENT-validation.sock" \
  docker compose -p bakabel-backup -f deploy/compose.example.yaml config --quiet
env -u DOCKER_CONTEXT DOCKER_HOST="unix://$PWD/deploy/ABSENT-validation.sock" \
  docker stack config -c deploy/swarm.example.yaml >/dev/null
```

This validates Compose/stack rendering only, not Bakabel schema, image availability, source placement, credential delivery, or backup/restore behavior. Replace the invalid `worker_image` placeholder before using Bakabel's config loader. Do not execute secret preparation, deployment or backup commands as part of documentation lint.

## Security and mount boundaries

The root controller's Docker socket is root-equivalent even with `read_only: true`. Only trusted operators may edit config, placement, image identity, or controller mounts. Protect state, repository, config, all credential files and the socket from application source selection, aliasing and nesting. Default local **source** volumes have no driver options; runtime credential/config bind files are a separate, deliberately restricted mechanism, not permission to back up arbitrary source binds.

No scheduler host-root mount is needed. File restore may require read-only mirrors of exact inspected consumer roots at their daemon-native paths for metadata/alias proof; it does not grant an unrestricted host filesystem. Broad/system-root, inaccessible or opaque consumer topology can make restore unsupported. Exclude concurrent privileged Docker/mount administration during restore.
