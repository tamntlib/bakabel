# Configuration

Start with [the minimal example](../deploy/bakabel.example.yaml). It is a template, not a ready-to-run config: replace `REPLACE_WITH_DOCKER_IMAGE_ID` with `docker image inspect bakabel:local --format '{{.Id}}'`. Use that same immutable image for the controller. Mutable tags are rejected by `worker_image`; a local `sha256:…` image ID or digest-pinned image reference is required.

| Required field | Meaning |
|---|---|
| `version: 1` | Schema version; retain it. |
| `installation` | Stable installation identity; must match controller container label `bakabel.installation`. |
| `platform` | Exactly `compose` or `swarm`. |
| `scope` | Nonempty allowlist of existing Compose project / Swarm stack names, not the independent backup project's name. |
| `repository` | One absolute local repository path visible inside the controller, or Restic S3 repository URL. |
| `credentials.password_file` | Absolute path to a protected repository-password file, mounted read-only. |
| `worker_image` | Reviewed immutable image identity, available on the same daemon. |

No central service or mount list is needed. No enable/consistency switches or per-source schedule exist. Unknown keys, duplicate keys, YAML anchors/aliases and multiple documents are rejected. Config is bounded to 64 KiB.

## Omitted defaults

The examples intentionally omit `docker_socket` (`/var/run/docker.sock`), `state_dir` (`/var/lib/bakabel`), `timeout` (`30m`) and `timezone` (`UTC`). Override only for a real operational need, and match the controller mounts. State must be a private persistent directory (0700); do not share it with repository/credential storage or place runtime paths only in the container writable layer.

`schedule` is optional for one-shot commands and required by `serve` and `health`. The example sets `0 2 * * *`. It is five-field cron (minute, hour, day-of-month, month, day-of-week), with lists/ranges/steps and month/day names. No seconds, `@daily`, inline timezone, or fallback for an invalid expression. Set an IANA `timezone` only when UTC is not wanted. Only a running `serve` process schedules backups; writing a schedule into YAML does not start it.

## Worker resource ceilings

`worker_resources` is optional. Omitted or zero fields select **2 CPUs** and
**512 MiB memory**; zero does not disable a ceiling. These are limits, not
reservations or a claim that every repository fits. The memory default is a
starting point informed by a measured small workload, not a large-index bound.
Use only the override you need, for example:

```yaml
worker_resources:
  memory_mib: 1024
```

`cpus` and `memory_mib` accept nonnegative integers, with overflow rejected.
Docker receives the effective CPU quota and memory limit for each new worker;
Restic's `GOMAXPROCS` follows the effective CPU count. The scheduler is not
limited by these keys, and PostgreSQL exec runs in the source/target container,
outside the worker cgroup. Daemon/kernel support is an operational prerequisite:
inspect actual enforcement instead of assuming a successful create means that
limits took effect. Resource exhaustion is a failure, not permission to mark a
partial backup complete or release uncertain ownership. Changing these values
does not update an already running/adopted worker.

## Credential delivery

| Reference | Operator supplies | Recovery requirement |
|---|---|---|
| `credentials.password_file` | Repository decryption password file from the secret manager; no literal value in config. | Keep an independently retrievable copy outside the source host. |
| `credentials.s3_credentials_file` (optional) | Protected AWS shared-credentials file for the chosen S3 backend. | Recover/rotate access credentials separately from the irreplaceable repository password. |
| `notification_url_file` (optional) | Protected file containing the webhook endpoint, including any secret URL component. | Recreate from the secret manager; do not commit the endpoint. |

Explicit controller bind mounts or operator-managed volumes must expose these files read-only. Workers created by Docker API do **not** automatically inherit native Swarm Secret mounts. Bakabel resolves its supported password/S3 references from inspected controller mounts; do not rely on environment-secret interpolation or Swarm inheritance. Do not source `.env`, use secrets in labels, or add credential-value CLI flags.

For S3, replace `repository` with the provider's Restic URL and add only the needed references, for example this **config fragment** (not a second backend block):

```yaml
repository: s3:https://s3.example.invalid/backup-bucket/bakabel
credentials:
  password_file: /run/secrets/restic-password
  s3_credentials_file: /run/secrets/aws
  s3_region: operator-selected-region
```

Replace the deliberately non-routable endpoint/region, mount `/run/secrets/aws` explicitly, arrange network access, and initialize the intended repository explicitly with Restic before use. This guide does not provision a bucket or run an external S3 backup. Do not disable TLS verification to fix connectivity.

## Optional retention and notifications

Both are off when omitted. A retention map has only `daily`, `weekly`, `monthly` counts (each defaults to zero); **no enable field**. After a verified independent restore and explicit approval of deletion, a possible policy fragment is:

```yaml
retention:
  daily: 7
  weekly: 4
  monthly: 6
```

These are example retention counts, not an approved policy. See [operations](operations.md) for locking and complete-only candidates. Retention runs inside the existing worker only after the data run is complete. For a failure webhook, add only `notification_url_file: /run/secrets/notification-url` and its explicit read-only controller mount; do not put an actual endpoint in Git. The controller sends notifications; the worker does not need this file.
