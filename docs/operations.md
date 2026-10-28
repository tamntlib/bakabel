# Operations

## Outcomes and durable state

Treat command exit status **and** JSON target receipts as evidence. Overall backup success requires all required targets complete, exact repository readback and terminal source-export proof. Earlier complete targets remain valid if a later target fails; the run is not atomic. A target may return both a snapshot ID and an error. Repository snapshots start `unknown` and become `complete` only after verified success; partial/error snapshots are not elevated merely because they exist.

PostgreSQL export additionally requires the run-correlated producer completion trailer, not merely Docker EOF and exec exit zero. See [streaming verification and trust assumptions](streaming.md); this is suffix-loss detection, not arbitrary-corruption authentication.

Useful bounded state under the default `/var/lib/bakabel`:

| Path | Meaning |
|---|---|
| `owner.json` | Current durable run ownership/checkpoint; never delete it to bypass an overlap or quarantine. |
| `last-result.json` | Last terminal result plus `operation`, `finishedAt` and retained `lastBackupSuccessAt`; not proof the scheduler is alive. |
| `workflow/job.json` | Fixed current/last workflow job, not an append-only history. |
| `workflow/output/result.json` | Bounded workflow target receipts, not the repository recovery catalog. |

Do not edit these files as recovery instructions. Worker death, a lost socket, elapsed time or a restarted scheduler is not proof an external PostgreSQL exec ended. Ambiguous termination retains ownership/quarantine and blocks replacement. Preserve state and sanitized diagnostics; have an operator resolve exact worker/export identity. There is no documented public `recover`, `unlock`, or force-run CLI. Never use broad process kills, source restart/scale-down or Docker system prune as a backup cleanup step.

## Scheduler and external monitoring

`serve` sleeps until the configured five-field cron time, calls the same `run` pipeline synchronously and skips missed occurrences rather than replaying a burst. It does not run an immediate backup on an empty startup. Invalid cron/timezone or missing schedule fails validation. An existing durable worker is monitored with its original creation-time deadline; restarting the controller does not renew the deadline or create a replacement worker. Unproven recovery retains ownership and blocks new work.

After the one-shot backup and independent restore drill, operate exactly one scheduler/installation per repository. Starting the service is a separate operator action, not a documentation validation step:

```bash
docker compose -p bakabel-backup -f deploy/compose.example.yaml up -d scheduler
docker compose -p bakabel-backup -f deploy/compose.example.yaml exec -T scheduler \
  /usr/local/bin/bakabel --config /etc/bakabel/bakabel.yaml health
```

The examples allow 30 seconds for controller shutdown: concrete cleanup has a fresh 20-second budget and a failure notification can take up to 5 seconds. A cleanup deadline never authorizes a forced ownership release.

`health` reads bounded state and the clock without Docker API calls, writes or notifications. Its JSON distinguishes `never`, `healthy`, `overdue`, `failed`, `running` and `blocked`. It requires a configured schedule; the overdue boundary is the next scheduled occurrence after `lastBackupSuccessAt`, plus the configured timeout. No prior verified backup, overdue success, failed outcome or blocked state returns nonzero. An active run does not hide an overdue last success. Restore and failed/no-target runs never advance the last successful **backup** timestamp.

A dead scheduler cannot run its own check. Independently monitor the container/process and invoke the read-only health command from a separate monitor with the same config/state references. Also validate repository snapshot status and expected source coverage: Compose services with no remaining container metadata cannot be discovered. A fresh timestamp is not a substitute for a restore drill. There is no embedded HTTP monitoring server.

## Retention: off until a restore is proven

Omit `retention` during initial setup. All daily/weekly/monthly counts default to zero, which disables it. Only after an independent restore drill **and explicit operator approval of deletion policy** should nonzero counts be configured. There is no product approval workflow or enable flag.

Retention uses native Restic `forget` and, only after candidates were actually removed and protected snapshots read back, `prune`. It groups by stable `host,paths`, considers only valid `complete` snapshots belonging to this installation, and protects partial/unknown/foreign snapshots. It runs inside the existing worker **under the same installation lock**, only after a complete nonempty backup, never after a failed/unknown/no-target run or restore. Test the chosen policy on a disposable repository before enabling it for real backups.

A retention error is reported separately as `maintenanceError: "retention failed"`: verified data can remain `complete`, but the overall command returns nonzero. It does not erase a successful data-backup timestamp or turn a failed data target into success.

Low-level Restic operations performed outside Bakabel are **not** covered by Bakabel's mutex. Arrange an exclusive operator maintenance window: no overlapping backup/restore/retention or other repository clients. Keep native Restic locks; do not use `--no-lock`, automatic `unlock`, or manual snapshot/tag changes to bypass safety. Repository checks complement, not replace, a restore drill.

## Notifications

An optional `notification_url_file` references a protected webhook endpoint file; it is not an inline URL field. CLI `run`/`restore` and scheduled failures send a bounded JSON POST with `installation`, optional `run_id`, and `failed`/`blocked` status, accept only a 2xx result and do not follow redirects. No dump, source credentials, raw endpoint or response body belongs in diagnostics.

Notification delivery errors are logged separately and never replace the backup error or change the data result. There is no unbounded retry loop. `health` does not send overdue webhooks: external overdue/dead-process monitoring is mandatory, including when the controller cannot run at all.

## Capacity and recovery checks

- Streaming avoids full local database dump or tar staging; Restic indexes/cache/temp, logs, source export work and destination database/WAL still consume resources. Uploaded blocks from a failed producer can remain unreferenced in the repository; failure is not a promise of zero remote disk use.
- Keep repository and decryption keys recoverable outside the source host. A persistent local repository survives container replacement, not loss of its disk/server. Do not classify repository data as temporary cache.
- Upgrade controller and configured worker image together, retaining a reviewed immutable build. Recheck discovery and perform a disposable restore drill before enabling schedules or retention. Do not change application services as part of a Bakabel deployment.
- Use [resource defaults and sizing](resources.md) and [testing](testing.md) to plan a disposable capacity/recovery drill. Bounded fixture workloads are not universal memory, physical-I/O or recovery-time guarantees.
