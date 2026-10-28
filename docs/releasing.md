# Publishing a GHCR image

[Publish GHCR](../.github/workflows/release.yaml) is manual-only. It publishes an
image, not a deployment or a GitHub Release. Adding this workflow does not mean
an image has been published. Only `linux/amd64` is built, using the supplied
Dockerfile and `GOAMD64=v1`. Build and test parallelism follows the runner's
available resources; machine-local CPU budgets are not embedded in the workflow.

## Before dispatch

1. Review and commit the intended source, including release automation changes.
2. Obtain a successful **push-triggered** `ci.yaml` run and a successful
   **manually dispatched** `acceptance.yaml` run with **scope `all`, case `all`
   on that exact commit**. PR CI tests a synthetic merge checkout and is not
   accepted as exact-head evidence. A new commit needs new runs; prior evidence
   cannot authorize a different SHA. Isolated fault runs do not count.
3. Open **Actions → Publish GHCR → Run workflow**, select that same commit's
   branch/ref, and supply `version` (default `v0.1.0`, strictly `vN.N.N`, no leading
   zeros, prereleases or build metadata), `ci_run_id` and `acceptance_run_id`.
   Run IDs are the numeric suffixes of the two Actions run URLs, not job IDs.

The gate reads GitHub with the job's `GITHUB_TOKEN`. Both workflow paths, head
SHAs, expected event types and successful terminal states must match. Missing or
unrecognized events fail closed. Every CI job must succeed;
acceptance must have exactly `selection`, `acceptance (core-resources, all)`,
`acceptance (capacity, all)` and `acceptance (faults, all)`, all successful.
Missing/truncated job listings fail closed. These known names deliberately bind
the gate to the current acceptance matrix; review the gate if that matrix changes.

## Publication and consumption

The canonical image is `ghcr.io/<lowercase-owner>/<lowercase-repository>`.
Tags are the requested version and `sha-<full-40-character-commit>`; there is no
`latest`. Both tags must be absent: authenticated registry manifest **404** is
required, while auth failures, throttling and other errors stop publication.
Registry token and manifest requests refuse all redirects, including same-origin
redirects, so Authorization is never forwarded to a redirect target.
The workflow serializes releases, but GHCR does not provide atomic tag creation:
keep it the sole tag writer; an external writer can race the existence check.

Restic version and Bakabel's actual invalid-argument/usage exit are checked
without network, mounts or a Docker socket before login/push. OCI source,
revision and version labels identify the exact checkout. Registry credentials
are passed via stdin/HTTP headers, stored only in a private `RUNNER_TEMP` Docker
config, and logged out/removed in an always-run cleanup step. No PAT is required;
only the publishing job receives `packages: write` alongside contents/actions read.

After both pushes, their registry digests must agree. The job's `digest` output
and Actions summary provide the immutable `ghcr.io/owner/repository@sha256:…`
pull reference. Copy that **actual reference** for controller and worker image
configuration; never invent a digest or treat a version tag as immutable.
GHCR package access/visibility policy still applies; the workflow does not change
visibility or promise anonymous pulls. Confirm visibility separately if needed.

A push is not transactional: interruption can leave one published tag. The
workflow refuses to overwrite it on rerun; inspect the actual package and obtain
explicit approval for any recovery/deletion. Do not auto-delete or silently reuse
an existing tag. No production changes, deployment, upgrade or backup run occur.
