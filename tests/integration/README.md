# Integration tests

See [Testing](../../docs/testing.md) for prerequisites, offline checks, the
mandatory full GitHub-hosted acceptance run, optional local fixtures, expected
results and evidence limits.

- [swarm_s3_test.go](swarm_s3_test.go) contains opt-in real Swarm/S3 core API tests.
  Ordinary Go discovery skips live tests without their fixture environment.
- [fixtures](fixtures) contains runners, observers, verifiers and their offline
  regression tests. They are disposable test infrastructure, not deployment tools.

Use only synthetic data on an exclusive disposable runtime. Do not execute
file-restore acceptance probes against a shared production Docker daemon.
