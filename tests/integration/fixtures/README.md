# Integration fixtures

[Testing](../../../docs/testing.md) is the maintained guide for offline tests,
full hosted acceptance, optional isolated local fixtures, resource/fault/capacity
scopes, expected results and evidence limits. [Resources](../../../docs/resources.md)
explains worker defaults and sizing caveats.

These runners use disposable synthetic data. Hosted runners require the actual
exclusive GitHub-hosted environment and returned Engine socket; never spoof
admission on a VPS. Local core/CLI nesting is explicitly limited and does not
replace the full direct-Engine acceptance run. No fixture is a production
backup, deployment or cleanup command.
