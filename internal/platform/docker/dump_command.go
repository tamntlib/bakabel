package docker

import "slices"

// Values are positional arguments, never shell source. Only the pg_dump child
// has a run-tagged environment: the existing PID scanner must not match the
// parent shell. printf is a POSIX shell builtin, not an installed source agent.
const dumpScript = `run=$1
shift
BAKABEL_RUN_ID="$run" PGAPPNAME="$run" /usr/local/bin/pg_dump "$@"
code=$?
[ "$code" -eq 0 ] || exit "$code"
printf '\000BAKABEL_EXPORT_COMPLETE_V1:%s\000' "$run"`

func legacyDumpCommand(d Dump) ([]string, error) {
	conn, err := (Postgres{Database: d.Database, User: d.User}).conninfo()
	if err != nil || !validToken(d.RunID) {
		return nil, ErrQuarantine
	}
	return []string{"/usr/local/bin/pg_dump", "--no-password", "--dbname", conn, "--format=custom", "--compress=gzip:9"}, nil
}

func dumpCommand(d Dump) ([]string, error) {
	argv, err := legacyDumpCommand(d)
	if err != nil {
		return nil, err
	}
	return append([]string{"/bin/sh", "-c", dumpScript, "bakabel-export-v1", d.RunID}, argv[1:]...), nil
}

func matchesDumpExec(x ExecStatus, d Dump, allowLegacy bool) bool {
	if x.ID != d.ExecID || x.ContainerID != d.Source.ContainerID {
		return false
	}
	argv, err := dumpCommand(d)
	if err == nil && x.ProcessConfig.Entrypoint == argv[0] && slices.Equal(x.ProcessConfig.Arguments, argv[1:]) {
		return true
	}
	if allowLegacy {
		argv, err = legacyDumpCommand(d)
		return err == nil && x.ProcessConfig.Entrypoint == argv[0] && slices.Equal(x.ProcessConfig.Arguments, argv[1:])
	}
	return false
}
