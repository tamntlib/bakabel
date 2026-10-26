package docker

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Exercise the production POSIX script with a synthetic pg_dump process; real
// PostgreSQL/archive and source lifecycle acceptance is a separate runtime gate.
func TestDumpScriptChildStatusAndLiteralArguments(t *testing.T) {
	run := "bakabel_0123456789abcdef0123456789abcdef"
	d := Dump{RunID: run, Database: "db ' $(touch SHOULD_NOT_EXIST); \\host=evil", User: "postgres"}
	argv, err := dumpCommand(d)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyDumpCommand(d)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(argv[5:], legacy[1:]) || strings.Contains(dumpScript, d.Database) {
		t.Fatal("connection value entered shell source")
	}
	for _, code := range []string{"0", "9"} {
		t.Run(code, func(t *testing.T) {
			dir := t.TempDir()
			fake := filepath.Join(dir, "pg_dump")
			script := `#!/bin/sh
[ "$BAKABEL_RUN_ID" = "$EXPECTED_RUN" ] && [ "$PGAPPNAME" = "$EXPECTED_RUN" ] || exit 83
[ "$#" = 5 ] && [ "$1" = --no-password ] && [ "$2" = --dbname ] && [ "$3" = "$EXPECTED_CONN" ] && [ "$4" = --format=custom ] && [ "$5" = --compress=gzip:9 ] || exit 84
printf PGDMPfixture
exit "$TEST_EXIT"
`
			if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			args := append([]string(nil), argv[1:]...)
			args[1] = strings.Replace(dumpScript, "/usr/local/bin/pg_dump", `"$TEST_DUMP"`, 1)
			cmd := exec.Command(argv[0], args...)
			cmd.Dir = dir
			cmd.Env = append(pgEnv(""), "EXPECTED_RUN="+run, "EXPECTED_CONN="+legacy[3], "TEST_DUMP="+fake, "TEST_EXIT="+code)
			raw, err := cmd.Output()
			if code == "9" {
				if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 9 {
					t.Fatal("child failure not preserved", err)
				}
				if !bytes.Equal(raw, []byte("PGDMPfixture")) {
					t.Fatal("failure emitted completion")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				s := newDumpStream(&out, run)
				if _, err = s.Write(raw); err != nil {
					t.Fatal(err)
				}
				if err = s.Finish(); err != nil || out.String() != "PGDMPfixture" {
					t.Fatal("producer protocol mismatch", err)
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "SHOULD_NOT_EXIST")); !os.IsNotExist(err) {
				t.Fatal("connection interpreted as shell source")
			}
		})
	}
}
