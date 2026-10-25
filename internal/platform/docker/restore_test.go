package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRestoreLiteralConnection(t *testing.T) {
	for _, db := range []string{"a=b", "a b", "postgresql://evil:secret@remote/other", `a'\\ host=remote user=evil dbname=oops`} {
		got, e := restoreConninfo(db, "postgres")
		if e != nil {
			t.Fatal(e)
		}
		expected := "host='/var/run/postgresql' port='5432' user='postgres' dbname='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(db) + "'"
		if got != expected {
			t.Fatalf("%q != %q", got, expected)
		}
	}
	for _, db := range []string{"", "nul\x00db", strings.Repeat("x", 257)} {
		if _, e := restoreConninfo(db, "postgres"); e == nil {
			t.Fatal("invalid literal accepted")
		}
	}
}

func TestRestoreStockBaseline(t *testing.T) {
	if e := checkRestoreInventory([]byte(restoreBaseline)); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"namespaces", "objects", "extensions", "global_objects", "namespace_policies"} {
		var v map[string]any
		json.Unmarshal([]byte(restoreBaseline), &v)
		v[field] = append(v[field].([]any), map[string]any{"unexpected": true})
		raw, _ := json.Marshal(v)
		if e := checkRestoreInventory(raw); e == nil {
			t.Fatal("dirty inventory accepted", field)
		}
	}
	for _, bad := range []string{"{}", "null", "[]", restoreBaseline + " trailing"} {
		if e := checkRestoreInventory([]byte(bad)); e == nil {
			t.Fatal("invalid inventory accepted")
		}
	}
}

func TestRestoreBrokenTransportDoesNotWaitForStillRunningExec(t *testing.T) {
	d := RestoreExec{Target: Source{"daemon", "target", "start"}, ExecID: "restoreexec", RunID: "restore_token_0123456789", Database: "db", User: "postgres"}
	args, _ := restoreArgs(d)
	started := false
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/target/json":
			io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"}}`)
		case "/v1.55/exec/restoreexec/start":
			started = true
			w.WriteHeader(500)
		case "/v1.55/exec/restoreexec/json":
			json.NewEncoder(w).Encode(map[string]any{"ID": "restoreexec", "ContainerID": "target", "Running": started, "Pid": 0, "ExitCode": nil, "ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": args}})
		default:
			w.WriteHeader(404)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, e := c.StreamRestoreExec(ctx, d, io.NopCloser(strings.NewReader("archive")))
	if e == nil {
		t.Fatal("broken transport accepted")
	}
	if time.Since(begin) > 300*time.Millisecond {
		t.Fatal("waited for running exec instead of returning for exact cancellation")
	}
}

func TestRestoreNeverRestartsTerminalExec(t *testing.T) {
	d := RestoreExec{Target: Source{"daemon", "target", "start"}, ExecID: "restoreexec", RunID: "restore_token_0123456789", Database: "db", User: "postgres"}
	args, _ := restoreArgs(d)
	started := false
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/target/json":
			io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"}}`)
		case "/v1.55/exec/restoreexec/json":
			json.NewEncoder(w).Encode(map[string]any{"ID": "restoreexec", "ContainerID": "target", "Running": false, "Pid": 0, "ExitCode": 0, "ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": args}})
		case "/v1.55/exec/restoreexec/start":
			started = true
			w.WriteHeader(500)
		default:
			w.WriteHeader(404)
		}
	})
	if _, e := c.StreamRestoreExec(context.Background(), d, io.NopCloser(strings.NewReader("archive"))); e == nil || started {
		t.Fatalf("terminal exec restarted: start=%v err=%v", started, e)
	}
}

func TestRestoreTerminalProofDoesNotInventNeverStarted(t *testing.T) {
	d := RestoreExec{Target: Source{"daemon", "target", "start"}, ExecID: "restoreexec", RunID: "restore_token_0123456789", Database: "db", User: "postgres"}
	args, _ := restoreArgs(d)
	controlOutput := ""
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/target/json":
			io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"}}`)
		case "/v1.55/exec/restoreexec/json":
			json.NewEncoder(w).Encode(map[string]any{"ID": "restoreexec", "ContainerID": "target", "Running": false, "Pid": 0, "ExitCode": 0, "ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": args}})
		case "/v1.55/containers/target/exec":
			var cfg ExecConfig
			json.NewDecoder(r.Body).Decode(&cfg)
			controlOutput = ""
			if strings.Contains(cfg.Cmd[len(cfg.Cmd)-1], "SELECT count(*)") {
				controlOutput = "0\n"
			}
			io.WriteString(w, `{"Id":"controlexec"}`)
		case "/v1.55/exec/controlexec/start":
			w.Write(frame(1, controlOutput))
		case "/v1.55/exec/controlexec/json":
			io.WriteString(w, `{"ID":"controlexec","ContainerID":"target","Running":false,"Pid":0,"ExitCode":0}`)
		default:
			w.WriteHeader(404)
		}
	})
	proof, e := c.CancelRestoreExec(context.Background(), d)
	if e != nil || proof.ExecExitCode == nil || *proof.ExecExitCode != 0 || proof.ExecNeverStarted || !proof.NoProcesses || !proof.NoSessions {
		t.Fatalf("completed process is NOT never-started: %+v %v", proof, e)
	}
}

func TestRestoreCheckpointPrecedesStart(t *testing.T) {
	started := false
	persisted := false
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/target/json":
			io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"}}`)
		case "/v1.55/containers/target/exec":
			var cfg ExecConfig
			json.NewDecoder(r.Body).Decode(&cfg)
			if cfg.Cmd[0] != "/usr/local/bin/pg_restore" || !cfg.AttachStdin || cfg.Tty {
				t.Error(cfg)
			}
			io.WriteString(w, `{"Id":"restoreexec"}`)
		case "/v1.55/exec/restoreexec/start":
			started = true
			if !persisted {
				t.Error("started without checkpoint")
			}
			w.WriteHeader(500)
		default:
			w.WriteHeader(404)
		}
	})
	p := RestorePostgresTarget{postgres: Postgres{Source: Source{"daemon", "target", "start"}, Database: "db", User: "postgres"}, prepared: true}
	d, e := c.CreateRestoreExec(context.Background(), p, "restore_token_0123456789", func(d RestoreExec) error {
		persisted = true
		if d.ExecID != "restoreexec" || d.Target != p.postgres.Source || d.Database != "db" || d.RunID == "" {
			t.Error(d)
		}
		return nil
	})
	if e != nil || !persisted || started || d.ExecID != "restoreexec" {
		t.Fatal(d, e, persisted, started)
	}
	// Persist failure must never issue exec start; the unstarted checkpoint remains identifiable.
	_, e = c.CreateRestoreExec(context.Background(), p, "restore_token_0123456789", func(RestoreExec) error { return io.ErrClosedPipe })
	if e == nil || started {
		t.Fatal("persistence failure started restore")
	}
	if _, e = c.CreateRestoreExec(context.Background(), p, "restore_token_0123456789", nil); e == nil {
		t.Fatal("untracked exec accepted")
	}
}
