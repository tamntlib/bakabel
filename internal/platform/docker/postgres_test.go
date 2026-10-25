package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestLiteralConnectionAndPrerequisite(t *testing.T) {
	for _, entry := range pgEnv("bakabel_control_0123456789abcdef") {
		if entry == "PGSERVICE=" {
			t.Fatal("empty PGSERVICE selects a nonexistent named service instead of unsetting it")
		}
	}
	for _, name := range []string{"normal", "host=evil user=attacker", "postgresql://evil/db", "quote' slash\\ space"} {
		p := Postgres{Database: name, User: "postgres"}
		got, e := p.conninfo()
		if e != nil || !strings.HasPrefix(got, "host='/var/run/postgresql' port='5432' user='postgres' dbname='") || !strings.HasSuffix(got, "'") {
			t.Fatal(got, e)
		}
		if name == "quote' slash\\ space" && got != "host='/var/run/postgresql' port='5432' user='postgres' dbname='quote\\' slash\\\\ space'" {
			t.Fatal(got)
		}
	}
	if _, e := (Postgres{Database: "x", User: ""}).conninfo(); e == nil {
		t.Fatal("missing user accepted")
	}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"},"Config":{"Env":["POSTGRES_DB=fixture","POSTGRES_USER=postgres"],"Labels":{}}}`))
		case "/v1.55/containers/source/exec":
			var cfg ExecConfig
			json.NewDecoder(r.Body).Decode(&cfg)
			if cfg.User != "0" {
				t.Error(cfg)
			}
			if cfg.Cmd[0] == "psql" {
				if !strings.Contains(cfg.Cmd[len(cfg.Cmd)-1], "acldefault") || !strings.Contains(cfg.Cmd[len(cfg.Cmd)-1], "THEN ''") {
					t.Error(cfg)
				}
				w.Write([]byte(`{"Id":"metaexec"}`))
			} else {
				w.Write([]byte(`{"Id":"versionexec"}`))
			}
		case "/v1.55/exec/metaexec/start":
			w.Write(frame(1, `{"database":"fixture","database_oid":"123","cluster_id":"456","owner":"postgres","acl":[{"grantor":"postgres","grantee":"","privilege":"CONNECT","grantable":false},{"grantor":"postgres","grantee":"PUBLIC","privilege":"CONNECT","grantable":false}],"server_version":180006,"format":"custom","superuser":true}`))
		case "/v1.55/exec/versionexec/start":
			w.Write(frame(1, "pg_dump (PostgreSQL) 18.6\n"))
		case "/v1.55/exec/versionexec/json":
			w.Write([]byte(`{"ID":"versionexec","ContainerID":"source","Running":false,"ExitCode":0}`))
		case "/v1.55/exec/metaexec/json":
			w.Write([]byte(`{"ID":"metaexec","ContainerID":"source","Running":false,"ExitCode":0}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	})
	p, e := c.PreparePostgres(context.Background(), Source{ContainerID: "source", DaemonID: "daemon", StartedAt: "start"})
	if e != nil || p.Database != "fixture" || p.Metadata.ClusterID != "456" || p.Metadata.ClientVersion != 180006 || p.Metadata.ServerVersion != 180006 || p.Metadata.Format != "custom" || len(p.Metadata.ACL) != 2 || p.Metadata.ACL[0].Grantee != "" || p.Metadata.ACL[1].Grantee != "PUBLIC" {
		t.Fatal(p, e)
	}
}
func TestDumpPersistBeforeStartAndHelperStatus(t *testing.T) {
	started := false
	persisted := false
	source := Source{ContainerID: "source", DaemonID: "daemon", StartedAt: "start"}
	run := "bakabel_0123456789abcdef0123456789abcdef"
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
		case "/v1.55/containers/source/exec":
			var cfg ExecConfig
			json.NewDecoder(r.Body).Decode(&cfg)
			if cfg.Cmd[0] != "/usr/local/bin/pg_dump" || cfg.User != "0" || !strings.Contains(strings.Join(cfg.Env, ";"), "PGAPPNAME="+run) || !strings.Contains(strings.Join(cfg.Cmd, ";"), "dbname='host=evil'") {
				t.Error(cfg)
			}
			w.Write([]byte(`{"Id":"dumpexec"}`))
		case "/v1.55/exec/dumpexec/start":
			if !persisted {
				t.Error("started before persistence")
			}
			started = true
			w.Write(append(frame(1, "PGDMP"), frame(2, "password=SECRET")...))
		case "/v1.55/exec/dumpexec/json":
			w.Write([]byte(`{"ID":"dumpexec","ContainerID":"source","Running":false,"ExitCode":9,"ProcessConfig":{"entrypoint":"/usr/local/bin/pg_dump"}}`))
		default:
			w.WriteHeader(404)
		}
	})
	p := Postgres{Source: source, Database: "host=evil", User: "postgres", prepared: true}
	d, e := c.CreateDump(context.Background(), p, run, func(d Dump) error {
		if started || d.ExecID != "dumpexec" || d.Source != source {
			t.Fatal(d)
		}
		persisted = true
		return nil
	})
	if e != nil || started {
		t.Fatal(e, started)
	}
	var out bytes.Buffer
	code, e := c.StreamDump(context.Background(), d, &out)
	if code != 9 || !errors.Is(e, ErrDumpFailed) || out.String() != "PGDMP" || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(code, e, out.String())
	}
	persisted = false
	started = false
	_, e = c.CreateDump(context.Background(), p, run, func(Dump) error { return errors.New("password=SECRET") })
	if !errors.Is(e, ErrQuarantine) || strings.Contains(e.Error(), "SECRET") || started {
		t.Fatal(e, started)
	}
	if _, e = c.CreateDump(context.Background(), p, run, nil); e == nil {
		t.Fatal("nil persistence accepted")
	}
}
