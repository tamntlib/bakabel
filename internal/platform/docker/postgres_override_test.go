package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPreparePostgresUsesPinnedServiceDatabaseOverride(t *testing.T) {
	const database = "service db host=not-a-host"
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"},"Config":{"Env":["POSTGRES_DB=fallback","POSTGRES_USER=postgres"],"Labels":{"bakabel.postgres.database":"container-label"}}}`))
		case "/v1.55/containers/source/exec":
			var cfg ExecConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				t.Error(err)
			}
			if cfg.Cmd[0] == "psql" {
				if !strings.Contains(strings.Join(cfg.Cmd, "\n"), "dbname='"+database+"'") {
					t.Error("service override was not encoded literally", cfg.Cmd)
				}
				w.Write([]byte(`{"Id":"meta"}`))
			} else {
				w.Write([]byte(`{"Id":"version"}`))
			}
		case "/v1.55/exec/meta/start":
			raw, _ := json.Marshal(map[string]any{"database": database, "database_oid": "123", "cluster_id": "456", "owner": "postgres", "acl": []any{}, "server_version": 180006, "format": "custom", "superuser": true})
			w.Write(frame(1, string(raw)))
		case "/v1.55/exec/version/start":
			w.Write(frame(1, "pg_dump (PostgreSQL) 18.6\n"))
		case "/v1.55/exec/meta/json":
			w.Write([]byte(`{"ID":"meta","ContainerID":"source","Running":false,"ExitCode":0}`))
		case "/v1.55/exec/version/json":
			w.Write([]byte(`{"ID":"version","ContainerID":"source","Running":false,"ExitCode":0}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	})
	p, err := c.PreparePostgresDatabase(context.Background(), Source{DaemonID: "daemon", ContainerID: "source", StartedAt: "start"}, database)
	if err != nil || p.Database != database {
		t.Fatalf("pinned database: %+v %v", p, err)
	}
}
