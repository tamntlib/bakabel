package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestRestoreCreateIntentBoundaryFollowsReadonlyChecks(t *testing.T) {
	for _, mode := range []string{"running", "source-terminal", "intent-write-failed", "create-response-lost"} {
		t.Run(mode, func(t *testing.T) {
			before, created, persisted := 0, 0, 0
			client := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					fmt.Fprint(w, `{"ID":"daemon"}`)
				case "/v1.55/containers/target/json":
					fmt.Fprintf(w, `{"Id":"target","State":{"Running":%t,"StartedAt":"start"}}`, mode != "source-terminal")
				case "/v1.55/containers/target/exec":
					if before != 1 {
						t.Error("create preceded durable intent")
					}
					created++
					if mode == "create-response-lost" {
						w.WriteHeader(500)
						return
					}
					fmt.Fprint(w, `{"Id":"importexec"}`)
				default:
					t.Errorf("unexpected create-boundary API %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			})
			defer client.Close()
			target := RestorePostgresTarget{postgres: Postgres{Source: Source{"daemon", "target", "start"}, Database: "fixture", User: "postgres"}, prepared: true}
			_, err := client.CreateRestoreExec(context.Background(), target, "restore_token_0123456789", func(RestoreExec) error { persisted++; return nil }, func() error {
				before++
				if mode == "intent-write-failed" {
					return errors.New("fixture intent write failed")
				}
				return nil
			})
			switch mode {
			case "running":
				if err != nil || before != 1 || created != 1 || persisted != 1 {
					t.Fatal(before, created, persisted, err)
				}
			case "source-terminal":
				if err == nil || before != 0 || created != 0 || persisted != 0 {
					t.Fatal(before, created, persisted, err)
				}
			case "intent-write-failed":
				if err == nil || before != 1 || created != 0 || persisted != 0 {
					t.Fatal(before, created, persisted, err)
				}
			case "create-response-lost":
				if err == nil || before != 1 || created != 1 || persisted != 0 {
					t.Fatal(before, created, persisted, err)
				}
			}
		})
	}
}
