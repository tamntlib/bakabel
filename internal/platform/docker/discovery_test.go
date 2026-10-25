package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func discoveryContainer(id, project, service, kind string) Container {
	var c Container
	c.ID = id
	c.State.Running = true
	c.State.StartedAt = "incarnation"
	c.Config.Env = []string{"POSTGRES_DB=app", "POSTGRES_USER=fixture", "POSTGRES_PASSWORD=SECRET"}
	c.Config.Labels = map[string]string{"com.docker.compose.project": project, "com.docker.compose.service": service}
	if kind != "" {
		c.Config.Labels["bakabel.type"] = kind
	}
	return c
}
func discoveryFixture(t *testing.T, containers *[]Container, extra func(http.ResponseWriter, *http.Request) bool) *Client {
	t.Helper()
	return server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("non-read request %s", r.Method)
		}
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon", "Swarm": map[string]any{"NodeID": "node", "ControlAvailable": true}})
		case "/v1.55/containers/json":
			if r.URL.Query().Get("all") != "1" {
				t.Error("discovery did not include stopped containers")
			}
			list := []map[string]any{}
			for _, c := range *containers {
				list = append(list, map[string]any{"Id": c.ID, "Labels": c.Config.Labels})
			}
			json.NewEncoder(w).Encode(list)
		default:
			for _, c := range *containers {
				if r.URL.Path == "/v1.55/containers/"+c.ID+"/json" {
					json.NewEncoder(w).Encode(struct {
						Container
						HostConfig struct{ Mounts []any }
					}{Container: c})
					return
				}
			}
			if extra != nil && extra(w, r) {
				return
			}
			t.Errorf("unexpected route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
}
func discoveryOptions() DiscoveryOptions {
	return DiscoveryOptions{Installation: "fixture", Platform: "compose", Scope: []string{"app"}}
}

func TestDiscoveryComposePostgres(t *testing.T) {
	containers := []Container{discoveryContainer("b", "app", "zdb", "postgres"), discoveryContainer("a", "app", "adb", "postgres"), discoveryContainer("other", "excluded", "db", "SECRET"), discoveryContainer("plain", "app", "web", "")}
	c := discoveryFixture(t, &containers, nil)
	targets, e := c.Discover(context.Background(), discoveryOptions())
	if e != nil {
		t.Fatal(e)
	}
	if len(targets) != 2 || targets[0].Service != "adb" || targets[1].Service != "zdb" {
		t.Fatalf("targets %#v", targets)
	}
	a := targets[0]
	if a.ID != "fixture/compose/app/adb/postgres/app" || a.Kind != "postgres" || a.Project != "app" || a.Source.ContainerID != "a" || a.Source.DaemonID != "daemon" || a.Source.StartedAt != "incarnation" || a.Database != "app" || a.DatabaseOverride != "" || len(a.Mounts) != 0 {
		t.Fatalf("target %#v", a)
	}
	containers[1].ID = "replacement"
	changed, e := c.Discover(context.Background(), discoveryOptions())
	if e != nil {
		t.Fatal(e)
	}
	if changed[0].ID != a.ID || reflect.DeepEqual(changed[0].Source, a.Source) {
		t.Fatal("unstable ID or unchanged runtime reference")
	}
}
