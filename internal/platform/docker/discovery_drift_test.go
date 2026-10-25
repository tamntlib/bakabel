package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestDiscoveryRejectsDaemonAndIncarnationDrift(t *testing.T) {
	for _, mode := range []string{"daemon", "incarnation", "container labels"} {
		t.Run(mode, func(t *testing.T) {
			infos, inspects := 0, 0
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					infos++
					id := "daemon"
					if mode == "daemon" && infos > 1 {
						id = "replacement"
					}
					json.NewEncoder(w).Encode(map[string]string{"ID": id})
				case "/v1.55/containers/json":
					json.NewEncoder(w).Encode([]map[string]any{{"Id": "source", "Labels": map[string]string{"com.docker.compose.project": "app", "com.docker.compose.service": "db"}}})
				case "/v1.55/containers/source/json":
					inspects++
					v := discoveryContainer("source", "app", "db", "postgres")
					if mode == "incarnation" && inspects > 1 {
						v.State.StartedAt = "new"
					}
					if mode == "container labels" {
						v.Config.Labels["com.docker.compose.project"] = "replacement"
					}
					json.NewEncoder(w).Encode(v)
				default:
					t.Errorf("unexpected %s", r.URL.Path)
					w.WriteHeader(404)
				}
			})
			got, e := c.Discover(context.Background(), discoveryOptions())
			if e == nil || got != nil {
				t.Fatal("drift accepted")
			}
		})
	}
}
func TestDiscoveryProtectedNodePaths(t *testing.T) {
	for _, protected := range []string{"/var/lib/docker/volumes/data/_data", "/var/lib/docker/volumes/data/_data/password", "/var/lib/docker/volumes", "relative", "/", "/var/../SECRET"} {
		t.Run(protected, func(t *testing.T) {
			v := volumeContainer()
			v.Config.Labels["bakabel.paths"] = "/data"
			containers := []Container{v}
			c := discoveryFixture(t, &containers, volumeAPI)
			o := discoveryOptions()
			o.ProtectedNodePaths = []string{protected}
			got, e := c.Discover(context.Background(), o)
			if e == nil || got != nil {
				t.Fatal("protected mount accepted")
			}
			if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("unsafe error")
			}
		})
	}
}
func TestDiscoveryNoTargets(t *testing.T) {
	containers := []Container{}
	c := discoveryFixture(t, &containers, nil)
	got, e := c.Discover(context.Background(), discoveryOptions())
	if e != nil || got == nil || len(got) != 0 {
		t.Fatal("no-target outcome", got, e)
	}
}
