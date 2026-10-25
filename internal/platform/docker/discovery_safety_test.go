package docker

import (
	"context"
	"strings"
	"testing"
)

func TestDiscoveryComposeRejectsMarkedUnavailable(t *testing.T) {
	for _, mode := range []string{"stopped", "replicas", "unmarked replica", "missing service", "bad kind", "empty kind", "missing DB", "duplicate DB env", "forbidden label", "orphan label", "paths on DB", "db newline"} {
		t.Run(mode, func(t *testing.T) {
			v := discoveryContainer("source", "app", "db", "postgres")
			containers := []Container{v}
			switch mode {
			case "stopped":
				containers[0].State.Running = false
			case "replicas":
				v.ID = "replica"
				containers = append(containers, v)
			case "unmarked replica":
				v.ID = "replica"
				delete(v.Config.Labels, "bakabel.type")
				containers = append(containers, v)
				containers[0].Config.Labels = map[string]string{"com.docker.compose.project": "app", "com.docker.compose.service": "db", "bakabel.type": "postgres"}
			case "missing service":
				delete(v.Config.Labels, "com.docker.compose.service")
			case "bad kind":
				v.Config.Labels["bakabel.type"] = "SECRET"
			case "empty kind":
				v.Config.Labels["bakabel.type"] = ""
			case "missing DB":
				containers[0].Config.Env = nil
			case "duplicate DB env":
				containers[0].Config.Env = append(v.Config.Env, "POSTGRES_DB=other")
			case "forbidden label":
				v.Config.Labels["bakabel.enable"] = "SECRET"
			case "orphan label":
				delete(v.Config.Labels, "bakabel.type")
				v.Config.Labels["bakabel.paths"] = "/data"
			case "paths on DB":
				v.Config.Labels["bakabel.paths"] = "/data"
			case "db newline":
				v.Config.Labels["bakabel.postgres.database"] = "SECRET\n"
			}
			c := discoveryFixture(t, &containers, nil)
			got, e := c.Discover(context.Background(), discoveryOptions())
			if e == nil || got != nil {
				t.Fatalf("accepted unsupported source: %#v", got)
			}
			if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("unsafe error")
			}
		})
	}
}
func TestDiscoveryOptionsFailClosed(t *testing.T) {
	for _, mode := range []string{"empty installation", "bad installation", "empty platform", "unsupported platform", "empty scope", "duplicate scope", "invalid scope"} {
		t.Run(mode, func(t *testing.T) {
			o := discoveryOptions()
			switch mode {
			case "empty installation":
				o.Installation = ""
			case "bad installation":
				o.Installation = "../SECRET"
			case "empty platform":
				o.Platform = ""
			case "unsupported platform":
				o.Platform = "auto"
			case "empty scope":
				o.Scope = nil
			case "duplicate scope":
				o.Scope = []string{"app", "app"}
			case "invalid scope":
				o.Scope = []string{"../app"}
			}
			containers := []Container{}
			c := discoveryFixture(t, &containers, nil)
			if _, e := c.Discover(context.Background(), o); e == nil {
				t.Fatal("accepted invalid options")
			}
		})
	}
}
func TestDiscoveryDatabaseOverride(t *testing.T) {
	v := discoveryContainer("source", "app", "db", "postgres")
	v.Config.Labels["bakabel.postgres.database"] = "literal db/name"
	v.Config.Env = nil
	containers := []Container{v}
	c := discoveryFixture(t, &containers, nil)
	got, e := c.Discover(context.Background(), discoveryOptions())
	if e != nil {
		t.Fatal(e)
	}
	if got[0].Database != "literal db/name" || got[0].DatabaseOverride != "literal db/name" || !strings.HasSuffix(got[0].ID, "/literal%20db%2Fname") {
		t.Fatalf("override %#v", got[0])
	}
}
