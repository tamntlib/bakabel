package docker

import (
	"context"
	"encoding/json"
	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestFileVolumeRefusesOpaqueBackingAndPGDATA(t *testing.T) {
	for _, tc := range []struct {
		name, driver string
		options      map[string]string
		env          []string
		mount        Mount
		extra        []Mount
	}{
		{name: "driver", driver: "nfs"},
		{name: "local-bind-alias", driver: "local", options: map[string]string{"type": "none", "o": "bind", "device": "/same/backing"}},
		{name: "pgdata", driver: "local", env: []string{"PGDATA=/data/pgdata"}},
		{name: "default-pgdata", driver: "local", mount: Mount{Type: "volume", Name: "uploads", Source: "/var/lib/docker/volumes/uploads/_data", Destination: "/var/lib/postgresql/data"}},
		{name: "nested-secret", driver: "local", extra: []Mount{{Type: "bind", Source: "/secret", Destination: "/data/secret"}}},
		{name: "bind", driver: "local", mount: Mount{Type: "bind", Source: "/host", Destination: "/data"}},
		{name: "source-drift", driver: "local", mount: Mount{Type: "volume", Name: "uploads", Source: "/other", Destination: "/data"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mount := tc.mount
			if mount.Destination == "" {
				mount = Mount{Type: "volume", Name: "uploads", Source: "/var/lib/docker/volumes/uploads/_data", Destination: "/data"}
			}
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
				case "/v1.55/containers/source/json":
					json.NewEncoder(w).Encode(map[string]any{"Id": "source", "State": map[string]any{"Running": true, "StartedAt": "start"}, "Config": map[string]any{"Env": tc.env}, "Mounts": append([]Mount{mount}, tc.extra...)})
				case "/v1.55/volumes/uploads":
					json.NewEncoder(w).Encode(map[string]any{"Name": "uploads", "Driver": tc.driver, "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/uploads/_data", "Options": tc.options})
				default:
					w.WriteHeader(404)
				}
			})
			if _, e := c.PrepareFileVolume(context.Background(), Source{"daemon", "source", "start"}, mount.Destination); e == nil {
				t.Fatal("unsafe volume accepted")
			}
		})
	}
}
func TestFileRestoreVolumePreflightIncludesStoppedConsumers(t *testing.T) {
	root := t.TempDir()
	source := t.TempDir()
	m, e := files.Capture("install", "source", files.Volume{DaemonID: "daemon", NodeID: "daemon", Name: "sourcevol", Mountpoint: source, Destination: "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	tags, _ := backup.EncodeTags(m, "complete", "run")
	snap := backup.Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: m.Paths}
	consumer := false
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/volumes/target":
			json.NewEncoder(w).Encode(map[string]any{"Name": "target", "Driver": "local", "Scope": "local", "Mountpoint": root, "Options": map[string]string{}})
		case "/v1.55/containers/json":
			if r.URL.Query().Get("all") != "true" {
				t.Error("did not list stopped containers")
			}
			if consumer {
				json.NewEncoder(w).Encode([]map[string]any{{"Id": "stopped"}})
			} else {
				json.NewEncoder(w).Encode([]any{})
			}
		case "/v1.55/containers/stopped/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "stopped", "State": map[string]any{"Running": false, "StartedAt": "old"}, "Mounts": []Mount{{Type: "volume", Name: "target", Source: root, Destination: "/data"}}})
		default:
			w.WriteHeader(404)
		}
	})
	if v, e := c.PreflightFileRestoreVolume(context.Background(), snap, "target", nil); e != nil || v.Name != "target" {
		t.Fatal(v, e)
	}
	consumer = true
	if _, e := c.PreflightFileRestoreVolume(context.Background(), snap, "target", nil); e == nil {
		t.Fatal("stopped consumer accepted")
	}
	consumer = false
	os.WriteFile(root+"/late", []byte("x"), 0600)
	if _, e := c.PreflightFileRestoreVolume(context.Background(), snap, "target", nil); e == nil {
		t.Fatal("nonempty local volume accepted")
	}
}
func TestDirectoryAppMountRefused(t *testing.T) {
	source := t.TempDir()
	dest := t.TempDir()
	m, e := files.Capture("install", "source", files.Volume{DaemonID: "daemon", NodeID: "daemon", Name: "sourcevol", Mountpoint: source, Destination: "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	tags, _ := backup.EncodeTags(m, "complete", "run")
	s := backup.Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: m.Paths}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/containers/json":
			json.NewEncoder(w).Encode([]map[string]string{{"Id": "app"}})
		case "/v1.55/containers/app/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "app", "State": map[string]any{"Running": false, "StartedAt": "old"}, "Mounts": []Mount{{Type: "bind", Source: dest, Destination: "/appdata"}}})
		default:
			w.WriteHeader(404)
		}
	})
	if target, e := c.PreflightFileRestoreDirectory(context.Background(), s, dest, nil); e == nil {
		target.Close()
		t.Fatal("empty app mount accepted")
	}
}
func TestFileSourceRestartDuringInspectRejected(t *testing.T) {
	calls := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/containers/source/json":
			calls++
			start := "start"
			if calls > 1 {
				start = "replacement"
			}
			json.NewEncoder(w).Encode(map[string]any{"Id": "source", "State": map[string]any{"Running": true, "StartedAt": start}, "Mounts": []Mount{{Type: "volume", Name: "uploads", Source: "/var/lib/docker/volumes/uploads/_data", Destination: "/data"}}})
		case "/v1.55/volumes/uploads":
			json.NewEncoder(w).Encode(map[string]any{"Name": "uploads", "Driver": "local", "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/uploads/_data", "Options": map[string]string{}})
		default:
			w.WriteHeader(404)
		}
	})
	if _, e := c.PrepareFileVolume(context.Background(), Source{"daemon", "source", "start"}, "/data"); e == nil {
		t.Fatal("changed source incarnation accepted")
	}
}
func TestPrepareExactLocalFileVolume(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/containers/source/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "source", "State": map[string]any{"Running": true, "StartedAt": "start"}, "Mounts": []Mount{{Type: "volume", Name: "uploads", Source: "/var/lib/docker/volumes/uploads/_data", Destination: "/data", RW: true}}})
		case "/v1.55/volumes/uploads":
			json.NewEncoder(w).Encode(map[string]any{"Name": "uploads", "Driver": "local", "Scope": "local", "Mountpoint": "/var/lib/docker/volumes/uploads/_data", "Options": map[string]string{}})
		default:
			t.Errorf("unexpected %s", r.URL)
			w.WriteHeader(404)
		}
	})
	p, e := c.PrepareFileVolume(context.Background(), Source{"daemon", "source", "start"}, "/data")
	if e != nil {
		t.Fatal(e)
	}
	if p.Name != "uploads" || p.NodeID != "daemon" || p.Mountpoint != "/var/lib/docker/volumes/uploads/_data" || p.Destination != "/data" {
		t.Fatal(p)
	}
}
