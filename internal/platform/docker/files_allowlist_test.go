package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
)

func TestFileRestoreOwnedWorkerOnly(t *testing.T) {
	source := t.TempDir()
	dest := t.TempDir()
	m, e := files.Capture("install", "source", files.Volume{DaemonID: "daemon", NodeID: "daemon", Name: "source", Mountpoint: source, Destination: "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	tags, _ := backup.EncodeTags(m, "complete", "snapshotrun")
	snap := backup.Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: m.Paths}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/volumes/target":
			json.NewEncoder(w).Encode(map[string]any{"Name": "target", "Driver": "local", "Scope": "local", "Mountpoint": dest, "Options": map[string]string{}})
		case "/v1.55/containers/json":
			json.NewEncoder(w).Encode([]map[string]string{{"Id": "worker"}})
		case "/v1.55/containers/worker/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "worker", "Name": "/worker", "Config": map[string]any{"Labels": map[string]string{"bakabel.worker": "1", "bakabel.run": "thisrun", "bakabel.daemon": "daemon"}}, "HostConfig": map[string]any{"AutoRemove": false, "RestartPolicy": map[string]string{"Name": "no"}}, "State": map[string]any{"Running": true, "StartedAt": "start", "Status": "running", "Restarting": false, "Dead": false, "ExitCode": 0}, "Mounts": []Mount{{Type: "volume", Name: "target", Source: dest, Destination: "/restore"}}})
		default:
			w.WriteHeader(404)
		}
	})
	if _, e = c.PreflightFileRestoreVolume(context.Background(), snap, "target", nil); e == nil {
		t.Fatal("unallowed worker consumer accepted")
	}
	owned := Worker{DaemonID: "daemon", ContainerID: "worker", Name: "worker", RunID: "thisrun"}
	if _, e = c.PreflightFileRestoreVolume(context.Background(), snap, "target", &owned); e != nil {
		t.Fatal("own worker refused", e)
	}
	owned.RunID = "different-run"
	if _, e = c.PreflightFileRestoreVolume(context.Background(), snap, "target", &owned); e == nil {
		t.Fatal("different run allowlisted")
	}
}
