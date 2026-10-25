package docker

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit discovery-only opt-in avoids re-running any B1 integration suite.
func TestDiscoveryRealCompose(t *testing.T) {
	socket := os.Getenv("BAKABEL_DISCOVERY_SOCKET")
	if socket == "" {
		t.Skip("disposable discovery fixture opt-in required")
	}
	c, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	project := fmt.Sprintf("bakabel-discovery-%d", time.Now().UnixNano())
	o := DiscoveryOptions{Installation: "fixture", Platform: "compose", Scope: []string{project}, Repository: "/repository", PasswordFile: "/credentials/restic"}
	createVolume := func(t *testing.T, suffix string, options map[string]string) string {
		t.Helper()
		name := project + "-" + suffix
		var v struct{ Name string }
		if e := c.request(ctx, "POST", "/volumes/create", map[string]any{"Name": name, "Driver": "local", "DriverOpts": options, "Labels": map[string]string{"test.discovery.owner": project}}, &v); e != nil || v.Name != name {
			t.Fatal("create fixture volume", e)
		}
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if e := c.request(clean, "DELETE", "/volumes/"+name, nil, nil); e != nil {
				t.Error("remove fixture volume", e)
			}
			var body any
			if e := c.request(clean, "GET", "/volumes/"+name, nil, &body); e != apiError(404) {
				t.Error("volume absence unverified", e)
			}
		})
		return name
	}
	createContainer := func(t *testing.T, service, kind, paths string, mounts []map[string]any, start bool) string {
		t.Helper()
		labels := map[string]string{"com.docker.compose.project": project, "com.docker.compose.service": service, "test.discovery.owner": project}
		if kind != "" {
			labels["bakabel.type"] = kind
		}
		if paths != "" {
			labels["bakabel.paths"] = paths
		}
		var v struct {
			ID string `json:"Id"`
		}
		config := map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"/bin/sh", "-c", "exec sleep 300"}, "Env": []string{"POSTGRES_DB=fixture", "POSTGRES_USER=fixture"}, "Labels": labels, "HostConfig": map[string]any{"Mounts": mounts, "NetworkMode": "none", "NanoCpus": 2000000000, "CpusetCpus": "0,1", "AutoRemove": false}}
		if e := c.request(ctx, "POST", "/containers/create?name="+url.QueryEscape(project+"-"+service+fmt.Sprint(time.Now().UnixNano())), config, &v); e != nil || v.ID == "" {
			t.Fatal("create fixture container", e)
		}
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if e := c.request(clean, "DELETE", "/containers/"+v.ID+"?force=true&v=true", nil, nil); e != nil {
				t.Error("remove fixture container", e)
			}
			if _, e := c.InspectContainer(clean, v.ID); e != apiError(404) {
				t.Error("container absence unverified", e)
			}
		})
		if start {
			if e := c.request(ctx, "POST", "/containers/"+v.ID+"/start", nil, nil); e != nil {
				t.Fatal("start fixture", e)
			}
			source, e := c.CaptureSource(ctx, v.ID)
			if e != nil || source.ContainerID != v.ID {
				t.Fatal("running fixture unverified", e)
			}
		} else {
			v, e := c.InspectContainer(ctx, v.ID)
			if e != nil || v.State.Running {
				t.Fatal("stopped fixture unverified", e)
			}
		}
		return v.ID
	}
	t.Run("zero containers", func(t *testing.T) {
		targets, e := c.Discover(ctx, o)
		if e != nil || len(targets) != 0 {
			t.Fatal("empty discovery", e)
		}
	})
	t.Run("running postgres", func(t *testing.T) {
		id := createContainer(t, "db", "postgres", "", nil, true)
		targets, e := c.Discover(ctx, o)
		if e != nil || len(targets) != 1 || targets[0].Source.ContainerID != id || targets[0].Database != "fixture" {
			t.Fatal("real postgres discovery", e)
		}
	})
	t.Run("stopped marked", func(t *testing.T) {
		createContainer(t, "stopped", "postgres", "", nil, false)
		if got, e := c.Discover(ctx, o); e == nil || got != nil {
			t.Fatal("stopped marked source disappeared")
		}
	})
	t.Run("replica includes stopped", func(t *testing.T) {
		createContainer(t, "replicated", "postgres", "", nil, true)
		createContainer(t, "replicated", "", "", nil, false)
		if got, e := c.Discover(ctx, o); e == nil || got != nil {
			t.Fatal("replica source accepted")
		}
	})
	t.Run("exact local volume roots", func(t *testing.T) {
		a, b := createVolume(t, "data", nil), createVolume(t, "other", nil)
		mounts := []map[string]any{{"Type": "volume", "Source": a, "Target": "/data", "VolumeOptions": map[string]bool{"NoCopy": true}}, {"Type": "volume", "Source": b, "Target": "/other", "VolumeOptions": map[string]bool{"NoCopy": true}}}
		createContainer(t, "files", "volume", "/other,/data", mounts, true)
		got, e := c.Discover(ctx, o)
		if e != nil || len(got) != 2 || len(got[0].Mounts) != 1 || !strings.HasSuffix(got[0].ID, "/volume/%2Fdata") {
			t.Fatal("real volume discovery", e)
		}
		protected := o
		protected.ProtectedNodePaths = []string{got[0].Mounts[0].Source + "/password"}
		if targets, e := c.Discover(ctx, protected); e == nil || targets != nil {
			t.Fatal("real source/protected overlap accepted")
		}
	})
	t.Run("volume subpath must not broaden", func(t *testing.T) {
		name := createVolume(t, "subpath", nil)
		seed := createContainer(t, "seed", "", "", []map[string]any{{"Type": "volume", "Source": name, "Target": "/data"}}, true)
		execID, e := c.CreateExec(ctx, seed, ExecConfig{Cmd: []string{"mkdir", "-p", "/data/subset"}})
		if e != nil {
			t.Fatal(e)
		}
		if e = c.StartExec(ctx, execID, io.Discard, io.Discard); e != nil {
			t.Fatal(e)
		}
		if code, e := c.WaitExec(ctx, execID); e != nil || code != 0 {
			t.Fatal("fixture subpath mkdir", e)
		}
		source := createContainer(t, "subset", "volume", "/data", []map[string]any{{"Type": "volume", "Source": name, "Target": "/data", "VolumeOptions": map[string]any{"Subpath": "subset", "NoCopy": true}}}, true)
		var inspect struct {
			HostConfig struct {
				Mounts []struct{ VolumeOptions struct{ Subpath string } }
			}
		}
		if e := c.request(ctx, "GET", "/containers/"+source+"/json", nil, &inspect); e != nil || len(inspect.HostConfig.Mounts) != 1 || inspect.HostConfig.Mounts[0].VolumeOptions.Subpath != "subset" {
			t.Fatal("actual Engine subpath metadata unverified", e)
		}
		if got, e := c.Discover(ctx, o); e == nil || got != nil {
			t.Fatal("real volume subpath broadened")
		}
	})
	t.Run("local bind alias driver options", func(t *testing.T) {
		// Existing fixture metadata is enough; never mount or write the alias.
		alias := createVolume(t, "alias", map[string]string{"type": "none", "o": "bind", "device": "/var/empty-discovery-fixture"})
		if _, e := c.InspectLocalVolume(ctx, alias); e == nil {
			t.Fatal("bind alias local volume accepted")
		}
	})
}
