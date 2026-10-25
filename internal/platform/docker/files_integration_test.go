package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
)

type fileFixtureJob struct {
	Action, SourceID, Installation, Run, Destination string
	Volume                                           files.Volume
	Snapshot                                         backup.Snapshot
}

func TestFileWorkerFixture(t *testing.T) {
	jobpath := os.Getenv("BAKABEL_FILE_FIXTURE_JOB")
	if jobpath == "" {
		return
	}
	raw, e := os.ReadFile(jobpath)
	if e != nil {
		t.Fatal(e)
	}
	var j fileFixtureJob
	if e = json.Unmarshal(raw, &j); e != nil {
		t.Fatal(e)
	}
	r := backup.Repository{Binary: "/fixture/restic-wrapper", Env: append(os.Environ(), "RESTIC_REPOSITORY=/fixture/repo", "RESTIC_PASSWORD=disposable-file-fixture")}
	if j.Action == "partial" {
		r.Binary = "/restic"
		r.Env = append(os.Environ(), "RESTIC_REPOSITORY=/fixture/partial-repo", "RESTIC_PASSWORD=disposable-file-fixture")
		cmd := exec.Command("/restic", "--no-cache", "init")
		cmd.Env = r.Env
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(string(out), e)
		}
		p := files.WorkerPath(j.SourceID, j.Volume.Destination)
		m, e := files.Capture(j.Installation, j.SourceID, j.Volume, p)
		if e != nil {
			t.Fatal(e)
		}
		result := files.Backup(context.Background(), r, m, j.Run, j.Installation, []string{"/fixture/partial-repo"})
		if result.Err == nil || result.Status != "partial" || result.SnapshotID == "" {
			t.Fatal("real unreadable file did not produce partial receipt", result)
		}
		all, e := r.Snapshots(context.Background())
		if e != nil || len(all) != 1 {
			t.Fatal(all, e)
		}
		if _, e = all[0].Restorable(); e == nil {
			t.Fatal("partial restored")
		}
		raw, _ := json.Marshal(all[0])
		if e = os.WriteFile("/fixture/partial.receipt", raw, 0600); e != nil {
			t.Fatal(e)
		}
	} else if j.Action == "backup" {
		p := files.WorkerPath(j.SourceID, j.Volume.Destination)
		m, e := files.Capture(j.Installation, j.SourceID, j.Volume, p)
		if e != nil {
			t.Fatal(e)
		}
		result := files.Backup(context.Background(), r, m, j.Run, j.Installation, []string{"/fixture/repo"})
		if result.Err != nil || result.Status != "complete" {
			t.Fatal(result)
		}
		all, e := r.Snapshots(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command("/restic", "--no-cache", "cat", "snapshot", result.SnapshotID)
		cmd.Env = r.Env
		raw, e := cmd.Output()
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile("/fixture/"+j.Run+".snapshot", raw, 0600); e != nil {
			t.Fatal(e)
		}
		for _, s := range all {
			if s.ID == result.SnapshotID {
				b, _ := json.Marshal(s)
				if e = os.WriteFile("/fixture/"+j.Run+".receipt", b, 0600); e != nil {
					t.Fatal(e)
				}
				return
			}
		}
		t.Fatal("exact receipt missing")
	} else if j.Action == "reject-backup" {
		p := files.WorkerPath(j.SourceID, j.Volume.Destination)
		m, e := files.Capture(j.Installation, j.SourceID, j.Volume, p)
		if e != nil {
			t.Fatal(e)
		}
		result := files.Backup(context.Background(), r, m, j.Run, j.Installation, []string{"/fixture/repo"})
		if result.Err == nil || !strings.Contains(result.Err.Error(), "protected storage") {
			os.WriteFile("/fixture/last-failure", []byte(fmt.Sprint("nested backup exclusion not gated: ", result.Err)), 0600)
			t.Fatal(result)
		}
	} else if strings.HasPrefix(j.Action, "reject") {
		if j.Action == "reject-symlink" {
			if e = os.Symlink(j.Destination, "/fixture/source-alias"); e != nil {
				t.Fatal(e)
			}
			j.Destination = "/fixture/source-alias"
		}
		target, e := files.OpenRestore(j.Snapshot, j.Destination, []string{"/fixture/repo"})
		if e == nil {
			target.Close()
			os.WriteFile("/fixture/last-failure", []byte("unsafe restore accepted: "+j.Action), 0600)
			t.Fatal("unsafe restore accepted", j.Action)
		}
	} else {
		target, e := files.OpenRestore(j.Snapshot, j.Destination, []string{"/fixture/repo"})
		if e != nil {
			t.Fatal(e)
		}
		defer target.Close()
		if e = target.Restore(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
}

func TestRealLocalVolumeChangedWorkersRoundtrip(t *testing.T) {
	hostWork := os.Getenv("BAKABEL_FILES_HOST_WORK")
	hostRestic := os.Getenv("BAKABEL_FILES_HOST_RESTIC")
	if hostWork == "" || hostRestic == "" {
		t.Skip("explicit disposable Docker+Restic fixture opt-in required")
	}
	c, e := NewClient("/var/run/docker.sock")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	root, e := os.MkdirTemp(".", "files-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	root, _ = filepath.Abs(root)
	defer os.RemoveAll(root)
	hostRoot := filepath.Join(hostWork, "internal/platform/docker", filepath.Base(root))
	self, _ := os.Executable()
	exe, e := os.ReadFile(self)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "fixture.test"), exe, 0700); e != nil {
		t.Fatal(e)
	}
	wrapper := "#!/bin/sh\nif [ \"$2\" = backup ]; then\n /restic --verbose=2 \"$@\" > /fixture/backup-stats.json 2>>/fixture/errors\n code=$?\n cat /fixture/backup-stats.json\n exit $code\nfi\nexec /restic \"$@\" 2>>/fixture/errors\n"
	os.WriteFile(filepath.Join(root, "restic-wrapper"), []byte(wrapper), 0700)
	prefix := fmt.Sprintf("bakabel-b2-files-%d", time.Now().UnixNano())
	volname := prefix + "-source"
	var vol LocalVolume
	if e = c.request(ctx, "POST", "/volumes/create", map[string]any{"Name": volname, "Driver": "local"}, &vol); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if e := c.request(cleanup, "DELETE", "/volumes/"+volname, nil, nil); e != nil && e != apiError(404) {
			t.Error(e)
		}
		if _, e := c.InspectLocalVolume(cleanup, volname); e != apiError(404) {
			t.Error("volume cleanup readback", e)
		}
	})
	create := func(suffix string, mounts []map[string]any, cmd []string, env []string) string {
		t.Helper()
		var out struct {
			ID string `json:"Id"`
		}
		config := map[string]any{"Image": "golang:1.26.8-bookworm", "Entrypoint": []string{"taskset", "-c", "0,1"}, "Cmd": cmd, "Env": env, "HostConfig": map[string]any{"Mounts": mounts, "NetworkMode": "none", "NanoCpus": 2000000000, "CpusetCpus": "0,1", "RestartPolicy": map[string]string{"Name": "no"}}}
		if suffix == "-partial" {
			config["User"] = "1234:2345"
		}
		if e := c.request(ctx, "POST", "/containers/create?name="+prefix+suffix, config, &out); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
			defer done()
			if e := c.request(cleanup, "DELETE", "/containers/"+out.ID+"?force=true&v=true", nil, nil); e != nil && e != apiError(404) {
				t.Error(e)
			}
			if _, e := c.InspectContainer(cleanup, out.ID); e != apiError(404) {
				t.Error("container cleanup readback", e)
			}
		})
		if e := c.request(ctx, "POST", "/containers/"+out.ID+"/start", nil, nil); e != nil {
			t.Fatal(e)
		}
		return out.ID
	}
	mount := func(kind, source, target string, ro bool) map[string]any {
		return map[string]any{"Type": kind, "Source": source, "Target": target, "ReadOnly": ro, "VolumeOptions": map[string]any{"NoCopy": true}}
	}
	// VolumeOptions is invalid for bind mounts: keep the fixture as strict as API.
	bind := func(source, target string, ro bool) map[string]any {
		return map[string]any{"Type": "bind", "Source": source, "Target": target, "ReadOnly": ro}
	}
	sourceID := create("-application", []map[string]any{mount("volume", volname, "/data", false)}, []string{"sh", "-c", "dd if=/dev/zero of=/data/payload bs=1048576 count=4 2>/dev/null; printf 'real-local-volume\\n' >> /data/payload; chmod 0640 /data/payload; chown 1234:2345 /data/payload; touch /tmp/bakabel-ready; exec sleep infinity"}, nil)
	source, e := c.CaptureSource(ctx, sourceID)
	if e != nil {
		t.Fatal(e)
	}
	for {
		if _, e = c.control(ctx, source, []string{"test", "-f", "/tmp/bakabel-ready"}); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("source fixture readiness", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	v, e := c.PrepareFileVolume(ctx, source, "/data")
	if e != nil {
		t.Fatal(e)
	}
	stableID := prefix + "/compose/uploads/data"
	p := files.WorkerPath(stableID, "/data")
	// Explicit init belongs to this disposable fixture, not the production adapter.
	initID := create("-init", []map[string]any{bind(hostRoot, "/fixture", false), bind(hostRestic, "/restic", true)}, []string{"/restic", "--no-cache", "init"}, []string{"RESTIC_REPOSITORY=/fixture/repo", "RESTIC_PASSWORD=disposable-file-fixture"})
	wait := func(id string) {
		t.Helper()
		var out struct {
			StatusCode int
			Error      any
		}
		if e := c.request(ctx, "POST", "/containers/"+id+"/wait?condition=not-running", nil, &out); e != nil || out.StatusCode != 0 {
			diagnostic, _ := os.ReadFile(filepath.Join(root, "errors"))
			failure, _ := os.ReadFile(filepath.Join(root, "last-failure"))
			t.Fatal("fixture child", id, out, e, string(diagnostic), string(failure))
		}
	}
	wait(initID)
	jobs := func(j fileFixtureJob, suffix string, mounts []map[string]any) string {
		raw, _ := json.Marshal(j)
		file := j.Run + ".json"
		if e := os.WriteFile(filepath.Join(root, file), raw, 0644); e != nil {
			t.Fatal(e)
		}
		// The unreadable-file fixture deliberately runs as another UID. Its
		// synthetic job descriptor, unlike source payload, must remain readable.
		if e := os.Chmod(filepath.Join(root, file), 0644); e != nil {
			t.Fatal(e)
		}
		mounts = append(mounts, bind(hostRoot, "/fixture", false), bind(hostRestic, "/restic", true))
		id := create(suffix, mounts, []string{"/fixture/fixture.test", "-test.run=^TestFileWorkerFixture$", "-test.v"}, []string{"BAKABEL_FILE_FIXTURE_JOB=/fixture/" + file, "GOMAXPROCS=2"})
		wait(id)
		return id
	}
	workers := []string{}
	var snapshots []backup.Snapshot
	for i := 1; i <= 2; i++ {
		run := fmt.Sprintf("backup%d", i)
		id := jobs(fileFixtureJob{Action: "backup", SourceID: stableID, Installation: "fixture-install", Run: run, Volume: v}, "-"+run, []map[string]any{mount("volume", volname, p, true)})
		workers = append(workers, id)
		receipt, e := os.ReadFile(filepath.Join(root, run+".receipt"))
		if e != nil {
			t.Fatal(e)
		}
		var s backup.Snapshot
		if e = json.Unmarshal(receipt, &s); e != nil {
			t.Fatal(e)
		}
		snapshots = append(snapshots, s)
		stats, _ := os.ReadFile(filepath.Join(root, "backup-stats.json"))
		t.Logf("worker%d=%s snapshot=%s stats=%s", i, id, s.ID, stats)
		if i == 2 {
			var summary struct {
				Parent string `json:"parent"`
			}
			raw, _ := os.ReadFile(filepath.Join(root, run+".snapshot"))
			if e = json.Unmarshal(raw, &summary); e != nil || summary.Parent != snapshots[0].ID {
				t.Fatal("wrong parent", summary.Parent, e)
			}
			unchanged := false
			for _, line := range strings.Split(strings.TrimSpace(string(stats)), "\n") {
				var event struct {
					Type   string `json:"message_type"`
					Action string `json:"action"`
					Item   string `json:"item"`
					Data   int64  `json:"data_size"`
				}
				if e = json.Unmarshal([]byte(line), &event); e != nil {
					t.Fatal(e)
				}
				if event.Action == "unchanged" && event.Item == p+"/payload" && event.Data == 0 {
					unchanged = true
				}
			}
			if !unchanged || !strings.Contains(string(stats), "\"files_unmodified\":1") || !strings.Contains(string(stats), "\"data_blobs\":0") {
				t.Fatal("second worker did not reuse unchanged file", string(stats))
			}
			t.Logf("exact parent=%s unchanged payload JSON data_size=0 data_blobs=0 (logical total_bytes_processed is NOT bytes reread)", summary.Parent)
		}
	}
	if workers[0] == workers[1] || snapshots[0].Hostname != snapshots[1].Hostname || strings.Join(snapshots[0].Paths, ",") != strings.Join(snapshots[1].Paths, ",") {
		t.Fatal("unstable worker identity")
	}
	if e = os.Chmod(root, 0777); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(root, "fixture.test"), 0755); e != nil {
		t.Fatal(e)
	}
	if _, e = c.control(ctx, source, []string{"chmod", "000", "/data/payload"}); e != nil {
		t.Fatal(e)
	}
	partialID := jobs(fileFixtureJob{Action: "partial", SourceID: stableID, Installation: "fixture-install", Run: "partial", Volume: v}, "-partial", []map[string]any{mount("volume", volname, p, true)})
	workers = append(workers, partialID)
	partialRaw, e := os.ReadFile(filepath.Join(root, "partial.receipt"))
	if e != nil {
		t.Fatal(e)
	}
	var partial backup.Snapshot
	if e = json.Unmarshal(partialRaw, &partial); e != nil {
		t.Fatal(e)
	}
	if _, e = partial.Restorable(); e == nil {
		t.Fatal("partial accepted")
	}
	t.Logf("real unreadable file retained exact partial snapshot=%s and restore refused", partial.ID)
	// Real same-backing local-driver alias is created explicitly by this fixture;
	// the production inspector refuses it before mounting or restoring anything.
	aliasName := prefix + "-alias"
	var alias LocalVolume
	if e = c.request(ctx, "POST", "/volumes/create", map[string]any{"Name": aliasName, "Driver": "local", "DriverOpts": map[string]string{"type": "none", "o": "bind", "device": v.Mountpoint}}, &alias); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := c.request(cleanup, "DELETE", "/volumes/"+aliasName, nil, nil); err != nil && err != apiError(404) {
			t.Error("alias cleanup", err)
		}
		if err := c.request(cleanup, "GET", "/volumes/"+aliasName, nil, &LocalVolume{}); err != apiError(404) {
			t.Error("alias cleanup readback", err)
		}
	})
	if _, e = c.InspectLocalVolume(ctx, aliasName); e == nil {
		t.Fatal("local-driver bind alias accepted")
	}
	if e = c.request(ctx, "DELETE", "/volumes/"+aliasName, nil, nil); e != nil {
		t.Fatal(e)
	}
	if e = c.request(ctx, "GET", "/volumes/"+aliasName, nil, &alias); e != apiError(404) {
		t.Fatal("alias cleanup readback", e)
	}
	// An empty source is still never a restore destination, even under another
	// mount pathname, through a bind alias, or through a symlink to that alias.
	if _, e = c.control(ctx, source, []string{"rm", "/data/payload"}); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"reject-volume", "reject-bind", "reject-symlink"} {
		selected := mount("volume", volname, "/alias", false)
		if action != "reject-volume" {
			selected = bind(v.Mountpoint, "/alias", false)
		}
		id := jobs(fileFixtureJob{Action: action, Run: action, Snapshot: snapshots[1], Destination: "/alias"}, "-"+action, []map[string]any{selected})
		workers = append(workers, id)
	}
	if _, e = c.control(ctx, source, []string{"mkdir", "/data/child"}); e != nil {
		t.Fatal(e)
	}
	id := jobs(fileFixtureJob{Action: "reject-child", Run: "reject-child", Snapshot: snapshots[1], Destination: "/alias/child"}, "-reject-child", []map[string]any{bind(v.Mountpoint, "/alias", false)})
	workers = append(workers, id)
	id = jobs(fileFixtureJob{Action: "reject-bound-child", Run: "reject-bound-child", Snapshot: snapshots[1], Destination: "/alias-child"}, "-reject-bound-child", []map[string]any{bind(v.Mountpoint+"/child", "/alias-child", false)})
	workers = append(workers, id)
	id = jobs(fileFixtureJob{Action: "reject-backup", Run: "reject-backup", SourceID: stableID, Installation: "fixture-install", Volume: v}, "-reject-backup", []map[string]any{mount("volume", volname, p, true), bind(v.Mountpoint+"/child", "/fixture/repo", true)})
	workers = append(workers, id)
	t.Log("real empty-source self/volume/bind/symlink aliases and nested child refused; local-driver option alias refused")
	// Remove source application and the stopped backup workers before deleting the
	// volume. Their snapshots alone must suffice for independent directory restore.
	for _, id := range append(workers, sourceID) {
		if e = c.request(ctx, "DELETE", "/containers/"+id+"?force=true&v=true", nil, nil); e != nil {
			t.Fatal(e)
		}
		if _, err := c.InspectContainer(ctx, id); err != apiError(404) {
			t.Fatal("source/worker absence before independent restore", err)
		}
	}
	// Cleanup callbacks accept absence below; cleanup only exact fixture resources.
	if e = c.request(ctx, "DELETE", "/volumes/"+volname, nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, err := c.InspectLocalVolume(ctx, volname); err != apiError(404) {
		t.Fatal("source volume absence before independent restore", err)
	}
	dest := filepath.Join(root, "destination")
	os.Mkdir(dest, 0700)
	jobs(fileFixtureJob{Action: "restore", Run: "restore", Snapshot: snapshots[1], Destination: "/restore"}, "-restore", []map[string]any{bind(filepath.Join(hostRoot, "destination"), "/restore", false)})
	data, e := os.ReadFile(filepath.Join(dest, "payload"))
	if e != nil || len(data) != 4*1048576+len("real-local-volume\n") || !strings.HasSuffix(string(data), "real-local-volume\n") {
		t.Fatal("content roundtrip", len(data), e)
	}
	stat, e := os.Stat(filepath.Join(dest, "payload"))
	if e != nil || stat.Mode().Perm() != 0640 {
		t.Fatal("permission roundtrip", stat, e)
	}
	ownership := stat.Sys().(*syscall.Stat_t)
	if ownership.Uid != 1234 || ownership.Gid != 2345 {
		t.Fatal("ownership roundtrip", ownership.Uid, ownership.Gid)
	}
	t.Logf("independent source-gone local-volume roundtrip bytes=%d mode=%o uid=%d gid=%d", len(data), stat.Mode().Perm(), ownership.Uid, ownership.Gid)
}
