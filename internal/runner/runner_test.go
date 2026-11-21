package runner

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/docker"
	"github.com/tamntlib/bakabel/internal/restic"
)

func TestMatchSnapshot(t *testing.T) {
	snaps := []restic.Snapshot{
		{ID: "aaaa1111bbbb2222", ShortID: "aaaa1111", Tags: []string{"bakabel", "type:postgres"}},
		{ID: "aaaa9999cccc3333", ShortID: "aaaa9999", Tags: []string{"bakabel", "type:volume"}},
	}
	if s, err := matchSnapshot(snaps, "aaaa1111"); err != nil || s.ID != "aaaa1111bbbb2222" {
		t.Fatalf("exact short ID match failed: %+v, %v", s, err)
	}
	if _, err := matchSnapshot(snaps, "aaaa"); err == nil {
		t.Fatal("expected ambiguous prefix error")
	}
	if _, err := matchSnapshot(snaps, "deadbeef"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestBuildHelperMountsPropagatesNamedVolumesAndBinds(t *testing.T) {
	r := New(config.Config{
		Repository:         "/repository",
		ResticPasswordFile: "/run/secrets/restic-password",
		StateDir:           "/var/lib/bakabel",
	}, nil)
	self := &docker.Container{
		ID:    "self-1",
		Image: "sha256:abc",
		Mounts: []docker.Mount{
			{Type: "volume", Name: "backup_repo", Destination: "/repository", RW: true},
			{Type: "bind", Source: "/srv/secrets/restic-password", Destination: "/run/secrets/restic-password", RW: false},
		},
	}

	mounts, err := r.buildHelperMounts(self)
	if err != nil {
		t.Fatalf("buildHelperMounts: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %+v", mounts)
	}
	if mounts[0].Type != "volume" || mounts[0].Source != "backup_repo" || mounts[0].Target != "/repository" || mounts[0].ReadOnly {
		t.Fatalf("unexpected repo mount: %+v", mounts[0])
	}
	if mounts[1].Type != "bind" || mounts[1].Source != "/srv/secrets/restic-password" || !mounts[1].ReadOnly {
		t.Fatalf("unexpected secret mount: %+v", mounts[1])
	}
	if img := r.resolveWorkerImage(self); img != "sha256:abc" {
		t.Fatalf("resolveWorkerImage = %q, want sha256:abc", img)
	}
	if netMode := r.resolveWorkerNetwork(t.Context(), nil, self); netMode != "none" {
		t.Fatalf("local repo worker network = %q, want none", netMode)
	}
	// Remote S3 repo falls back to bridge when no self container is present.
	s3Runner := New(config.Config{Repository: "s3:https://s3.example.com/bucket"}, nil)
	if netMode := s3Runner.resolveWorkerNetwork(t.Context(), nil, nil); netMode != "bridge" {
		t.Fatalf("remote repo fallback network = %q, want bridge", netMode)
	}
}

func TestResolveWorkerNetworkSwarmAndLocal(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	nets := map[string]docker.Network{
		"backup_default":  {Name: "backup_default", Scope: "swarm", Attachable: false},
		"docker_gwbridge": {Name: "docker_gwbridge", Scope: "local", Attachable: false},
		"s3net":           {Name: "s3net", Scope: "swarm", Attachable: true},
		"ciapp_default":   {Name: "ciapp_default", Scope: "local", Attachable: false},
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Header().Set("Api-Version", "1.45")
			_, _ = w.Write([]byte("OK"))
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/v1.45/networks/"); ok {
			if n, found := nets[name]; found {
				_ = json.NewEncoder(w).Encode(n)
				return
			}
		}
		http.NotFound(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	dc, err := docker.NewClient(sock)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer dc.Close()

	s3Runner := New(config.Config{Repository: "s3:http://minio:9000/backups"}, nil)

	// Swarm container on non-attachable backup_default + docker_gwbridge + attachable s3net:
	// must skip both backup_default and docker_gwbridge and pick s3net.
	selfAttachable := &docker.Container{}
	selfAttachable.NetworkSettings.Networks = map[string]any{
		"backup_default":  map[string]any{},
		"docker_gwbridge": map[string]any{},
		"s3net":           map[string]any{},
	}
	if got := s3Runner.resolveWorkerNetwork(t.Context(), dc, selfAttachable); got != "s3net" {
		t.Fatalf("attachable swarm overlay = %q, want s3net", got)
	}

	// Swarm container with only non-attachable backup_default + docker_gwbridge:
	// must fall back to bridge for public S3/R2 connectivity.
	selfNonAttachable := &docker.Container{}
	selfNonAttachable.NetworkSettings.Networks = map[string]any{
		"backup_default":  map[string]any{},
		"docker_gwbridge": map[string]any{},
	}
	if got := s3Runner.resolveWorkerNetwork(t.Context(), dc, selfNonAttachable); got != "bridge" {
		t.Fatalf("non-attachable swarm fallback = %q, want bridge", got)
	}

	// Compose container on local user bridge: picks ciapp_default.
	selfCompose := &docker.Container{}
	selfCompose.NetworkSettings.Networks = map[string]any{
		"ciapp_default": map[string]any{},
	}
	if got := s3Runner.resolveWorkerNetwork(t.Context(), dc, selfCompose); got != "ciapp_default" {
		t.Fatalf("compose bridge = %q, want ciapp_default", got)
	}

	// Explicit override always wins.
	overrideRunner := New(config.Config{Repository: "s3:http://minio:9000/backups", WorkerNetwork: "custom-net"}, nil)
	if got := overrideRunner.resolveWorkerNetwork(t.Context(), dc, selfAttachable); got != "custom-net" {
		t.Fatalf("explicit override = %q, want custom-net", got)
	}
}

func TestSqliteHelpersAndValidation(t *testing.T) {
	rel, full, err := resolveSafeSubpath("/sqlite-src", "nested/app.db")
	if err != nil || rel != "nested/app.db" || full != "/sqlite-src/nested/app.db" {
		t.Fatalf("resolveSafeSubpath valid failed: rel=%q full=%q err=%v", rel, full, err)
	}
	for _, bad := range []string{"", ".", "..", "../escape.db", "/abs.db"} {
		if _, _, err := resolveSafeSubpath("/sqlite-src", bad); err == nil {
			t.Fatalf("expected resolveSafeSubpath to reject %q", bad)
		}
	}

	if u, g, ok := parseOwnerTag("100:101"); !ok || u != 100 || g != 101 {
		t.Fatalf("parseOwnerTag valid failed: %d:%d ok=%v", u, g, ok)
	}
	for _, bad := range []string{"", "100", "a:b", "-1:0"} {
		if _, _, ok := parseOwnerTag(bad); ok {
			t.Fatalf("expected parseOwnerTag to reject %q", bad)
		}
	}

	badFile := filepath.Join(t.TempDir(), "not-sqlite.db")
	if err := os.WriteFile(badFile, []byte("plain text file, not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSqliteHeader(badFile); err == nil {
		t.Fatal("expected checkSqliteHeader to reject non-SQLite file")
	}
}

func TestSqliteWALBackupAndRestoreRoundTrip(t *testing.T) {
	sqliteBin := os.Getenv("SQLITE3_BIN")
	if sqliteBin == "" {
		sqliteBin = "sqlite3"
	}
	if _, err := exec.LookPath(sqliteBin); err != nil {
		t.Skip("sqlite3 binary not installed in unit test container")
	}
	resticBin := os.Getenv("RESTIC_BIN")
	if resticBin == "" {
		resticBin = "restic"
	}
	if _, err := exec.LookPath(resticBin); err != nil {
		t.Skip("restic binary not installed in unit test container")
	}

	tmp := t.TempDir()
	srcRoot := filepath.Join(tmp, "src")
	dstRoot := filepath.Join(tmp, "dst")
	repoDir := filepath.Join(tmp, "repo")
	stateDir := filepath.Join(tmp, "state")
	for _, d := range []string{srcRoot, dstRoot, repoDir, stateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Create a WAL-mode database and insert rows with autocheckpoint disabled so data lives in -wal.
	dbPath := filepath.Join(srcRoot, "app.db")
	setupSQL := `
PRAGMA journal_mode=WAL;
PRAGMA wal_autocheckpoint=0;
CREATE TABLE usage_events (id INTEGER PRIMARY KEY, model TEXT NOT NULL);
INSERT INTO usage_events (model) VALUES ('gpt-5.4'), ('claude-4.6'), ('gemini-3');
`
	if out, err := exec.Command(sqliteBin, "-bail", dbPath, setupSQL).CombinedOutput(); err != nil {
		t.Fatalf("setup sqlite db: %v: %s", err, out)
	}

	cfg := config.Config{
		Repository:     repoDir,
		ResticPassword: "test-sqlite-password",
		ResticBin:      resticBin,
		SqliteBin:      sqliteBin,
		ResticCacheDir: filepath.Join(stateDir, "cache"),
		StateDir:       stateDir,
		Installation:   "test-host",
		AutoInit:       true,
	}
	r := New(cfg, nil)
	if _, _, err := r.Restic.EnsureRepo(t.Context(), r.Store); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}

	target := docker.Target{
		ID:         "llmproxy/cli-proxy-api-usage/sqlite/data/app.db",
		Type:       "sqlite",
		Stack:      "llmproxy",
		Service:    "cli-proxy-api-usage",
		VolumeName: "llmproxy_cli-proxy-api-usage-data",
		MountPath:  "/data",
		DBPath:     "app.db",
	}
	snapID, err := r.backupSqliteFile(t.Context(), srcRoot, target)
	if err != nil {
		t.Fatalf("backupSqliteFile: %v", err)
	}

	snaps, err := r.Snapshots(t.Context())
	if err != nil || len(snaps) != 1 {
		t.Fatalf("Snapshots: %+v, %v", snaps, err)
	}
	snap := snaps[0]
	if snap.ID != snapID || snap.TagValue("type") != "sqlite" || snap.TagValue("db") != "app.db" {
		t.Fatalf("unexpected sqlite snapshot metadata: %+v", snap)
	}

	// Non-empty restore target must be refused.
	nonEmpty := filepath.Join(tmp, "nonempty")
	if err := os.MkdirAll(nonEmpty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "existing"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.restoreSqliteFile(t.Context(), nonEmpty, snap.ID, snap.Paths[0], snap.TagValue("db"), snap.TagValue("owner")); err == nil {
		t.Fatal("expected restoreSqliteFile to refuse non-empty directory")
	}

	// Restore into empty directory and verify all 3 WAL rows survived cleanly.
	if err := r.restoreSqliteFile(t.Context(), dstRoot, snap.ID, snap.Paths[0], snap.TagValue("db"), snap.TagValue("owner")); err != nil {
		t.Fatalf("restoreSqliteFile: %v", err)
	}
	out, err := exec.Command(sqliteBin, "-bail", filepath.Join(dstRoot, "app.db"), "SELECT count(*) FROM usage_events;").CombinedOutput()
	if err != nil {
		t.Fatalf("query restored sqlite db: %v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "3" {
		t.Fatalf("restored row count = %q, want 3", strings.TrimSpace(string(out)))
	}
}
