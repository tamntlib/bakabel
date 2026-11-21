package runner

import (
	"encoding/json"
	"net"
	"net/http"
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
