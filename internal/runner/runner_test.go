package runner

import (
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
	if netMode := r.resolveWorkerNetwork(self); netMode != "none" {
		t.Fatalf("local repo worker network = %q, want none", netMode)
	}
}
