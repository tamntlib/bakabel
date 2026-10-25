package app

import (
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"testing"
)

func TestRuntimeMountPlanUsesOnlyInspectedSchedulerMounts(t *testing.T) {
	self := docker.Container{}
	self.Config.Labels = map[string]string{"bakabel.installation": "demo", "bakabel.role": "scheduler"}
	self.Mounts = []docker.Mount{
		{Type: "volume", Name: "state", Source: "/volumes/state/_data", Destination: "/var/lib/bakabel", RW: true},
		{Type: "volume", Name: "repository", Source: "/volumes/repository/_data", Destination: "/repo", RW: true},
		{Type: "bind", Source: "/operator/password", Destination: "/credentials/password", RW: false},
		{Type: "bind", Source: "/run/user/1000/docker.sock", Destination: "/var/run/docker.sock", RW: false},
	}
	paths := RuntimePaths{Installation: "demo", StateDir: "/var/lib/bakabel", Repository: "/repo", PasswordFile: "/credentials/password", Socket: "/var/run/docker.sock"}
	plan, err := PlanRuntimeMounts(self, paths)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NodeState != "/volumes/state/_data" || len(plan.Mounts) != 4 {
		t.Fatalf("wrong plan %+v", plan)
	}
	mapped := map[string]docker.WorkerMount{}
	for _, m := range plan.Mounts {
		mapped[m.Target] = m
	}
	if mapped[paths.StateDir].ReadOnly || mapped["/repository"].ReadOnly || !mapped[workerPassword].ReadOnly || !mapped[workerSocket].ReadOnly {
		t.Fatal("mount permissions broadened", mapped)
	}
	if mapped[workerPassword].Source != "/operator/password" || mapped[workerSocket].Source != "/run/user/1000/docker.sock" {
		t.Fatal("scheduler path confused with node path")
	}
	paths.PasswordFile = "/run/secrets/not-an-inspected-mount"
	if _, err = PlanRuntimeMounts(self, paths); err == nil {
		t.Fatal("assumed inherited Swarm secret")
	}
	paths.PasswordFile = "/credentials/password"
	self.Mounts[0].RW = false
	if _, err = PlanRuntimeMounts(self, paths); err == nil {
		t.Fatal("readonly state accepted")
	}
}

func TestRuntimeMountPlanRefusesAmbiguousPathsAndWrongInstallation(t *testing.T) {
	self := docker.Container{}
	self.Config.Labels = map[string]string{"bakabel.installation": "other", "bakabel.role": "scheduler"}
	p := RuntimePaths{Installation: "demo"}
	if _, err := PlanRuntimeMounts(self, p); err == nil {
		t.Fatal("wrong installation accepted")
	}
	self.Config.Labels["bakabel.installation"] = "demo"
	self.Mounts = []docker.Mount{{Type: "volume", Source: "/backing", Destination: "/data", RW: true}}
	p.StateDir = "/data/state"
	p.Repository = "/data/state/repository"
	p.PasswordFile = "/data/password"
	p.Socket = "/data/socket"
	if _, err := PlanRuntimeMounts(self, p); err == nil {
		t.Fatal("repository nested in state accepted")
	}
	p.Repository = "/data/repository"
	p.StateDir = "/data/../escape"
	if _, err := PlanRuntimeMounts(self, p); err == nil {
		t.Fatal("noncanonical path accepted")
	}
}
