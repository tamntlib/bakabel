package app

import (
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"testing"
)

func TestFileRestoreMountsPreserveNativeMetadataVisibility(t *testing.T) {
	runtime := []docker.WorkerMount{{Source: "/node/state", Target: "/state"}, {Source: "/node/repo", Target: "/repository"}, {Source: "/node/pass", Target: workerPassword, ReadOnly: true}}
	consumers := []docker.Mount{{Type: "volume", Source: "/node/volumes/source/_data"}, {Type: "bind", Source: "/node/credentials/file"}}
	mounts, e := PlanFileRestoreMounts(consumers, "/node/restore", runtime)
	if e != nil {
		t.Fatal(e)
	}
	if len(mounts) != 3 {
		t.Fatal(mounts)
	}
	for i, m := range mounts[:2] {
		if m.Source != consumers[i].Source || m.Target != m.Source || !m.ReadOnly {
			t.Fatal(m)
		}
	}
	if mounts[2].Source != "/node/restore" || mounts[2].Target != "/node/restore" || mounts[2].ReadOnly {
		t.Fatal(mounts)
	}
	for _, bad := range []string{"/", "/proc", "/etc", "/usr", "/state", "/run/bakabel", "/node/restore/child", "/node"} {
		if _, e := PlanFileRestoreMounts([]docker.Mount{{Type: "bind", Source: bad}}, "/node/restore", runtime); e == nil {
			t.Fatal("unsafe native mirror accepted", bad)
		}
	}
	if _, e := PlanFileRestoreMounts(consumers, "/node/state/restore", runtime); e == nil {
		t.Fatal("runtime target overlap")
	}
}
