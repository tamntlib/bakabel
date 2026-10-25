package config

import (
	"math"
	"strings"
	"testing"
)

func TestWorkerResourcesDefaultAndPartialOverride(t *testing.T) {
	for _, tc := range []struct {
		extra        string
		cpus, memory int64
	}{
		{"", 2, 512},
		{"worker_resources:\n  cpus: 1\n", 1, 512},
		{"worker_resources:\n  memory_mib: 1024\n", 2, 1024},
		{"worker_resources:\n  cpus: 0\n  memory_mib: 0\n", 2, 512},
	} {
		c, err := Parse(strings.NewReader(minimal + tc.extra))
		if err != nil {
			t.Fatal(err)
		}
		got := c.WorkerResources.Effective()
		if got.CPUs != tc.cpus || got.MemoryMiB != tc.memory {
			t.Fatal(got, tc)
		}
	}
	for _, value := range []WorkerResources{{CPUs: -1}, {MemoryMiB: -1}, {CPUs: math.MaxInt64}, {MemoryMiB: math.MaxInt64}} {
		if value.Validate() == nil {
			t.Fatal("invalid resource limit accepted", value)
		}
	}
	for _, extra := range []string{"worker_resources:\n  cpus: 0.5\n", "worker_resources:\n  memory_mib: unlimited\n", "worker_resources:\n  arbitrary: 1\n"} {
		if _, err := Parse(strings.NewReader(minimal + extra)); err == nil {
			t.Fatal("invalid resource config accepted")
		}
	}
}
