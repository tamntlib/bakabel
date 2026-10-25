package app

import (
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
)

func TestResticConcurrencyFollowsWorkerCPUOverride(t *testing.T) {
	c := healthConfig(t)
	c.WorkerResources = config.WorkerResources{CPUs: 1}
	env := configuredRepository(c).Env
	if !strings.Contains(strings.Join(env, "\n"), "GOMAXPROCS=1\n") {
		t.Fatal("Restic concurrency ignores CPU limit")
	}
}
