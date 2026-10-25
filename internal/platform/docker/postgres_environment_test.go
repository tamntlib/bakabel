package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPostgresEnvironmentClearsInheritedHostAddress(t *testing.T) {
	count := 0
	for _, entry := range pgEnv("bakabel_env_0123456789abcdef") {
		if strings.HasPrefix(entry, "PGHOSTADDR=") {
			count++
			if entry != "PGHOSTADDR=" {
				t.Fatal("PostgreSQL host address was not cleared")
			}
		}
	}
	if count != 1 {
		t.Fatal("local conninfo must not inherit a TCP hostaddr", count)
	}
}

// A container-level libpq default must not redirect control/export/restore away
// from the pinned Unix endpoint. The real fixture permits Unix and rejects TCP.
func TestRealPostgresInheritedHostAddressCannotRedirect(t *testing.T) {
	socket := os.Getenv("BAKABEL_DOCKER_SOCKET")
	if socket == "" {
		t.Skip("explicit disposable Docker fixture opt-in required")
	}
	c, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := fmt.Sprintf("bakabel-pg-env-%d", time.Now().UnixNano())
	var created struct {
		ID string `json:"Id"`
	}
	script := "while [ ! -e /tmp/bakabel-env-ready ]; do sleep .1; done; unset PGHOSTADDR; printf 'local all all trust\\nhost all all 127.0.0.1/32 reject\\nhost all all ::1/128 reject\\n' > /tmp/bakabel-env-hba; exec docker-entrypoint.sh postgres -c hba_file=/tmp/bakabel-env-hba"
	cfg := map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"sh", "-c", script}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_DB=fixture", "POSTGRES_USER=postgres", "PGHOSTADDR=127.0.0.1"}, "HostConfig": map[string]any{"NanoCpus": 2000000000, "CpusetCpus": "0,1", "NetworkMode": "none"}}
	if err = c.request(ctx, "POST", "/containers/create?name="+name, cfg, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("missing fixture identity")
	}
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if err := c.request(clean, "DELETE", "/containers/"+created.ID+"?force=true&v=true", nil, nil); err != nil {
			t.Error(err)
		}
		if _, err := c.InspectContainer(clean, created.ID); err != apiError(404) {
			t.Error("fixture cleanup readback", err)
		}
	})
	if err = c.request(ctx, "POST", "/containers/"+created.ID+"/start", nil, nil); err != nil {
		t.Fatal(err)
	}
	source, err := c.CaptureSource(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.InspectContainer(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("taskset", "-pc", "0,1", strconv.Itoa(initial.State.Pid)).CombinedOutput(); err != nil {
		t.Fatalf("fixture requires runner --pid host: %s %v", out, err)
	}
	if _, err = c.control(ctx, source, []string{"sh", "-c", ": > /tmp/bakabel-env-ready"}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; ; attempt++ {
		if _, err = c.control(ctx, source, []string{"pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "fixture"}); err == nil {
			break
		}
		if attempt >= 100 {
			t.Fatal("fixture readiness failed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	pg, err := c.PreparePostgres(ctx, source)
	if err != nil {
		t.Fatal("inherited hostaddr bypassed the required Unix endpoint", err)
	}
	raw, err := c.sql(ctx, pg, "SELECT inet_client_addr() IS NULL")
	if err != nil || strings.TrimSpace(string(raw)) != "t" {
		t.Fatal("control did not use Unix", err)
	}
	checkpoint := filepath.Join(t.TempDir(), "dump.json")
	dump, err := c.CreateDump(ctx, pg, "bakabel_env_0123456789abcdef", func(d Dump) error {
		f, err := os.OpenFile(checkpoint, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = json.NewEncoder(f).Encode(d); err != nil {
			return err
		}
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	sink := &countSink{}
	if code, err := c.StreamDump(ctx, dump, sink); err != nil || code != 0 || sink.magic != "PGDMP" {
		t.Fatal("dump did not use Unix", code, err)
	}
	proof, err := c.CancelDump(ctx, dump)
	if err != nil || !proof.NoProcesses || !proof.NoSessions {
		t.Fatal("dump terminal proof", proof, err)
	}
	final, err := c.InspectContainer(ctx, created.ID)
	if err != nil || !final.State.Running || final.State.StartedAt != initial.State.StartedAt || final.RestartCount != initial.RestartCount {
		t.Fatal("source changed", err)
	}
}
