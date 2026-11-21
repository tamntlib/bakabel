package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(mapEnv(map[string]string{}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Platform != "auto" || cfg.Schedule != "0 2 * * *" || cfg.Timezone != "UTC" || !cfg.AutoInit {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Timeout != time.Hour || cfg.StateDir != "/var/lib/bakabel" || cfg.DockerSocket != "/var/run/docker.sock" {
		t.Fatalf("unexpected path/timeout defaults: %+v", cfg)
	}
	if err := cfg.ValidateDiscovery(); err != nil {
		t.Fatalf("ValidateDiscovery() failed on defaults: %v", err)
	}
	if err := cfg.ValidateRepo(); err == nil {
		t.Fatal("ValidateRepo() expected error when repository/password unset")
	}
}

func TestLoadEnvOverridesAndRetention(t *testing.T) {
	cfg, err := Load(mapEnv(map[string]string{
		"RESTIC_REPOSITORY": "s3:https://s3.example.com/bucket",
		"RESTIC_PASSWORD":   "secret",
		"BAKABEL_SCOPE":     " llmproxy-data , app , llmproxy-data ",
		"BAKABEL_TZ":        "Asia/Ho_Chi_Minh",
		"BAKABEL_AUTO_INIT": "false",
		"BAKABEL_TIMEOUT":   "30m",
		"BAKABEL_RETENTION": "7d,4w,6m,last=2",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Repository != "s3:https://s3.example.com/bucket" || cfg.IsLocalRepo() {
		t.Fatalf("unexpected repository: %q", cfg.Repository)
	}
	if !reflect.DeepEqual(cfg.Scope, []string{"llmproxy-data", "app"}) {
		t.Fatalf("unexpected scope: %v", cfg.Scope)
	}
	if cfg.AutoInit {
		t.Fatal("expected AutoInit=false")
	}
	if cfg.Timeout != 30*time.Minute {
		t.Fatalf("unexpected timeout: %v", cfg.Timeout)
	}
	wantRet := Retention{Last: 2, Daily: 7, Weekly: 4, Monthly: 6}
	if cfg.Retention != wantRet || !cfg.Retention.Enabled() {
		t.Fatalf("unexpected retention: %+v", cfg.Retention)
	}
	if _, loc, err := cfg.ValidateSchedule(); err != nil || loc.String() != "Asia/Ho_Chi_Minh" {
		t.Fatalf("ValidateSchedule() failed: %v", err)
	}
	if err := cfg.ValidateRepo(); err != nil {
		t.Fatalf("ValidateRepo() failed: %v", err)
	}
}

func TestParseRetentionRejectsInvalid(t *testing.T) {
	for _, bad := range []string{"7x", "daily=-1", "x", "daily=abc"} {
		if _, err := ParseRetention(bad); err == nil {
			t.Errorf("ParseRetention(%q) expected error", bad)
		}
	}
}

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte("my-passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret("", p)
	if err != nil || got != "my-passphrase" {
		t.Fatalf("ReadSecret() = %q, %v", got, err)
	}
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := ReadSecret("", empty); err == nil {
		t.Fatal("expected error on empty secret file")
	}
}
