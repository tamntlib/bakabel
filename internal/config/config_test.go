package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `version: 1
installation: fixture
platform: compose
scope: [app]
repository: /repository
credentials:
  password_file: /run/secrets/restic
worker_image: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`

func TestParseMinimal(t *testing.T) {
	c, err := Parse(strings.NewReader(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.Installation != "fixture" || c.Platform != "compose" || len(c.Scope) != 1 || c.Scope[0] != "app" || c.Repository != "/repository" || c.Credentials.PasswordFile != "/run/secrets/restic" {
		t.Fatalf("unexpected config: %#v", c)
	}
	if c.DockerSocket != "/var/run/docker.sock" || c.StateDir != "/var/lib/bakabel" || c.Timeout != 30*time.Minute || c.Timezone != "UTC" || c.Schedule != "" {
		t.Fatal("incorrect defaults")
	}
}
