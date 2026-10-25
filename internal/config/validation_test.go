package config

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestInvalidConfiguration(t *testing.T) {
	cases := map[string]string{
		"version":                      strings.Replace(minimal, "version: 1", "version: 2", 1),
		"installation":                 strings.Replace(minimal, "fixture", "../SECRET", 1),
		"required installation":        strings.Replace(minimal, "installation: fixture\n", "", 1),
		"explicit platform":            strings.Replace(minimal, "platform: compose\n", "", 1),
		"bad platform":                 strings.Replace(minimal, "compose", "auto", 1),
		"empty scope":                  strings.Replace(minimal, "[app]", "[]", 1),
		"duplicate scope":              strings.Replace(minimal, "[app]", "[app, app]", 1),
		"invalid scope":                strings.Replace(minimal, "[app]", "['../SECRET']", 1),
		"required repository":          strings.Replace(minimal, "repository: /repository\n", "", 1),
		"relative repository":          strings.Replace(minimal, "/repository", "relative", 1),
		"inline URL credentials":       strings.Replace(minimal, "/repository", "s3:https://SECRET:SECRET@host/bucket", 1),
		"required password":            strings.Replace(minimal, "  password_file: /run/secrets/restic", "  password_file: ''", 1),
		"root password":                strings.Replace(minimal, "/run/secrets/restic", "/", 1),
		"root socket":                  minimal + "docker_socket: /\n",
		"relative password":            strings.Replace(minimal, "/run/secrets/restic", "relative", 1),
		"credential traversal":         strings.Replace(minimal, "/run/secrets/restic", "/run/../SECRET", 1),
		"optional credential relative": minimal + "  nope: value\n", // malformed mapping is always invalid
		"bad optional credential":      strings.Replace(minimal, "  password_file:", "  s3_credentials_file: relative\n  password_file:", 1),
		"image tag":                    strings.Replace(minimal, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "trusted:latest", 1),
		"empty explicit default":       minimal + "docker_socket: ''\n",
		"state traversal":              minimal + "state_dir: /var/../SECRET\n",
		"bad timeout":                  minimal + "timeout: SECRET\n",
		"zero timeout":                 minimal + "timeout: 0s\n",
		"bad timezone":                 minimal + "timezone: SECRET\n",
		"empty timezone":               minimal + "timezone: ''\n",
		"cron fields":                  minimal + "schedule: '* * * *'\n",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(s))
			if err == nil {
				t.Fatal("accepted invalid config")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("unsafe error")
			}
		})
	}
}

func TestExplicitOptions(t *testing.T) {
	s := strings.Replace(minimal, "platform: compose", "platform: swarm", 1) + "docker_socket: /docker.sock\nstate_dir: /state\ntimeout: 2m\nschedule: '0 3 * * *'\ntimezone: Asia/Ho_Chi_Minh\n"
	s = strings.Replace(s, "  password_file:", "  s3_credentials_file: /credentials/s3\n  s3_region: fixture-region\n  password_file:", 1)
	s = strings.Replace(s, "/repository", "s3:https://s3.example/bucket/prefix", 1)
	c, e := Parse(strings.NewReader(s))
	if e != nil {
		t.Fatal(e)
	}
	if c.Timeout != 2*time.Minute || c.Timezone != "Asia/Ho_Chi_Minh" || c.DockerSocket != "/docker.sock" || c.StateDir != "/state" || c.Credentials.S3CredentialsFile != "/credentials/s3" || c.Credentials.S3Region != "fixture-region" {
		t.Fatal("options lost")
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("SECRET") }
func TestYAMLBoundary(t *testing.T) {
	for name, s := range map[string]string{
		"unknown":               minimal + "password: SECRET\n",
		"nested unknown":        strings.Replace(minimal, "  password_file:", "  secret: SECRET\n  password_file:", 1),
		"duplicate":             minimal + "platform: swarm\n",
		"nested duplicate":      strings.Replace(minimal, "  password_file:", "  password_file: SECRET\n  password_file:", 1),
		"multi-document":        minimal + "---\npassword: SECRET\n",
		"empty second document": minimal + "---\n",
		"oversize":              minimal + "#" + strings.Repeat("x", 65536),
		"alias":                 strings.Replace(minimal, "installation: fixture", "installation: &id fixture", 1) + "timezone: *id\n",
		"null":                  minimal + "timezone: null\n",
		"merge":                 minimal + "<<: {password: SECRET}\n",
		"sequence root":         "- SECRET\n",
		"bad scalar type":       strings.Replace(minimal, "version: 1", "version: '1'", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, e := Parse(strings.NewReader(s))
			if e == nil {
				t.Fatal("accepted invalid YAML")
			}
			if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("unsafe YAML error")
			}
		})
	}
	if _, e := Parse(brokenReader{}); e == nil || strings.Contains(e.Error(), "SECRET") {
		t.Fatal("unsafe reader error")
	}
	if _, e := Parse(io.LimitReader(strings.NewReader(minimal), 0)); e == nil {
		t.Fatal("empty accepted")
	}
}
