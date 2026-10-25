// Package config reads installation configuration without loading credential contents.
package config

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/tamntlib/bakabel/internal/schedule"

	"gopkg.in/yaml.v3"
)

const MaxSize = 64 * 1024

var ErrInvalid = errors.New("invalid installation configuration")

type Credentials struct {
	PasswordFile      string `yaml:"password_file"`
	S3CredentialsFile string `yaml:"s3_credentials_file"`
	S3Region          string `yaml:"s3_region"`
}

type Retention struct {
	Daily   int `yaml:"daily"`
	Weekly  int `yaml:"weekly"`
	Monthly int `yaml:"monthly"`
}

type Config struct {
	// SourceFile is CLI provenance, not a configuration key or worker input.
	SourceFile          string          `yaml:"-" json:"-"`
	Version             int             `yaml:"version"`
	Installation        string          `yaml:"installation"`
	Platform            string          `yaml:"platform"`
	Scope               []string        `yaml:"scope"`
	Repository          string          `yaml:"repository"`
	Credentials         Credentials     `yaml:"credentials"`
	DockerSocket        string          `yaml:"docker_socket"`
	StateDir            string          `yaml:"state_dir"`
	WorkerImage         string          `yaml:"worker_image"`
	WorkerResources     WorkerResources `yaml:"worker_resources"`
	Timeout             time.Duration   `yaml:"-"`
	Schedule            string          `yaml:"schedule"`
	Timezone            string          `yaml:"timezone"`
	Retention           Retention       `yaml:"retention"`
	NotificationURLFile string          `yaml:"notification_url_file"`
}

// Parse accepts exactly one bounded document. Errors never include input values,
// YAML parser messages, reader errors, or credential file contents.
func Parse(r io.Reader) (Config, error) {
	b, e := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if e != nil || len(b) > MaxSize {
		return Config{}, ErrInvalid
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	var doc, extra yaml.Node
	if e = d.Decode(&doc); e != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode || !safeNode(doc.Content[0], "") {
		return Config{}, ErrInvalid
	}
	if e = d.Decode(&extra); e != io.EOF {
		return Config{}, ErrInvalid
	}
	wire := struct {
		Config     `yaml:",inline"`
		RawTimeout string `yaml:"timeout"`
	}{Config: Config{DockerSocket: "/var/run/docker.sock", StateDir: "/var/lib/bakabel", Timezone: "UTC"}, RawTimeout: "30m"}
	d = yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(&wire); e != nil {
		return Config{}, ErrInvalid
	}
	wire.Timeout, e = time.ParseDuration(wire.RawTimeout)
	if e != nil || wire.Config.Validate() != nil {
		return Config{}, ErrInvalid
	}
	return wire.Config, nil
}

func safeNode(n *yaml.Node, field string) bool {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode:
		if field != "" && field != "credentials" && field != "retention" && field != "worker_resources" {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag != "!!str" || seen[k.Value] || k.Value == "<<" {
				return false
			}
			seen[k.Value] = true
			if !safeNode(v, k.Value) {
				return false
			}
		}
		return true
	case yaml.SequenceNode:
		if field != "scope" {
			return false
		}
		for _, v := range n.Content {
			if v.Kind != yaml.ScalarNode || v.Tag != "!!str" || !safeNode(v, "scope_item") {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		if field == "version" || field == "daily" || field == "weekly" || field == "monthly" || field == "cpus" || field == "memory_mib" {
			return n.Tag == "!!int"
		}
		return n.Tag == "!!str" && field != "credentials" && field != "scope" && field != "retention" && field != "worker_resources"
	}
	return false
}

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
var imageID = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64})$`)

func absoluteClean(s string) bool {
	return strings.HasPrefix(s, "/") && s != "/" && path.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}

// Validate also validates programmatically constructed configuration. Schedule
// syntax beyond the five-field boundary belongs to the scheduler's cron parser.
func (c Config) Validate() error {
	if c.WorkerResources.Validate() != nil {
		return ErrInvalid
	}
	if c.Version != 1 || !safeID.MatchString(c.Installation) || c.Platform != "compose" && c.Platform != "swarm" || len(c.Scope) == 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range c.Scope {
		if !safeID.MatchString(s) || seen[s] {
			return ErrInvalid
		}
		seen[s] = true
	}
	if !repository(c.Repository) || !absoluteClean(c.Credentials.PasswordFile) || c.Credentials.S3CredentialsFile != "" && !absoluteClean(c.Credentials.S3CredentialsFile) {
		return ErrInvalid
	}
	if !absoluteClean(c.DockerSocket) || !absoluteClean(c.StateDir) || c.StateDir == "/" || !imageID.MatchString(c.WorkerImage) || c.Timeout <= 0 {
		return ErrInvalid
	}
	if c.Schedule != "" {
		if _, e := schedule.Parse(c.Schedule, c.Timezone); e != nil {
			return ErrInvalid
		}
	}
	if c.Retention.Daily < 0 || c.Retention.Weekly < 0 || c.Retention.Monthly < 0 || (c.NotificationURLFile != "" && !absoluteClean(c.NotificationURLFile)) {
		return ErrInvalid
	}
	if c.Timezone == "" || strings.HasPrefix(c.Timezone, "/") {
		return ErrInvalid
	}
	if _, e := time.LoadLocation(c.Timezone); e != nil {
		return ErrInvalid
	}
	if strings.ContainsAny(c.Credentials.S3Region, "\x00\r\n") {
		return ErrInvalid
	}
	return nil
}

func repository(s string) bool {
	if absoluteClean(s) {
		return s != "/"
	}
	if !strings.HasPrefix(s, "s3:") || strings.ContainsAny(s, "\x00\r\n") {
		return false
	}
	endpoint := strings.TrimPrefix(s, "s3:")
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, e := url.Parse(endpoint)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && strings.Trim(u.Path, "/") != ""
}
