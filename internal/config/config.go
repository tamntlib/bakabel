// Package config loads Bakabel runtime settings from environment variables.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/robfig/cron/v3"
)

// Retention configures optional restic forget/prune counts. Zero disables all pruning.
type Retention struct {
	Last    int
	Hourly  int
	Daily   int
	Weekly  int
	Monthly int
	Yearly  int
}

// Enabled reports whether any retention count is non-zero.
func (r Retention) Enabled() bool {
	return r.Last > 0 || r.Hourly > 0 || r.Daily > 0 || r.Weekly > 0 || r.Monthly > 0 || r.Yearly > 0
}

// Config holds all Bakabel settings parsed from environment variables.
type Config struct {
	Repository         string
	ResticPassword     string
	ResticPasswordFile string
	ResticBin          string
	SqliteBin          string
	ResticCacheDir     string

	AWSAccessKeyID     string
	AWSAccessKeyIDFile string
	AWSSecretAccessKey string
	AWSSecretKeyFile   string
	AWSDefaultRegion   string

	Platform      string // "auto", "swarm", or "compose"
	Scope         []string
	Installation  string
	DockerSocket  string
	StateDir      string
	WorkerImage   string
	WorkerNetwork string

	Schedule string
	Timezone string
	Timeout  time.Duration
	AutoInit bool

	Retention      Retention
	WebhookURL     string
	WebhookURLFile string
}

// Load parses configuration from getenv (defaults to os.Getenv when nil).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(getenv(k)); v != "" {
				return v
			}
		}
		return ""
	}

	cfg := Config{
		Repository:         get("BAKABEL_REPOSITORY", "RESTIC_REPOSITORY"),
		ResticPassword:     getenv("RESTIC_PASSWORD"),
		ResticPasswordFile: get("RESTIC_PASSWORD_FILE"),
		ResticBin:          get("RESTIC_BIN"),
		SqliteBin:          get("SQLITE3_BIN"),
		ResticCacheDir:     get("RESTIC_CACHE_DIR"),

		AWSAccessKeyID:     getenv("AWS_ACCESS_KEY_ID"),
		AWSAccessKeyIDFile: get("AWS_ACCESS_KEY_ID_FILE"),
		AWSSecretAccessKey: getenv("AWS_SECRET_ACCESS_KEY"),
		AWSSecretKeyFile:   get("AWS_SECRET_ACCESS_KEY_FILE"),
		AWSDefaultRegion:   get("AWS_DEFAULT_REGION"),

		Platform:      strings.ToLower(get("BAKABEL_PLATFORM")),
		Installation:  get("BAKABEL_INSTALLATION"),
		DockerSocket:  get("BAKABEL_DOCKER_SOCKET"),
		StateDir:      get("BAKABEL_STATE_DIR"),
		WorkerImage:   get("BAKABEL_WORKER_IMAGE"),
		WorkerNetwork: get("BAKABEL_WORKER_NETWORK"),

		Schedule:       get("BAKABEL_SCHEDULE"),
		Timezone:       get("BAKABEL_TZ", "TZ"),
		WebhookURL:     get("BAKABEL_WEBHOOK_URL"),
		WebhookURLFile: get("BAKABEL_WEBHOOK_URL_FILE"),
		AutoInit:       true,
	}

	if cfg.ResticBin == "" {
		cfg.ResticBin = "restic"
	}
	if cfg.SqliteBin == "" {
		cfg.SqliteBin = "sqlite3"
	}
	if cfg.Platform == "" {
		cfg.Platform = "auto"
	}
	if cfg.Installation == "" {
		cfg.Installation = "bakabel"
	}
	if cfg.DockerSocket == "" {
		cfg.DockerSocket = "/var/run/docker.sock"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/bakabel"
	}
	if cfg.ResticCacheDir == "" {
		cfg.ResticCacheDir = filepath.Join(cfg.StateDir, "cache")
	}
	if cfg.Schedule == "" {
		cfg.Schedule = "0 2 * * *"
	}
	if cfg.Timezone == "" {
		cfg.Timezone = "UTC"
	}

	if raw := get("BAKABEL_SCOPE"); raw != "" {
		seen := make(map[string]struct{})
		for _, part := range strings.Split(raw, ",") {
			item := strings.TrimSpace(part)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; !ok {
				seen[item] = struct{}{}
				cfg.Scope = append(cfg.Scope, item)
			}
		}
	}

	if raw := get("BAKABEL_TIMEOUT"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("invalid BAKABEL_TIMEOUT %q: must be a positive duration", raw)
		}
		cfg.Timeout = d
	} else {
		cfg.Timeout = time.Hour
	}

	if raw := get("BAKABEL_AUTO_INIT"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, fmt.Errorf("invalid BAKABEL_AUTO_INIT %q: must be true or false", raw)
		}
		cfg.AutoInit = b
	}

	if raw := get("BAKABEL_RETENTION"); raw != "" {
		ret, err := ParseRetention(raw)
		if err != nil {
			return cfg, fmt.Errorf("invalid BAKABEL_RETENTION: %w", err)
		}
		cfg.Retention = ret
	}

	return cfg, nil
}

// ParseRetention parses concise retention specs such as "7d,4w,6m" or "daily=7,weekly=4".
func ParseRetention(raw string) (Retention, error) {
	var r Retention
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		var unit string
		var n int
		var err error
		if k, v, ok := strings.Cut(token, "="); ok {
			unit = strings.ToLower(strings.TrimSpace(k))
			n, err = strconv.Atoi(strings.TrimSpace(v))
		} else {
			if len(token) < 2 {
				return r, fmt.Errorf("invalid token %q", token)
			}
			unit = strings.ToLower(token[len(token)-1:])
			n, err = strconv.Atoi(token[:len(token)-1])
		}
		if err != nil || n < 0 {
			return r, fmt.Errorf("invalid count in %q", token)
		}
		switch unit {
		case "l", "last":
			r.Last = n
		case "h", "hourly":
			r.Hourly = n
		case "d", "daily":
			r.Daily = n
		case "w", "weekly":
			r.Weekly = n
		case "m", "monthly":
			r.Monthly = n
		case "y", "yearly":
			r.Yearly = n
		default:
			return r, fmt.Errorf("unknown retention unit %q in %q", unit, token)
		}
	}
	return r, nil
}

// ValidateDiscovery validates settings needed for Docker label discovery.
func (c Config) ValidateDiscovery() error {
	switch c.Platform {
	case "auto", "swarm", "compose":
	default:
		return fmt.Errorf("invalid BAKABEL_PLATFORM %q: expected auto, swarm, or compose", c.Platform)
	}
	if !filepath.IsAbs(c.DockerSocket) {
		return errors.New("BAKABEL_DOCKER_SOCKET must be an absolute path")
	}
	if strings.ContainsAny(c.Installation, " \t\r\n,/") || c.Installation == "" {
		return errors.New("BAKABEL_INSTALLATION must be a non-empty identifier without whitespace or slashes")
	}
	return nil
}

// ValidateRepo validates repository and credential settings.
func (c Config) ValidateRepo() error {
	if c.Repository == "" {
		return errors.New("BAKABEL_REPOSITORY (or RESTIC_REPOSITORY) is required")
	}
	if c.ResticPassword == "" && c.ResticPasswordFile == "" {
		return errors.New("RESTIC_PASSWORD or RESTIC_PASSWORD_FILE is required")
	}
	if c.ResticPasswordFile != "" && !filepath.IsAbs(c.ResticPasswordFile) {
		return errors.New("RESTIC_PASSWORD_FILE must be an absolute path")
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("BAKABEL_STATE_DIR must be an absolute path")
	}
	return nil
}

// ValidateSchedule validates cron expression and timezone settings.
func (c Config) ValidateSchedule() (cron.Schedule, *time.Location, error) {
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid timezone %q: %w", c.Timezone, err)
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(c.Schedule)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid BAKABEL_SCHEDULE %q: %w", c.Schedule, err)
	}
	return sched, loc, nil
}

// IsLocalRepo reports whether the repository points to a local filesystem path.
func (c Config) IsLocalRepo() bool {
	return filepath.IsAbs(c.Repository)
}

// ReadSecret resolves a value directly or from an accompanying *_FILE path.
func ReadSecret(direct, filePath string) (string, error) {
	if direct != "" {
		return direct, nil
	}
	if filePath == "" {
		return "", nil
	}
	b, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot read secret file %s: %w", filePath, err)
	}
	val := strings.TrimRight(string(b), "\r\n")
	if val == "" {
		return "", fmt.Errorf("secret file %s is empty", filePath)
	}
	return val, nil
}

// ResolveWebhookURL returns the optional failure webhook URL from env or file.
func (c Config) ResolveWebhookURL() (string, error) {
	return ReadSecret(c.WebhookURL, c.WebhookURLFile)
}
