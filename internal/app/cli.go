package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func loadConfig(path string) (config.Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return config.Config{}, config.ErrInvalid
	}
	defer f.Close()
	c, e := config.Parse(f)
	if e != nil {
		return config.Config{}, e
	}
	c.SourceFile, e = filepath.Abs(path)
	if e != nil {
		return config.Config{}, config.ErrInvalid
	}
	return c, nil
}

func discoveryOptions(c config.Config) docker.DiscoveryOptions {
	return docker.DiscoveryOptions{Installation: c.Installation, Platform: c.Platform, Scope: c.Scope, DockerSocket: c.DockerSocket, StateDir: c.StateDir, Repository: c.Repository, PasswordFile: c.Credentials.PasswordFile, S3CredentialsFile: c.Credentials.S3CredentialsFile}
}

func publicMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fail := func(e error) int { fmt.Fprintln(stderr, "bakabel:", e); return 1 }
	if len(args) < 3 || args[0] != "--config" || args[1] == "" {
		return fail(errors.New("usage: bakabel --config FILE plan|run|serve|health|snapshots|restore"))
	}
	c, e := loadConfig(args[1])
	if e != nil {
		return fail(config.ErrInvalid)
	}
	if args[2] != "serve" {
		bounded, cancel := context.WithTimeout(ctx, c.Timeout)
		defer cancel()
		ctx = bounded
	}
	switch args[2] {
	case "serve":
		if len(args) != 3 {
			return fail(errors.New("serve accepts no arguments"))
		}
		if e = Serve(ctx, c, stdout, stderr); e != nil {
			return fail(e)
		}
		return 0
	case "health":
		if len(args) != 3 {
			return fail(errors.New("health accepts no arguments"))
		}
		health, err := Health(c, time.Now())
		if json.NewEncoder(stdout).Encode(health) != nil {
			return 1
		}
		if err != nil {
			return fail(err)
		}
		return 0
	case "restore":
		req, e := parseRestore(args[3:])
		if e != nil {
			return fail(e)
		}
		result, e := Restore(ctx, c, req)
		reportFailure(ctx, c, result, e, stderr)
		if result.RunID != "" {
			if json.NewEncoder(stdout).Encode(result) != nil {
				return 1
			}
		}
		if e != nil {
			return fail(e)
		}
		return 0
	case "run":
		if len(args) != 3 {
			return fail(errors.New("run accepts no arguments"))
		}
		result, e := Run(ctx, c)
		reportFailure(ctx, c, result, e, stderr)
		if result.RunID != "" {
			if json.NewEncoder(stdout).Encode(result) != nil {
				return 1
			}
		}
		if e != nil {
			return fail(e)
		}
		return 0
	case "snapshots":
		if len(args) != 3 {
			return fail(errors.New("snapshots accepts no arguments"))
		}
		snaps, e := configuredRepository(c).Snapshots(ctx)
		if e != nil {
			return fail(e)
		}
		rows := make([]snapshotRow, 0, len(snaps))
		for _, s := range snaps {
			rows = append(rows, describeSnapshot(s))
		}
		if json.NewEncoder(stdout).Encode(rows) != nil {
			return 1
		}
		return 0
	case "plan":
		if len(args) != 3 {
			return fail(errors.New("plan accepts no arguments"))
		}
		client, e := docker.NewClient(c.DockerSocket)
		if e != nil {
			return fail(errors.New("discovery failed"))
		}
		defer client.Close()
		opts := discoveryOptions(c)
		if name, err := os.Hostname(); err == nil {
			if self, err := client.InspectContainer(ctx, name); err == nil {
				opts.RunnerContainerID = self.ID
			}
		}
		targets, e := client.Discover(ctx, opts)
		if e != nil {
			return fail(e)
		}
		if targets == nil {
			targets = []docker.Target{}
		}
		if json.NewEncoder(stdout).Encode(struct {
			Targets []docker.Target `json:"targets"`
		}{targets}) != nil {
			return 1
		}
		return 0
	default:
		return fail(errors.New("unknown command"))
	}
}
