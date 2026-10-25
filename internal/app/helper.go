// Package app exposes the user CLI, fixed worker/export helpers and ownership lifecycle.
package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/tamntlib/bakabel/internal/platform/docker"
)

// Main dispatches the user CLI and fixed internal helpers. No arbitrary command
// surface is accepted. Export stdout is exclusively dump bytes.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fail := func() int { fmt.Fprintln(stderr, "bakabel: export failed"); return 1 }
	if len(args) == 1 && args[0] == "_workflow" {
		return runWorkflow(ctx)
	}
	if len(args) == 1 && args[0] == "_worker" {
		return runWorker(ctx)
	}
	if len(args) == 0 || args[0] != "_export" {
		return publicMain(ctx, args, stdout, stderr)
	}
	fs := flag.NewFlagSet("_export", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var d docker.Dump
	var socket string
	var timeout time.Duration
	fs.StringVar(&socket, "socket", "", "")
	fs.StringVar(&d.Source.DaemonID, "daemon", "", "")
	fs.StringVar(&d.Source.ContainerID, "container", "", "")
	fs.StringVar(&d.Source.StartedAt, "started", "", "")
	fs.StringVar(&d.ExecID, "exec", "", "")
	fs.StringVar(&d.RunID, "run", "", "")
	fs.StringVar(&d.Database, "database", "", "")
	fs.StringVar(&d.User, "user", "", "")
	fs.DurationVar(&timeout, "timeout", 0, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || timeout <= 0 || d.Source.DaemonID == "" || d.Source.ContainerID == "" || d.Source.StartedAt == "" || d.ExecID == "" || d.RunID == "" || d.Database == "" || d.User == "" {
		return fail()
	}
	c, e := docker.NewClient(socket)
	if e != nil {
		return fail()
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, e := c.StreamDump(ctx, d, stdout)
	if e != nil || code != 0 {
		return fail()
	}
	return 0
}

// ExportArgs pins the immutable non-secret identity. The caller must durably
// authorize this exact helper before giving these arguments to Restic.
func ExportArgs(socket string, d docker.Dump, timeout time.Duration) []string {
	return []string{"_export", "--socket", socket, "--daemon", d.Source.DaemonID, "--container", d.Source.ContainerID, "--started", d.Source.StartedAt, "--exec", d.ExecID, "--run", d.RunID, "--database", d.Database, "--user", d.User, "--timeout", timeout.String()}
}
