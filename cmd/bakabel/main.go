package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/runner"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stderr)
		if len(args) == 0 {
			return 1
		}
		return 0
	}

	cmd := args[0]
	rest := args[1:]

	if cmd == "version" || cmd == "--version" {
		fmt.Fprintf(stdout, "bakabel %s\n", version)
		return 0
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "bakabel: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := runner.New(cfg, nil)

	switch cmd {
	case "plan":
		res, err := r.Plan(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "bakabel plan: %v\n", err)
			return 1
		}
		writeJSON(stdout, res)
		return 0

	case "run":
		res, err := r.Run(ctx)
		writeJSON(stdout, res)
		if err != nil {
			fmt.Fprintf(stderr, "bakabel run: %v\n", err)
			return 1
		}
		return 0

	case "serve":
		if err := r.Serve(ctx); err != nil {
			fmt.Fprintf(stderr, "bakabel serve: %v\n", err)
			return 1
		}
		return 0

	case "snapshots":
		snaps, err := r.Snapshots(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "bakabel snapshots: %v\n", err)
			return 1
		}
		writeJSON(stdout, snaps)
		return 0

	case "restore":
		fs := flag.NewFlagSet("restore", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts runner.RestoreOptions
		fs.StringVar(&opts.SnapshotID, "snapshot", "", "snapshot ID (or unique prefix)")
		fs.StringVar(&opts.Container, "container", "", "target PostgreSQL container name or ID")
		fs.StringVar(&opts.Database, "database", "", "target PostgreSQL database (default: container POSTGRES_DB)")
		fs.StringVar(&opts.User, "user", "", "target PostgreSQL user (default: container POSTGRES_USER)")
		fs.StringVar(&opts.Volume, "volume", "", "target empty Docker volume name")
		parseArgs := rest
		if len(rest) > 0 && rest[0] != "" && rest[0][0] != '-' {
			opts.SnapshotID = rest[0]
			parseArgs = rest[1:]
		}
		if err := fs.Parse(parseArgs); err != nil {
			return 1
		}
		if opts.SnapshotID == "" && fs.NArg() > 0 {
			opts.SnapshotID = fs.Arg(0)
		}
		if err := r.Restore(ctx, opts); err != nil {
			fmt.Fprintf(stderr, "bakabel restore: %v\n", err)
			return 1
		}
		writeJSON(stdout, map[string]string{"status": "ok", "snapshot": opts.SnapshotID})
		return 0

	case "health":
		report, ok, err := r.Health()
		if err != nil {
			fmt.Fprintf(stderr, "bakabel health: %v\n", err)
			return 1
		}
		writeJSON(stdout, report)
		if !ok {
			return 1
		}
		return 0

	case "_volume-backup":
		fs := flag.NewFlagSet("_volume-backup", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var targetID, stack, service, volume, mountPath string
		fs.StringVar(&targetID, "target-id", "", "")
		fs.StringVar(&stack, "stack", "", "")
		fs.StringVar(&service, "service", "", "")
		fs.StringVar(&volume, "volume", "", "")
		fs.StringVar(&mountPath, "mount-path", "", "")
		if err := fs.Parse(rest); err != nil {
			return 1
		}
		snapID, err := r.RunVolumeBackupInternal(ctx, targetID, stack, service, volume, mountPath)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
		writeJSON(stdout, map[string]string{"snapshot_id": snapID})
		return 0

	case "_volume-restore":
		fs := flag.NewFlagSet("_volume-restore", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var snapID string
		fs.StringVar(&snapID, "snapshot", "", "")
		if err := fs.Parse(rest); err != nil {
			return 1
		}
		if err := r.RunVolumeRestoreInternal(ctx, snapID); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
		return 0

	case "_sqlite-backup":
		fs := flag.NewFlagSet("_sqlite-backup", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var targetID, stack, service, volume, mountPath, dbPath string
		fs.StringVar(&targetID, "target-id", "", "")
		fs.StringVar(&stack, "stack", "", "")
		fs.StringVar(&service, "service", "", "")
		fs.StringVar(&volume, "volume", "", "")
		fs.StringVar(&mountPath, "mount-path", "", "")
		fs.StringVar(&dbPath, "db-path", "", "")
		if err := fs.Parse(rest); err != nil {
			return 1
		}
		snapID, err := r.RunSqliteBackupInternal(ctx, targetID, stack, service, volume, mountPath, dbPath)
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
		writeJSON(stdout, map[string]string{"snapshot_id": snapID})
		return 0

	case "_sqlite-restore":
		fs := flag.NewFlagSet("_sqlite-restore", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var snapID, snapPath, dbPath, owner string
		fs.StringVar(&snapID, "snapshot", "", "")
		fs.StringVar(&snapPath, "snap-path", "", "")
		fs.StringVar(&dbPath, "db-path", "", "")
		fs.StringVar(&owner, "owner", "", "")
		if err := fs.Parse(rest); err != nil {
			return 1
		}
		if err := r.RunSqliteRestoreInternal(ctx, snapID, snapPath, dbPath, owner); err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
		return 0

	default:
		fmt.Fprintf(stderr, "bakabel: unknown command %q\n", cmd)
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: bakabel <plan|run|serve|snapshots|restore|health|version>")
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil && !errors.Is(err, syscall.EPIPE) {
		fmt.Fprintf(os.Stderr, "bakabel: encode output: %v\n", err)
	}
}
