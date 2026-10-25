package app

import (
	"context"
	"errors"
	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/state"
	"path/filepath"
	"strings"

	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func nativePath(p string) bool {
	return p != "/" && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}
func unsafeMirror(p string) bool {
	if !nativePath(p) {
		return true
	}
	for _, root := range []string{"/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64"} {
		if overlap(root, p) {
			return true
		}
	}
	for _, root := range []string{"/run", "/var", "/var/lib", "/home", "/root", "/tmp"} {
		if p == root {
			return true
		}
	}
	return false
}

// PlanFileRestoreMounts grants stat visibility at EXACT inspected native consumer
// roots, not a host-root mount. Content is never passed to Restic as a backup.
// Worker repeats the real Docker consumer/physical alias gate before writing.
func PlanFileRestoreMounts(consumers []docker.Mount, destination string, runtime []docker.WorkerMount) ([]docker.WorkerMount, error) {
	fail := func() ([]docker.WorkerMount, error) {
		return nil, errors.New("file restore requires safe native consumer path visibility")
	}
	if unsafeMirror(destination) {
		return fail()
	}
	protected := []string{"/run/bakabel", "/run/secrets", "/tmp"}
	for _, m := range runtime {
		if overlap(destination, m.Source) || overlap(destination, m.Target) {
			return fail()
		}
		protected = append(protected, m.Target)
	}
	seen := map[string]bool{}
	mirrors := []docker.WorkerMount{}
	for _, m := range consumers {
		if m.Type != "bind" && m.Type != "volume" {
			continue
		}
		p := m.Source
		if unsafeMirror(p) || overlap(p, destination) {
			return fail()
		}
		for _, root := range protected {
			if overlap(root, p) {
				return fail()
			}
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		mirrors = append(mirrors, docker.WorkerMount{Source: p, Target: p, ReadOnly: true})
	}
	mirrors = append(mirrors, docker.WorkerMount{Source: destination, Target: destination})
	return mirrors, nil
}

func restoreFilesTarget(ctx context.Context, o *state.Owner, c *docker.Client, repo backup.Repository, j workflowJob, t docker.Target) TargetResult {
	tr := TargetResult{TargetID: t.ID, Status: "unknown", SnapshotID: j.Restore.SnapshotID, Error: "restore failed"}
	s, e := exactSnapshot(ctx, repo, j.Restore.SnapshotID)
	if e != nil {
		return tr
	}
	r, e := o.Load()
	if e != nil {
		return tr
	}
	w := recordWorker(r)
	forbidden := []string{j.Config.StateDir}
	if strings.HasPrefix(j.Config.Repository, "/") {
		forbidden = append(forbidden, j.Config.Repository)
	}
	if j.Restore.Volume != "" {
		v, err := c.PreflightFileRestoreVolume(ctx, s, j.Restore.Volume, &w, forbidden...)
		if err != nil || v.Mountpoint != j.Restore.Directory {
			return tr
		}
	}
	pinned, e := c.PreflightFileRestoreDirectory(ctx, s, j.Restore.Directory, &w, forbidden...)
	if e != nil {
		return tr
	}
	defer pinned.Close()
	if e = pinned.Restore(ctx, repo); e != nil {
		return tr
	}
	tr.Status = "restored"
	tr.Error = ""
	return tr
}
