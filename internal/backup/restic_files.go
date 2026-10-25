package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
)

// RestoreFiles is the low-level transport; callers MUST first enforce physical
// identity/exclusions and hold an empty destination open (files.OpenRestore).
// Restic 0.18.1 supports ID:subfolder, flattening exactly the one source root.
// ExtraFiles makes fd 3 survive exec. Bare /proc/self/fd/3 is NOT supported as
// the restore root by 0.18.1 (it tries to unlink that symlink). The files package
// creates a real .bakabel-restore child beneath the descriptor, then flattens
// with renameat. That moves directory entries, not a copied/staged data stream.
func (r Repository) RestoreFiles(ctx context.Context, s Snapshot, target *os.File) error {
	m, e := s.Restorable()
	if e != nil {
		return e
	}
	if m.Kind != "volume" || len(m.Paths) != 1 || len(m.Mounts) != 1 || target == nil {
		return errors.New("single file source and opened destination required")
	}
	info, e := target.Stat()
	if e != nil || !info.IsDir() {
		return errors.New("opened destination directory required")
	}
	snapshots, e := r.Snapshots(ctx)
	if e != nil {
		return e
	}
	found := false
	for _, actual := range snapshots {
		if actual.ID == s.ID {
			if !reflect.DeepEqual(actual, s) {
				return errors.New("snapshot changed since preflight")
			}
			found = true
		}
	}
	if !found {
		return errors.New("exact snapshot no longer present")
	}
	cmd := exec.CommandContext(ctx, r.Binary, "--no-cache", "restore", s.ID+":"+m.Paths[0], "--target", "/proc/self/fd/3/.bakabel-restore", "--verify", "--overwrite", "never")
	cmd.Env = r.Env
	cmd.ExtraFiles = []*os.File{target}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("restic file restore failed")
	}
	return nil
}
