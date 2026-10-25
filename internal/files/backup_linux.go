package files

import (
	"context"
	"errors"
	"syscall"

	"github.com/tamntlib/bakabel/internal/backup"
)

// Backup reads one read-only mounted source directly. No tar or staging files.
// The caller owns worker lifecycle and the installation lock. Unreadable files
// and Restic exit 3 propagate through the existing exact snapshot finalizer.
func Backup(ctx context.Context, r backup.Repository, m backup.Metadata, run, installation string, forbidden []string, protected ...ProtectedIdentity) backup.Result {
	fail := func(e error) backup.Result { return backup.Result{Status: "unknown", Err: e} }
	if installation == "" || m.Kind != "volume" || len(m.Paths) != 1 || len(m.Mounts) != 1 || m.Mounts[0].SnapshotPath != WorkerPath(m.Source, m.Mounts[0].Destination) {
		return fail(errors.New("single stable volume source required"))
	}
	f, e := openDir(m.Paths[0])
	if e != nil {
		return fail(e)
	}
	defer f.Close()
	own, e := ancestors(f)
	if e != nil {
		return fail(e)
	}
	if uint64(own[0].Dev) != m.Mounts[0].Device || own[0].Ino != m.Mounts[0].Inode {
		return fail(errors.New("mounted file source identity changed"))
	}
	var fs syscall.Statfs_t
	if e = syscall.Fstatfs(int(f.Fd()), &fs); e != nil {
		return fail(e)
	}
	if fs.Flags&1 == 0 {
		return fail(errors.New("file backup source must be mounted read-only"))
	}
	backing, e := filesystemPath(f)
	if e != nil {
		return fail(e)
	}
	if backing != m.Mounts[0].FilesystemPath {
		return fail(errors.New("source backing path changed"))
	}
	for _, proof := range protected {
		if err := validateProtection(proof); err != nil {
			return fail(err)
		}
		if uint64(own[0].Dev) == proof.Device && (own[0].Ino == proof.Inode || overlaps(backing, proof.FilesystemPath)) {
			return fail(errors.New("file source overlaps protected runtime storage"))
		}
	}
	for _, p := range forbidden {
		if overlaps(m.Paths[0], p) || overlaps(m.Mounts[0].Source, p) {
			return fail(errors.New("file source overlaps repository/state"))
		}
		excluded, e := openDir(p)
		if e != nil {
			return fail(e)
		}
		otherBacking, e := filesystemPath(excluded)
		if e != nil {
			excluded.Close()
			return fail(e)
		}
		other, e := ancestors(excluded)
		excluded.Close()
		if e != nil {
			return fail(e)
		}
		if own[0].Dev == other[0].Dev && overlaps(backing, otherBacking) {
			return fail(errors.New("file source backing overlaps protected storage"))
		}
		for _, st := range own {
			if same(st, other[0]) {
				return fail(errors.New("file source nested in protected storage"))
			}
		}
		for _, st := range other {
			if same(st, own[0]) {
				return fail(errors.New("protected storage nested in file source"))
			}
		}
	}
	return r.Backup(ctx, m, run, Hostname(installation), []string{"--group-by", "host,paths", "--", m.Paths[0]})
}
