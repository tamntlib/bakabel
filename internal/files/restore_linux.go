package files

import (
	"context"
	"errors"
	"github.com/tamntlib/bakabel/internal/backup"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// RestoreTarget owns an opened destination for the lifetime of Restic. Close
// after restore finishes. Never substitute the original pathname when writing.
type RestoreTarget struct {
	File     *os.File
	Snapshot backup.Snapshot
}

func (t *RestoreTarget) Close() error { return t.File.Close() }

// Restore rechecks emptiness and uses only the pinned descriptor, never Name().
// The installation lock and operator-exclusive target must remain held; this is
// not isolation against a privileged concurrent writer or mount administrator.
func (t *RestoreTarget) Restore(ctx context.Context, r backup.Repository) error {
	if _, e := t.File.Seek(0, 0); e != nil {
		return e
	}
	entries, e := t.File.Readdirnames(1)
	if e != io.EOF || len(entries) != 0 {
		return errors.New("destination changed after preflight")
	}
	// Restic 0.18.1 rejects a proc-fd symlink as the restore ROOT. Use a real
	// child beneath the pinned descriptor, then promote it using renameat; there is
	// no additional data copy or extra filesystem. Failure leaves partial output.
	child := ".bakabel-restore"
	if e = syscall.Mkdirat(int(t.File.Fd()), child, 0700); e != nil {
		return e
	}
	if e = r.RestoreFiles(ctx, t.Snapshot, t.File); e != nil {
		return e
	}
	containerFD, e := syscall.Openat(int(t.File.Fd()), child, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer syscall.Close(containerFD)
	// Restore the source as a directory node, not as Restic's metadata-free
	// target root. Both levels stay pinned even if their pathnames are moved.
	rootName := filepath.Base(t.Snapshot.Paths[0])
	fd, e := syscall.Openat(containerFD, rootName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	staged := os.NewFile(uintptr(fd), rootName)
	defer staged.Close()
	names, e := staged.Readdirnames(-1)
	if e != nil {
		return e
	}
	namesSet := map[string]bool{}
	for _, name := range names {
		namesSet[name] = true
	}
	if namesSet[child] {
		replacement := ""
		for i := 0; i <= len(names); i++ {
			candidate := ".bakabel-restore-work-" + strconv.Itoa(i)
			if !namesSet[candidate] {
				replacement = candidate
				break
			}
		}
		if e = syscall.Renameat(int(t.File.Fd()), child, int(t.File.Fd()), replacement); e != nil {
			return e
		}
		child = replacement
	}
	var st syscall.Stat_t
	if e = syscall.Fstat(fd, &st); e != nil {
		return e
	}
	acls, e := readRootACLs(fd)
	if e != nil {
		return e
	}
	for _, name := range names {
		if e = syscall.Renameat(fd, name, int(t.File.Fd()), name); e != nil {
			return e
		}
	}
	if e = os.Remove("/proc/self/fd/" + strconv.Itoa(containerFD) + "/" + rootName); e != nil {
		return e
	}
	if e = os.Remove("/proc/self/fd/" + strconv.FormatUint(uint64(t.File.Fd()), 10) + "/" + child); e != nil {
		return e
	}
	// chown may clear special mode bits; chmod changes an access ACL's mask.
	// Apply the exact ACLs last, including removal of stale destination ACLs.
	if e = syscall.Fchown(int(t.File.Fd()), int(st.Uid), int(st.Gid)); e != nil {
		return e
	}
	if e = syscall.Fchmod(int(t.File.Fd()), st.Mode&07777); e != nil {
		return e
	}
	if e = acls.apply(int(t.File.Fd())); e != nil {
		return e
	}
	return t.File.Sync()
}

// OpenRestore accepts an explicitly existing empty operator-created directory.
// forbidden must include the local repository and state roots accessible here.
func OpenRestore(s backup.Snapshot, destination string, forbidden []string) (*RestoreTarget, error) {
	m, e := s.Restorable()
	if e != nil {
		return nil, e
	}
	if m.Kind != "volume" || len(m.Paths) != 1 || len(m.Mounts) != 1 || m.Mounts[0].Type != "volume" || m.Mounts[0].Name == "" || m.Mounts[0].SnapshotPath != WorkerPath(m.Source, m.Mounts[0].Destination) {
		return nil, errors.New("unsupported single-volume layout")
	}
	f, e := openDir(destination)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*RestoreTarget, error) { f.Close(); return nil, err }
	if e = requireLocal(f); e != nil {
		return fail(e)
	}
	ancestry, e := ancestors(f)
	if e != nil {
		return fail(e)
	}
	mount := m.Mounts[0]
	if mount.FilesystemPath != "/" && !cleanPath(mount.FilesystemPath) {
		return fail(errors.New("missing resolved filesystem backing path"))
	}
	backing, e := filesystemPath(f)
	if e != nil {
		return fail(e)
	}
	if uint64(ancestry[0].Dev) == mount.Device && overlaps(backing, mount.FilesystemPath) {
		return fail(errors.New("destination filesystem backing overlaps snapshot source"))
	}
	for _, st := range ancestry {
		if uint64(st.Dev) == mount.Device && st.Ino == mount.Inode {
			return fail(errors.New("destination aliases or is inside snapshot source"))
		}
	}
	// Paths remain useful after the source has disappeared; physical identities
	// additionally catch bind aliases whose pathname bears no resemblance.
	paths := append([]string{mount.Source, mount.SnapshotPath}, forbidden...)
	for i, p := range paths {
		if !cleanPath(p) {
			return fail(errors.New("invalid exclusion directory"))
		}
		if overlaps(destination, p) {
			return fail(errors.New("destination overlaps protected directory"))
		}
		protected, err := openDir(p)
		if err != nil {
			if i < 2 && errors.Is(err, syscall.ENOENT) {
				continue
			}
			return fail(errors.New("cannot verify protected directory"))
		}
		otherBacking, err := filesystemPath(protected)
		if err != nil {
			protected.Close()
			return fail(err)
		}
		other, err := ancestors(protected)
		protected.Close()
		if err != nil {
			return fail(err)
		}
		if ancestry[0].Dev == other[0].Dev && overlaps(backing, otherBacking) {
			return fail(errors.New("destination backing overlaps protected storage"))
		}
		if same(ancestry[0], other[0]) {
			return fail(errors.New("physical directory alias"))
		}
		for _, st := range ancestry {
			if same(st, other[0]) {
				return fail(errors.New("destination nested in protected directory"))
			}
		}
		for _, st := range other {
			if same(st, ancestry[0]) {
				return fail(errors.New("protected directory nested in destination"))
			}
		}
	}
	if os.Geteuid() != 0 && uint32(os.Geteuid()) != ancestry[0].Uid {
		return fail(errors.New("destination must be owned by restore user"))
	}
	entries, e := f.Readdirnames(1)
	if e != io.EOF || len(entries) != 0 {
		return fail(errors.New("restore target must be empty"))
	}
	return &RestoreTarget{File: f, Snapshot: s}, nil
}
func overlaps(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	return a == b || a == "/" || b == "/" || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func same(a, b syscall.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func ancestors(f *os.File) ([]syscall.Stat_t, error) {
	fd, e := syscall.Dup(int(f.Fd()))
	if e != nil {
		return nil, e
	}
	defer func() { syscall.Close(fd) }()
	var all []syscall.Stat_t
	for i := 0; i < 4096; i++ {
		var st syscall.Stat_t
		if e = syscall.Fstat(fd, &st); e != nil {
			return nil, e
		}
		if len(all) > 0 && same(all[len(all)-1], st) {
			return all, nil
		}
		all = append(all, st)
		next, err := syscall.Openat(fd, "..", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		syscall.Close(fd)
		fd = next
	}
	return nil, errors.New("directory ancestry exceeds safety bound")
}
