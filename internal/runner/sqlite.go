package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/tamntlib/bakabel/internal/docker"
	"github.com/tamntlib/bakabel/internal/restic"
)

const sqliteHeaderMagic = "SQLite format 3\x00"

func (r *Runner) backupSqlite(ctx context.Context, dc *docker.Client, self *docker.Container, t docker.Target) (string, error) {
	image := r.resolveWorkerImage(self)
	if image == "" {
		return "", errors.New("cannot determine helper image for sqlite backup; set BAKABEL_WORKER_IMAGE")
	}

	mounts, err := r.buildHelperMounts(self)
	if err != nil {
		return "", err
	}
	// SQLite WAL readers need read-write mount access to map -shm; sqlite3 itself runs
	// with PRAGMA query_only=ON and drops to the DB file owner UID:GID so source ownership
	// and contents are never modified.
	mounts = append(mounts, docker.HelperMount{
		Type:     "volume",
		Source:   t.VolumeName,
		Target:   "/sqlite-src",
		ReadOnly: false,
	})

	env, err := r.helperEnv()
	if err != nil {
		return "", err
	}

	cmd := []string{
		"_sqlite-backup",
		"--target-id", t.ID,
		"--stack", t.Stack,
		"--service", t.Service,
		"--volume", t.VolumeName,
		"--mount-path", t.MountPath,
		"--db-path", t.DBPath,
	}

	res, err := dc.RunHelper(ctx, docker.HelperSpec{
		Image:       image,
		Cmd:         cmd,
		Env:         env,
		Mounts:      mounts,
		NetworkMode: r.resolveWorkerNetwork(ctx, dc, self),
		Labels:      map[string]string{"bakabel.role": "sqlite-helper"},
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		return "", fmt.Errorf("sqlite helper exited %d: %s", res.ExitCode, msg)
	}
	var out struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil || out.SnapshotID == "" {
		return "", fmt.Errorf("sqlite helper returned invalid output: %s", res.Stdout)
	}

	// Verify source container stayed running during backup.
	after, err := dc.InspectContainer(ctx, t.ContainerID)
	if err != nil || !after.State.Running || after.State.StartedAt != t.ContainerStartedAt {
		return "", errors.New("source container restarted or disappeared during sqlite backup")
	}
	return out.SnapshotID, nil
}

// RunSqliteBackupInternal runs inside the ephemeral helper container to create an online SQLite
// snapshot from /sqlite-src/<dbPath>, verify integrity_check, and back it up with Restic.
func (r *Runner) RunSqliteBackupInternal(ctx context.Context, targetID, stack, service, volumeName, mountPath, dbPath string) (string, error) {
	t := docker.Target{
		ID:         targetID,
		Type:       "sqlite",
		Stack:      stack,
		Service:    service,
		VolumeName: volumeName,
		MountPath:  mountPath,
		DBPath:     dbPath,
	}
	return r.backupSqliteFile(ctx, "/sqlite-src", t)
}

func (r *Runner) backupSqliteFile(ctx context.Context, srcRoot string, t docker.Target) (string, error) {
	rel, srcPath, err := resolveSafeSubpath(srcRoot, t.DBPath)
	if err != nil {
		return "", err
	}
	t.DBPath = rel

	info, err := os.Lstat(srcPath)
	if err != nil {
		return "", fmt.Errorf("stat sqlite database %s: %w", rel, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("sqlite path %s is not a regular file", rel)
	}
	if err := checkSqliteHeader(srcPath); err != nil {
		return "", fmt.Errorf("validate source sqlite database %s: %w", rel, err)
	}

	var uid, gid uint32
	hasOwner := false
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		uid = st.Uid
		gid = st.Gid
		hasOwner = true
	}

	tmpDir, err := os.MkdirTemp("", "bakabel-sqlite-*")
	if err != nil {
		return "", fmt.Errorf("create sqlite staging dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dropPrivs := hasOwner && os.Geteuid() == 0 && (uid != 0 || gid != 0)
	if dropPrivs {
		if err := os.Chown(tmpDir, int(uid), int(gid)); err != nil {
			return "", fmt.Errorf("chown sqlite staging dir: %w", err)
		}
	}

	snapPath := filepath.Join(tmpDir, "snapshot.db")
	if strings.ContainsAny(snapPath, "'\"\r\n\x00") {
		return "", errors.New("unsafe characters in sqlite snapshot path")
	}

	backupCmd := exec.CommandContext(ctx, r.sqliteBin(),
		"-bail",
		"-cmd", "PRAGMA busy_timeout=30000;",
		"-cmd", "PRAGMA query_only=ON;",
		srcPath,
		fmt.Sprintf(".backup '%s'", snapPath),
	)
	if dropPrivs {
		backupCmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid},
		}
	}
	if out, err := backupCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("sqlite3 .backup failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Clear WAL header flag on the standalone temporary copy so the backed-up database
	// is portable and readable even on read-only mounts without needing -shm.
	normCmd := exec.CommandContext(ctx, r.sqliteBin(), "-bail", snapPath, "PRAGMA journal_mode=DELETE;")
	if out, err := normCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("normalize sqlite snapshot journal mode: %w: %s", err, strings.TrimSpace(string(out)))
	}

	if err := r.verifySqliteFile(ctx, snapPath); err != nil {
		return "", fmt.Errorf("verify sqlite snapshot: %w", err)
	}

	f, err := os.Open(snapPath)
	if err != nil {
		return "", fmt.Errorf("open sqlite snapshot: %w", err)
	}
	defer f.Close()

	tags := targetTags(t)
	if hasOwner {
		tags = append(tags, fmt.Sprintf("owner:%d:%d", uid, gid))
	}
	return r.Restic.BackupStdin(ctx, filepath.Base(rel), r.Cfg.Installation, tags, f)
}

func (r *Runner) restoreSqlite(ctx context.Context, dc *docker.Client, snap restic.Snapshot, opts RestoreOptions) error {
	if opts.Volume == "" {
		return errors.New("--volume is required for sqlite restore")
	}
	if len(snap.Paths) != 1 {
		return fmt.Errorf("unexpected snapshot paths for sqlite snapshot %s", snap.ShortID)
	}
	vol, err := dc.InspectVolume(ctx, opts.Volume)
	if err != nil {
		return fmt.Errorf("inspect target volume %q: %w", opts.Volume, err)
	}
	if vol.Driver != "local" || len(vol.Options) > 0 {
		return fmt.Errorf("target volume %q uses unsupported driver/options", opts.Volume)
	}

	self, _ := dc.SelfContainer(ctx)
	image := r.resolveWorkerImage(self)
	if image == "" {
		return errors.New("cannot determine helper image for sqlite restore; set BAKABEL_WORKER_IMAGE")
	}

	mounts, err := r.buildHelperMounts(self)
	if err != nil {
		return err
	}
	mounts = append(mounts, docker.HelperMount{
		Type:     "volume",
		Source:   opts.Volume,
		Target:   "/restore-dst",
		ReadOnly: false,
	})

	env, err := r.helperEnv()
	if err != nil {
		return err
	}

	dbPath := snap.TagValue("db")
	if dbPath == "" {
		dbPath = filepath.Base(snap.Paths[0])
	}
	cmd := []string{
		"_sqlite-restore",
		"--snapshot", snap.ID,
		"--snap-path", snap.Paths[0],
		"--db-path", dbPath,
	}
	if owner := snap.TagValue("owner"); owner != "" {
		cmd = append(cmd, "--owner", owner)
	}

	res, err := dc.RunHelper(ctx, docker.HelperSpec{
		Image:       image,
		Cmd:         cmd,
		Env:         env,
		Mounts:      mounts,
		NetworkMode: r.resolveWorkerNetwork(ctx, dc, self),
		Labels:      map[string]string{"bakabel.role": "sqlite-helper"},
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		return fmt.Errorf("sqlite restore helper exited %d: %s", res.ExitCode, msg)
	}
	return nil
}

// RunSqliteRestoreInternal runs inside the ephemeral helper container to restore a verified SQLite
// snapshot into an empty /restore-dst volume.
func (r *Runner) RunSqliteRestoreInternal(ctx context.Context, snapshotID, snapPath, dbPath, owner string) error {
	return r.restoreSqliteFile(ctx, "/restore-dst", snapshotID, snapPath, dbPath, owner)
}

func (r *Runner) restoreSqliteFile(ctx context.Context, dstRoot, snapshotID, snapPath, dbPath, owner string) error {
	entries, err := os.ReadDir(dstRoot)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", dstRoot, err)
	}
	if len(entries) > 0 {
		return errors.New("refusing sqlite restore: target volume is not empty")
	}

	rel, dstPath, err := resolveSafeSubpath(dstRoot, dbPath)
	if err != nil {
		return err
	}
	parentDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return fmt.Errorf("create target directory for %s: %w", rel, err)
	}

	dump, err := r.Restic.Dump(ctx, snapshotID, snapPath)
	if err != nil {
		return err
	}
	defer dump.Reader.Close()

	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create restored sqlite file %s: %w", rel, err)
	}
	_, copyErr := io.Copy(out, dump.Reader)
	syncErr := out.Sync()
	closeErr := out.Close()
	dumpErr := dump.Wait()

	if err := firstError(dumpErr, copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(dstPath)
		return fmt.Errorf("restore sqlite file %s: %w", rel, err)
	}

	if err := r.verifySqliteFile(ctx, dstPath); err != nil {
		_ = os.Remove(dstPath)
		return fmt.Errorf("verify restored sqlite file %s: %w", rel, err)
	}

	if uid, gid, ok := parseOwnerTag(owner); ok && os.Geteuid() == 0 {
		_ = os.Chown(dstPath, uid, gid)
		for dir := parentDir; dir != filepath.Clean(dstRoot) && strings.HasPrefix(dir, filepath.Clean(dstRoot)+string(filepath.Separator)); dir = filepath.Dir(dir) {
			_ = os.Chown(dir, uid, gid)
		}
	}
	return nil
}

func (r *Runner) sqliteBin() string {
	if r.Cfg.SqliteBin != "" {
		return r.Cfg.SqliteBin
	}
	return "sqlite3"
}

func (r *Runner) verifySqliteFile(ctx context.Context, path string) error {
	if err := checkSqliteHeader(path); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, r.sqliteBin(), "-bail", path, "PRAGMA integrity_check;")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sqlite3 integrity_check failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if got := strings.TrimSpace(stdout.String()); got != "ok" {
		return fmt.Errorf("sqlite3 integrity_check returned %q", got)
	}
	return nil
}

func checkSqliteHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var hdr [16]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return fmt.Errorf("read sqlite header: %w", err)
	}
	if string(hdr[:]) != sqliteHeaderMagic {
		return errors.New("file does not have a valid SQLite 3 header")
	}
	return nil
}

func resolveSafeSubpath(root, relPath string) (string, string, error) {
	rel := filepath.Clean(strings.TrimSpace(relPath))
	if rel == "" || rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("invalid relative sqlite path %q", relPath)
	}
	cleanRoot := filepath.Clean(root)
	full := filepath.Join(cleanRoot, rel)
	if !strings.HasPrefix(full, cleanRoot+string(filepath.Separator)) {
		return "", "", fmt.Errorf("sqlite path %q escapes mount root", relPath)
	}
	return rel, full, nil
}

func parseOwnerTag(raw string) (int, int, bool) {
	if raw == "" {
		return 0, 0, false
	}
	uStr, gStr, ok := strings.Cut(raw, ":")
	if !ok {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(uStr)
	gid, err2 := strconv.Atoi(gStr)
	if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
