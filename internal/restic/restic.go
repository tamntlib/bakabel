// Package restic wraps the Restic CLI for repository management, backup, snapshots, restore, and retention.
package restic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/state"
)

// Snapshot describes a Bakabel snapshot returned by `restic snapshots --json`.
type Snapshot struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"short_id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Tags     []string  `json:"tags"`
	Paths    []string  `json:"paths"`
}

// TagValue extracts the value of a "key:value" tag, or "".
func (s Snapshot) TagValue(prefix string) string {
	want := prefix + ":"
	for _, t := range s.Tags {
		if strings.HasPrefix(t, want) {
			return strings.TrimPrefix(t, want)
		}
	}
	return ""
}

// HasTag reports whether snapshot s contains exact tag.
func (s Snapshot) HasTag(tag string) bool {
	for _, t := range s.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// Client invokes the restic binary with scoped environment credentials.
type Client struct {
	cfg config.Config
}

// New returns a Restic CLI client bound to cfg.
func New(cfg config.Config) *Client {
	return &Client{cfg: cfg}
}

// BuildEnv constructs the minimal environment passed to restic (and volume helper containers).
func (c *Client) BuildEnv() ([]string, error) {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"RESTIC_REPOSITORY=" + c.cfg.Repository,
		"RESTIC_CACHE_DIR=" + c.cfg.ResticCacheDir,
	}
	if c.cfg.ResticPasswordFile != "" {
		env = append(env, "RESTIC_PASSWORD_FILE="+c.cfg.ResticPasswordFile)
	} else if c.cfg.ResticPassword != "" {
		env = append(env, "RESTIC_PASSWORD="+c.cfg.ResticPassword)
	}
	awsID, err := config.ReadSecret(c.cfg.AWSAccessKeyID, c.cfg.AWSAccessKeyIDFile)
	if err != nil {
		return nil, err
	}
	awsSecret, err := config.ReadSecret(c.cfg.AWSSecretAccessKey, c.cfg.AWSSecretKeyFile)
	if err != nil {
		return nil, err
	}
	if awsID != "" {
		env = append(env, "AWS_ACCESS_KEY_ID="+awsID)
	}
	if awsSecret != "" {
		env = append(env, "AWS_SECRET_ACCESS_KEY="+awsSecret)
	}
	if c.cfg.AWSDefaultRegion != "" {
		env = append(env, "AWS_DEFAULT_REGION="+c.cfg.AWSDefaultRegion)
	}
	return env, nil
}

func (c *Client) run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, string, error) {
	env, err := c.BuildEnv()
	if err != nil {
		return nil, "", err
	}
	cmd := exec.CommandContext(ctx, c.cfg.ResticBin, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func (c *Client) catConfigID(ctx context.Context) (string, string, error) {
	out, stderr, err := c.run(ctx, nil, "cat", "config")
	if err != nil {
		return "", stderr, err
	}
	var meta struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &meta); err != nil || meta.ID == "" {
		return "", stderr, errors.New("restic repository config returned invalid ID")
	}
	return meta.ID, "", nil
}

// isMissingRepoError identifies errors strictly indicating an uninitialized repository.
func isMissingRepoError(stderr string) bool {
	low := strings.ToLower(stderr)
	if strings.Contains(low, "wrong password") || strings.Contains(low, "403") || strings.Contains(low, "access denied") || strings.Contains(low, "forbidden") {
		return false
	}
	if strings.Contains(low, "is there a repository at the following location") {
		return true
	}
	if strings.Contains(low, "unable to open config file") &&
		(strings.Contains(low, "does not exist") || strings.Contains(low, "no such file") || strings.Contains(low, "nosuchkey") || strings.Contains(low, "404")) {
		return true
	}
	return false
}

// EnsureRepo verifies the Restic repository is accessible and matches any previously recorded
// repository_id in state. When the repository does not exist yet, auto-init is enabled,
// state has no prior repository_id, and (for local paths) the directory is empty, it runs
// `restic init` automatically and pins the resulting repository_id.
func (c *Client) EnsureRepo(ctx context.Context, store *state.Store) (repoID string, initialized bool, err error) {
	if err := os.MkdirAll(c.cfg.ResticCacheDir, 0o700); err != nil {
		return "", false, fmt.Errorf("create restic cache dir: %w", err)
	}

	prev, err := store.LoadRepoMeta()
	if err != nil {
		return "", false, err
	}

	id, stderr, catErr := c.catConfigID(ctx)
	if catErr == nil {
		if prev != nil && prev.RepositoryID != "" && prev.RepositoryID != id {
			return "", false, fmt.Errorf("repository ID mismatch: state expects %s, found %s", prev.RepositoryID, id)
		}
		if prev == nil || prev.RepositoryID == "" {
			if err := store.SaveRepoMeta(state.RepoMeta{
				RepositoryID: id,
				Repository:   c.cfg.Repository,
				RecordedAt:   time.Now().UTC(),
			}); err != nil {
				return "", false, err
			}
		}
		return id, false, nil
	}

	if !isMissingRepoError(stderr) {
		return "", false, fmt.Errorf("access restic repository: %s", sanitizeError(stderr, catErr))
	}
	if !c.cfg.AutoInit {
		return "", false, errors.New("restic repository is not initialized (set BAKABEL_AUTO_INIT=true or run `restic init`)")
	}
	if prev != nil && prev.RepositoryID != "" {
		return "", false, fmt.Errorf("refusing to auto-initialize: state already pins repository_id %s (check mount or bucket)", prev.RepositoryID)
	}

	if c.cfg.IsLocalRepo() {
		entries, readErr := os.ReadDir(c.cfg.Repository)
		if errors.Is(readErr, os.ErrNotExist) {
			if err := os.MkdirAll(c.cfg.Repository, 0o700); err != nil {
				return "", false, fmt.Errorf("create local repository dir: %w", err)
			}
		} else if readErr != nil {
			return "", false, fmt.Errorf("inspect local repository dir: %w", readErr)
		} else if len(entries) > 0 {
			return "", false, fmt.Errorf("refusing to auto-initialize non-empty directory %s", c.cfg.Repository)
		}
	}

	if _, initStderr, initErr := c.run(ctx, nil, "init"); initErr != nil {
		return "", false, fmt.Errorf("restic init failed: %s", sanitizeError(initStderr, initErr))
	}
	id, stderr, catErr = c.catConfigID(ctx)
	if catErr != nil {
		return "", false, fmt.Errorf("verify initialized repository: %s", sanitizeError(stderr, catErr))
	}
	if err := store.SaveRepoMeta(state.RepoMeta{
		RepositoryID: id,
		Repository:   c.cfg.Repository,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		return "", false, err
	}
	return id, true, nil
}

// BackupStdin streams stdin into a new Restic snapshot and returns its snapshot ID.
func (c *Client) BackupStdin(ctx context.Context, filename, host string, tags []string, stdin io.Reader) (string, error) {
	args := []string{
		"backup", "--json",
		"--stdin", "--stdin-filename", filename,
		"--host", host,
	}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	out, stderr, err := c.run(ctx, stdin, args...)
	if err != nil {
		return "", fmt.Errorf("restic backup stdin failed: %s", sanitizeError(stderr, err))
	}
	snapID := parseBackupSnapshotID(out)
	if snapID == "" {
		return "", errors.New("restic backup succeeded without returning snapshot_id")
	}
	return snapID, nil
}

// BackupDir backs up a local directory into a new Restic snapshot and returns its snapshot ID.
func (c *Client) BackupDir(ctx context.Context, dir, host string, tags []string) (string, error) {
	if err := os.MkdirAll(c.cfg.ResticCacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create restic cache dir: %w", err)
	}
	args := []string{
		"backup", "--json",
		"--host", host,
	}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	args = append(args, dir)
	out, stderr, err := c.run(ctx, nil, args...)
	if err != nil {
		return "", fmt.Errorf("restic backup failed: %s", sanitizeError(stderr, err))
	}
	snapID := parseBackupSnapshotID(out)
	if snapID == "" {
		return "", errors.New("restic backup succeeded without returning snapshot_id")
	}
	return snapID, nil
}

// Snapshots lists all Bakabel-tagged snapshots in the repository.
func (c *Client) Snapshots(ctx context.Context) ([]Snapshot, error) {
	out, stderr, err := c.run(ctx, nil, "snapshots", "--json", "--tag", "bakabel")
	if err != nil {
		return nil, fmt.Errorf("restic snapshots failed: %s", sanitizeError(stderr, err))
	}
	if len(bytes.TrimSpace(out)) == 0 || string(bytes.TrimSpace(out)) == "null" {
		return []Snapshot{}, nil
	}
	var snaps []Snapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("decode restic snapshots: %w", err)
	}
	return snaps, nil
}

// DumpStream streams a single file out of snapshotID using `restic dump`.
type DumpStream struct {
	Reader io.ReadCloser
	cmd    *exec.Cmd
	stderr bytes.Buffer
}

// Wait waits for the `restic dump` process to exit.
func (d *DumpStream) Wait() error {
	err := d.cmd.Wait()
	if err != nil {
		return fmt.Errorf("restic dump failed: %s", sanitizeError(strings.TrimSpace(d.stderr.String()), err))
	}
	return nil
}

// Dump opens a streaming `restic dump <snapshotID> <filePath>`.
func (c *Client) Dump(ctx context.Context, snapshotID, filePath string) (*DumpStream, error) {
	env, err := c.BuildEnv()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.cfg.ResticBin, "dump", snapshotID, filePath)
	cmd.Env = env
	ds := &DumpStream{cmd: cmd}
	cmd.Stderr = &ds.stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start restic dump: %w", err)
	}
	ds.Reader = stdout
	return ds, nil
}

// RestoreDir restores a backed-up subpath of snapshotID into targetDir.
func (c *Client) RestoreDir(ctx context.Context, snapshotID, subpath, targetDir string) error {
	if err := os.MkdirAll(c.cfg.ResticCacheDir, 0o700); err != nil {
		return fmt.Errorf("create restic cache dir: %w", err)
	}
	ref := snapshotID
	if subpath != "" {
		ref = snapshotID + ":" + strings.TrimPrefix(subpath, "/")
	}
	_, stderr, err := c.run(ctx, nil, "restore", ref, "--target", targetDir)
	if err != nil {
		return fmt.Errorf("restic restore failed: %s", sanitizeError(stderr, err))
	}
	return nil
}

// ForgetPrune applies the configured retention policy to Bakabel snapshots.
func (c *Client) ForgetPrune(ctx context.Context, ret config.Retention) error {
	if !ret.Enabled() {
		return nil
	}
	args := []string{"forget", "--prune", "--group-by", "host,tags", "--tag", "bakabel"}
	if ret.Last > 0 {
		args = append(args, "--keep-last", strconv.Itoa(ret.Last))
	}
	if ret.Hourly > 0 {
		args = append(args, "--keep-hourly", strconv.Itoa(ret.Hourly))
	}
	if ret.Daily > 0 {
		args = append(args, "--keep-daily", strconv.Itoa(ret.Daily))
	}
	if ret.Weekly > 0 {
		args = append(args, "--keep-weekly", strconv.Itoa(ret.Weekly))
	}
	if ret.Monthly > 0 {
		args = append(args, "--keep-monthly", strconv.Itoa(ret.Monthly))
	}
	if ret.Yearly > 0 {
		args = append(args, "--keep-yearly", strconv.Itoa(ret.Yearly))
	}
	_, stderr, err := c.run(ctx, nil, args...)
	if err != nil {
		return fmt.Errorf("restic forget/prune failed: %s", sanitizeError(stderr, err))
	}
	return nil
}

func parseBackupSnapshotID(out []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var snapID string
	for scanner.Scan() {
		var msg struct {
			MessageType string `json:"message_type"`
			SnapshotID  string `json:"snapshot_id"`
		}
		if json.Unmarshal(scanner.Bytes(), &msg) == nil && msg.MessageType == "summary" && msg.SnapshotID != "" {
			snapID = msg.SnapshotID
		}
	}
	return snapID
}

func sanitizeError(stderr string, fallback error) string {
	if stderr != "" {
		lines := strings.Split(stderr, "\n")
		msg := strings.TrimSpace(lines[len(lines)-1])
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg != "" {
			return msg
		}
	}
	if fallback != nil {
		return fallback.Error()
	}
	return "unknown error"
}
