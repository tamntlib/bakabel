// Package runner orchestrates Bakabel plan, run, serve, snapshots, restore, and health workflows.
package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/docker"
	"github.com/tamntlib/bakabel/internal/notify"
	"github.com/tamntlib/bakabel/internal/restic"
	"github.com/tamntlib/bakabel/internal/state"
)

// Runner wires config, Docker, Restic, state, and notifications.
type Runner struct {
	Cfg    config.Config
	Store  *state.Store
	Restic *restic.Client
	Log    *log.Logger
}

// New constructs a Runner for cfg.
func New(cfg config.Config, logger *log.Logger) *Runner {
	if logger == nil {
		logger = log.New(os.Stderr, "bakabel: ", log.LstdFlags|log.LUTC)
	}
	return &Runner{
		Cfg:    cfg,
		Store:  state.New(cfg.StateDir),
		Restic: restic.New(cfg),
		Log:    logger,
	}
}

func (r *Runner) dockerClient() (*docker.Client, error) {
	return docker.NewClient(r.Cfg.DockerSocket)
}

// Plan performs read-only label discovery.
func (r *Runner) Plan(ctx context.Context) (docker.DiscoverResult, error) {
	if err := r.Cfg.ValidateDiscovery(); err != nil {
		return docker.DiscoverResult{}, err
	}
	dc, err := r.dockerClient()
	if err != nil {
		return docker.DiscoverResult{}, err
	}
	defer dc.Close()
	return docker.Discover(ctx, dc, docker.DiscoverOptions{
		Platform: r.Cfg.Platform,
		Scope:    r.Cfg.Scope,
	})
}

// Run executes one complete backup cycle across all discovered targets.
func (r *Runner) Run(ctx context.Context) (state.RunResult, error) {
	started := time.Now().UTC()
	res := state.RunResult{
		Operation: "run",
		StartedAt: started,
		Status:    "failed",
	}

	if err := r.Cfg.ValidateDiscovery(); err != nil {
		return res, err
	}
	if err := r.Cfg.ValidateRepo(); err != nil {
		return res, err
	}

	lock, err := r.Store.AcquireLock()
	if err != nil {
		return res, err
	}
	defer lock.Release()

	runCtx, cancel := context.WithTimeout(ctx, r.Cfg.Timeout)
	defer cancel()

	finish := func(runErr error) (state.RunResult, error) {
		res.FinishedAt = time.Now().UTC()
		if runErr == nil {
			res.Status = "ok"
		} else {
			res.Status = "failed"
			res.Error = runErr.Error()
		}
		if saveErr := r.Store.SaveLastResult(res); saveErr != nil {
			r.Log.Printf("warning: failed to persist last-result.json: %v", saveErr)
		}
		if runErr != nil {
			if url, uErr := r.Cfg.ResolveWebhookURL(); uErr == nil && url != "" {
				if nErr := notify.SendFailure(context.Background(), url, notify.FailurePayload{
					Installation: r.Cfg.Installation,
					Status:       res.Status,
					Error:        res.Error,
					FinishedAt:   res.FinishedAt,
				}); nErr != nil {
					r.Log.Printf("warning: webhook notification failed: %v", nErr)
				}
			}
		}
		return res, runErr
	}

	repoID, inited, err := r.Restic.EnsureRepo(runCtx, r.Store)
	if err != nil {
		return finish(err)
	}
	if inited {
		r.Log.Printf("initialized new restic repository (id=%s)", repoID[:min(12, len(repoID))])
	}

	dc, err := r.dockerClient()
	if err != nil {
		return finish(err)
	}
	defer dc.Close()

	disc, err := docker.Discover(runCtx, dc, docker.DiscoverOptions{
		Platform: r.Cfg.Platform,
		Scope:    r.Cfg.Scope,
	})
	if err != nil {
		return finish(err)
	}
	if len(disc.Targets) == 0 {
		return finish(errors.New("no backup targets discovered; add bakabel.type labels to services"))
	}

	self, _ := dc.SelfContainer(runCtx)
	var failed []string

	for _, target := range disc.Targets {
		r.Log.Printf("backing up %s (%s)", target.ID, target.Type)
		var snapID string
		var tErr error
		switch target.Type {
		case "postgres":
			snapID, tErr = r.backupPostgres(runCtx, dc, target)
		case "volume":
			snapID, tErr = r.backupVolume(runCtx, dc, self, target)
		default:
			tErr = fmt.Errorf("unsupported target type %q", target.Type)
		}
		if tErr != nil {
			r.Log.Printf("target %s failed: %v", target.ID, tErr)
			res.Targets = append(res.Targets, state.TargetResult{
				ID:     target.ID,
				Type:   target.Type,
				Status: "error",
				Error:  tErr.Error(),
			})
			failed = append(failed, fmt.Sprintf("%s: %v", target.ID, tErr))
		} else {
			r.Log.Printf("target %s complete (snapshot=%s)", target.ID, snapID[:min(12, len(snapID))])
			res.Targets = append(res.Targets, state.TargetResult{
				ID:         target.ID,
				Type:       target.Type,
				SnapshotID: snapID,
				Status:     "ok",
			})
		}
	}

	if len(failed) > 0 {
		return finish(fmt.Errorf("%d/%d target(s) failed: %s", len(failed), len(disc.Targets), strings.Join(failed, "; ")))
	}

	if r.Cfg.Retention.Enabled() {
		r.Log.Printf("applying retention policy")
		if err := r.Restic.ForgetPrune(runCtx, r.Cfg.Retention); err != nil {
			return finish(err)
		}
	}

	return finish(nil)
}

func (r *Runner) backupPostgres(ctx context.Context, dc *docker.Client, t docker.Target) (string, error) {
	runID := randomHex(16)
	tags := targetTags(t)

	pr, pw := io.Pipe()
	dumpStream := docker.NewDumpStream(pw, runID)
	resticCtx, cancelRestic := context.WithCancel(ctx)
	defer cancelRestic()

	var execEnv []string
	if t.DBPassword != "" {
		execEnv = []string{"PGPASSWORD=" + t.DBPassword}
	}
	script := `set -eu; pg_dump --format=custom --no-password -U "$1" -d "$2"; printf '\000BAKABEL_DONE:%s\000' "$3"`

	var stderrBuf bytes.Buffer
	execDone := make(chan error, 1)
	go func() {
		code, err := dc.StreamExecOut(ctx, t.ContainerID, docker.ExecOptions{
			User: "0:0",
			Cmd:  []string{"sh", "-c", script, "--", t.DBUser, t.Database, runID},
			Env:  execEnv,
		}, dumpStream, &stderrBuf)
		if err == nil && code != 0 {
			err = fmt.Errorf("pg_dump exited with code %d: %s", code, strings.TrimSpace(stderrBuf.String()))
		}
		if err == nil {
			err = dumpStream.Finish()
		}
		if err != nil {
			cancelRestic()
		}
		_ = pw.CloseWithError(err)
		execDone <- err
	}()

	snapID, resticErr := r.Restic.BackupStdin(resticCtx, t.Database+".dump", r.Cfg.Installation, tags, pr)
	_ = pr.Close()
	execErr := <-execDone

	if execErr != nil {
		return "", execErr
	}
	if resticErr != nil {
		return "", resticErr
	}

	// Verify source container did not restart mid-dump.
	after, err := dc.InspectContainer(ctx, t.ContainerID)
	if err != nil || !after.State.Running || after.State.StartedAt != t.ContainerStartedAt {
		return "", errors.New("source container restarted or disappeared during pg_dump")
	}
	return snapID, nil
}

func (r *Runner) backupVolume(ctx context.Context, dc *docker.Client, self *docker.Container, t docker.Target) (string, error) {
	image := r.resolveWorkerImage(self)
	if image == "" {
		return "", errors.New("cannot determine helper image for volume backup; set BAKABEL_WORKER_IMAGE")
	}

	mounts, err := r.buildHelperMounts(self)
	if err != nil {
		return "", err
	}
	mounts = append(mounts, docker.HelperMount{
		Type:     "volume",
		Source:   t.VolumeName,
		Target:   "/backup-src",
		ReadOnly: true,
	})

	env, err := r.helperEnv()
	if err != nil {
		return "", err
	}

	cmd := []string{
		"_volume-backup",
		"--target-id", t.ID,
		"--stack", t.Stack,
		"--service", t.Service,
		"--volume", t.VolumeName,
		"--mount-path", t.MountPath,
	}

	res, err := dc.RunHelper(ctx, docker.HelperSpec{
		Image:       image,
		Cmd:         cmd,
		Env:         env,
		Mounts:      mounts,
		NetworkMode: r.resolveWorkerNetwork(ctx, dc, self),
		Labels:      map[string]string{"bakabel.role": "volume-helper"},
	})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		return "", fmt.Errorf("volume helper exited %d: %s", res.ExitCode, msg)
	}
	var out struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil || out.SnapshotID == "" {
		return "", fmt.Errorf("volume helper returned invalid output: %s", res.Stdout)
	}
	return out.SnapshotID, nil
}

// RunVolumeBackupInternal runs inside the ephemeral helper container to back up /backup-src.
func (r *Runner) RunVolumeBackupInternal(ctx context.Context, targetID, stack, service, volumeName, mountPath string) (string, error) {
	if _, err := os.Stat(filepath.Join("/backup-src", "PG_VERSION")); err == nil {
		return "", errors.New("refusing volume backup of PostgreSQL PGDATA directory; use bakabel.type=postgres instead")
	}
	t := docker.Target{
		ID:         targetID,
		Type:       "volume",
		Stack:      stack,
		Service:    service,
		VolumeName: volumeName,
		MountPath:  mountPath,
	}
	return r.Restic.BackupDir(ctx, "/backup-src", r.Cfg.Installation, targetTags(t))
}

// RunVolumeRestoreInternal runs inside the ephemeral helper container to restore into empty /restore-dst.
func (r *Runner) RunVolumeRestoreInternal(ctx context.Context, snapshotID string) error {
	entries, err := os.ReadDir("/restore-dst")
	if err != nil {
		return fmt.Errorf("inspect /restore-dst: %w", err)
	}
	if len(entries) > 0 {
		return errors.New("refusing volume restore: target volume is not empty")
	}
	return r.Restic.RestoreDir(ctx, snapshotID, "backup-src", "/restore-dst")
}

// Serve runs scheduled backups until ctx is cancelled.
func (r *Runner) Serve(ctx context.Context) error {
	if err := r.Cfg.ValidateDiscovery(); err != nil {
		return err
	}
	if err := r.Cfg.ValidateRepo(); err != nil {
		return err
	}
	sched, loc, err := r.Cfg.ValidateSchedule()
	if err != nil {
		return err
	}

	c := cron.New(
		cron.WithLocation(loc),
		cron.WithChain(cron.SkipIfStillRunning(cron.DiscardLogger)),
	)
	c.Schedule(sched, cron.FuncJob(func() {
		r.Log.Printf("scheduled backup starting")
		if _, err := r.Run(ctx); err != nil {
			r.Log.Printf("scheduled backup failed: %v", err)
		} else {
			r.Log.Printf("scheduled backup succeeded")
		}
	}))
	c.Start()
	next := sched.Next(time.Now().In(loc))
	r.Log.Printf("scheduler started (schedule=%q tz=%s next=%s)", r.Cfg.Schedule, r.Cfg.Timezone, next.Format(time.RFC3339))

	<-ctx.Done()
	r.Log.Printf("shutting down scheduler...")
	stopCtx := c.Stop()
	select {
	case <-stopCtx.Done():
	case <-time.After(25 * time.Second):
		r.Log.Printf("shutdown grace window elapsed")
	}
	return nil
}

// Snapshots lists all Bakabel snapshots in the repository.
func (r *Runner) Snapshots(ctx context.Context) ([]restic.Snapshot, error) {
	if err := r.Cfg.ValidateRepo(); err != nil {
		return nil, err
	}
	return r.Restic.Snapshots(ctx)
}

// RestoreOptions selects what and where to restore.
type RestoreOptions struct {
	SnapshotID string
	Container  string
	Database   string
	User       string
	Volume     string
}

// Restore restores a verified Bakabel snapshot into a separate empty target.
func (r *Runner) Restore(ctx context.Context, opts RestoreOptions) error {
	if err := r.Cfg.ValidateDiscovery(); err != nil {
		return err
	}
	if err := r.Cfg.ValidateRepo(); err != nil {
		return err
	}
	if strings.TrimSpace(opts.SnapshotID) == "" {
		return errors.New("snapshot ID is required")
	}

	lock, err := r.Store.AcquireLock()
	if err != nil {
		return err
	}
	defer lock.Release()

	snaps, err := r.Restic.Snapshots(ctx)
	if err != nil {
		return err
	}
	snap, err := matchSnapshot(snaps, opts.SnapshotID)
	if err != nil {
		return err
	}

	dc, err := r.dockerClient()
	if err != nil {
		return err
	}
	defer dc.Close()

	switch snap.TagValue("type") {
	case "postgres":
		return r.restorePostgres(ctx, dc, snap, opts)
	case "volume":
		return r.restoreVolume(ctx, dc, snap, opts)
	default:
		return fmt.Errorf("snapshot %s is missing a valid type tag", snap.ShortID)
	}
}

func (r *Runner) restorePostgres(ctx context.Context, dc *docker.Client, snap restic.Snapshot, opts RestoreOptions) error {
	if opts.Container == "" {
		return errors.New("--container is required for PostgreSQL restore")
	}
	if len(snap.Paths) != 1 {
		return fmt.Errorf("unexpected snapshot paths for postgres snapshot %s", snap.ShortID)
	}
	ctr, err := dc.InspectContainer(ctx, opts.Container)
	if err != nil {
		return fmt.Errorf("inspect target container %q: %w", opts.Container, err)
	}
	if !ctr.State.Running {
		return fmt.Errorf("target container %q is not running", opts.Container)
	}

	env := make(map[string]string, len(ctr.Config.Env))
	for _, kv := range ctr.Config.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	user := opts.User
	if user == "" {
		user = env["POSTGRES_USER"]
	}
	if user == "" {
		user = "postgres"
	}
	db := opts.Database
	if db == "" {
		db = env["POSTGRES_DB"]
	}
	if db == "" {
		db = user
	}

	var execEnv []string
	if pwd := env["POSTGRES_PASSWORD"]; pwd != "" {
		execEnv = []string{"PGPASSWORD=" + pwd}
	}

	// Refuse restoring into a non-empty database.
	checkRes, err := dc.Exec(ctx, ctr.ID, docker.ExecOptions{
		User: "0:0",
		Cmd:  []string{"psql", "-v", "ON_ERROR_STOP=1", "-At", "-U", user, "-d", db, "-c", "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')"},
		Env:  execEnv,
	})
	if err != nil || checkRes.ExitCode != 0 {
		return fmt.Errorf("verify target database %q is empty: %s %v", db, strings.TrimSpace(checkRes.Stderr), err)
	}
	if strings.TrimSpace(checkRes.Stdout) != "0" {
		return fmt.Errorf("refusing restore: target database %q already has %s table(s); restore into an empty database", db, strings.TrimSpace(checkRes.Stdout))
	}

	dump, err := r.Restic.Dump(ctx, snap.ID, snap.Paths[0])
	if err != nil {
		return err
	}
	defer dump.Reader.Close()

	var stderrBuf bytes.Buffer
	code, execErr := dc.StreamExecIn(ctx, ctr.ID, docker.ExecOptions{
		User: "0:0",
		Cmd:  []string{"pg_restore", "--exit-on-error", "--single-transaction", "--no-password", "-U", user, "-d", db},
		Env:  execEnv,
	}, dump.Reader, &stderrBuf)
	dumpErr := dump.Wait()

	if dumpErr != nil {
		return dumpErr
	}
	if execErr != nil {
		return execErr
	}
	if code != 0 {
		return fmt.Errorf("pg_restore exited %d: %s", code, strings.TrimSpace(stderrBuf.String()))
	}
	return nil
}

func (r *Runner) restoreVolume(ctx context.Context, dc *docker.Client, snap restic.Snapshot, opts RestoreOptions) error {
	if opts.Volume == "" {
		return errors.New("--volume is required for volume restore")
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
		return errors.New("cannot determine helper image for volume restore; set BAKABEL_WORKER_IMAGE")
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

	res, err := dc.RunHelper(ctx, docker.HelperSpec{
		Image:       image,
		Cmd:         []string{"_volume-restore", "--snapshot", snap.ID},
		Env:         env,
		Mounts:      mounts,
		NetworkMode: r.resolveWorkerNetwork(ctx, dc, self),
		Labels:      map[string]string{"bakabel.role": "volume-helper"},
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		return fmt.Errorf("volume restore helper exited %d: %s", res.ExitCode, msg)
	}
	return nil
}

// Health evaluates local backup state without calling Docker or Restic.
func (r *Runner) Health() (state.HealthReport, bool, error) {
	sched, loc, err := r.Cfg.ValidateSchedule()
	if err != nil {
		return state.HealthReport{}, false, err
	}
	report, ok := r.Store.CheckHealth(time.Now().UTC(), sched, loc, r.Cfg.Timeout)
	return report, ok, nil
}

func (r *Runner) resolveWorkerImage(self *docker.Container) string {
	if r.Cfg.WorkerImage != "" {
		return r.Cfg.WorkerImage
	}
	if self != nil {
		if self.Image != "" {
			return self.Image
		}
		if self.Config.Image != "" {
			return self.Config.Image
		}
	}
	return ""
}

func (r *Runner) resolveWorkerNetwork(ctx context.Context, dc *docker.Client, self *docker.Container) string {
	if r.Cfg.WorkerNetwork != "" {
		return r.Cfg.WorkerNetwork
	}
	if r.Cfg.IsLocalRepo() {
		return "none"
	}
	if self != nil {
		// Sort user network names deterministically and skip built-in/Swarm-internal networks.
		names := make([]string, 0, len(self.NetworkSettings.Networks))
		for name := range self.NetworkSettings.Networks {
			switch name {
			case "", "none", "ingress", "docker_gwbridge", "bridge":
				continue
			}
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if dc == nil {
				return name
			}
			netInfo, err := dc.InspectNetwork(ctx, name)
			if err == nil && (netInfo.Scope == "local" || netInfo.Attachable) {
				return name
			}
		}
	}
	return "bridge"
}

func (r *Runner) buildHelperMounts(self *docker.Container) ([]docker.HelperMount, error) {
	var mounts []docker.HelperMount
	addedTarget := make(map[string]struct{})

	addFromSelfOrHost := func(targetPath string, readOnly bool) {
		if targetPath == "" {
			return
		}
		clean := filepath.Clean(targetPath)
		if _, exists := addedTarget[clean]; exists {
			return
		}
		if self != nil {
			for _, m := range self.Mounts {
				mDest := filepath.Clean(m.Destination)
				if clean == mDest || strings.HasPrefix(clean, mDest+"/") {
					if _, exists := addedTarget[mDest]; exists {
						return
					}
					addedTarget[mDest] = struct{}{}
					src := m.Source
					if m.Type == "volume" {
						src = m.Name
					}
					mounts = append(mounts, docker.HelperMount{
						Type:     m.Type,
						Source:   src,
						Target:   mDest,
						ReadOnly: readOnly || !m.RW,
					})
					return
				}
			}
		}
		// Host-mode fallback: bind the host path directly into the helper.
		addedTarget[clean] = struct{}{}
		mounts = append(mounts, docker.HelperMount{
			Type:     "bind",
			Source:   clean,
			Target:   clean,
			ReadOnly: readOnly,
		})
	}

	if r.Cfg.IsLocalRepo() {
		addFromSelfOrHost(r.Cfg.Repository, false)
	}
	if r.Cfg.ResticPasswordFile != "" {
		addFromSelfOrHost(r.Cfg.ResticPasswordFile, true)
	}
	if r.Cfg.AWSAccessKeyIDFile != "" {
		addFromSelfOrHost(r.Cfg.AWSAccessKeyIDFile, true)
	}
	if r.Cfg.AWSSecretKeyFile != "" {
		addFromSelfOrHost(r.Cfg.AWSSecretKeyFile, true)
	}
	return mounts, nil
}

func (r *Runner) helperEnv() ([]string, error) {
	env, err := r.Restic.BuildEnv()
	if err != nil {
		return nil, err
	}
	env = append(env,
		"BAKABEL_REPOSITORY="+r.Cfg.Repository,
		"BAKABEL_INSTALLATION="+r.Cfg.Installation,
		"BAKABEL_AUTO_INIT=false",
		"RESTIC_CACHE_DIR=/tmp/restic-cache",
	)
	return env, nil
}

func targetTags(t docker.Target) []string {
	tags := []string{
		"bakabel",
		"type:" + t.Type,
		"stack:" + t.Stack,
		"service:" + t.Service,
		"target:" + t.ID,
	}
	if t.Database != "" {
		tags = append(tags, "database:"+t.Database)
	}
	if t.VolumeName != "" {
		tags = append(tags, "volume:"+t.VolumeName)
	}
	return tags
}

func matchSnapshot(snaps []restic.Snapshot, query string) (restic.Snapshot, error) {
	var matches []restic.Snapshot
	for _, s := range snaps {
		if s.ID == query || s.ShortID == query || strings.HasPrefix(s.ID, query) {
			matches = append(matches, s)
		}
	}
	if len(matches) == 0 {
		return restic.Snapshot{}, fmt.Errorf("snapshot %q not found in Bakabel snapshots", query)
	}
	if len(matches) > 1 {
		return restic.Snapshot{}, fmt.Errorf("snapshot prefix %q is ambiguous (%d matches)", query, len(matches))
	}
	if !matches[0].HasTag("bakabel") {
		return restic.Snapshot{}, fmt.Errorf("snapshot %s is not a Bakabel snapshot", matches[0].ShortID)
	}
	return matches[0], nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
