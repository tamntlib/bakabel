package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

const maxWorkflowBytes = 512 * 1024
const maxWorkflowTargets = 128

type workflowJob struct {
	Version   int                       `json:"version"`
	RunID     string                    `json:"runID"`
	CreatedAt time.Time                 `json:"createdAt"`
	Config    config.Config             `json:"config"`
	Targets   []docker.Target           `json:"targets"`
	Restore   *RestoreRequest           `json:"restore,omitempty"`
	Protected []files.ProtectedIdentity `json:"protected,omitempty"`
}

type WorkflowHandle struct {
	Worker    docker.Worker `json:"worker"`
	CreatedAt time.Time     `json:"createdAt"`
}

type TargetResult struct {
	TargetID   string `json:"targetID"`
	Status     string `json:"status"`
	SnapshotID string `json:"snapshotID,omitempty"`
	Error      string `json:"error,omitempty"`
}

type WorkflowResult struct {
	RunID            string         `json:"runID"`
	Status           string         `json:"status"`
	Targets          []TargetResult `json:"targets"`
	MaintenanceError string         `json:"maintenanceError,omitempty"`
}

func targetHash(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:]) }
func randomRun() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func workflowDir(c config.Config) string { return filepath.Join(c.StateDir, "workflow") }
func workflowClient(c config.Config) (*docker.Client, error) {
	if c.Validate() != nil {
		return nil, config.ErrInvalid
	}
	return docker.NewClient(c.DockerSocket)
}

func runtimePlan(ctx context.Context, c config.Config, client *docker.Client) (RuntimeMountPlan, docker.Container, error) {
	name, e := os.Hostname()
	if e != nil {
		return RuntimeMountPlan{}, docker.Container{}, e
	}
	self, e := client.InspectContainer(ctx, name)
	if e != nil {
		return RuntimeMountPlan{}, self, errors.New("run requires an inspected scheduler container")
	}
	plan, e := PlanRuntimeMounts(self, RuntimePaths{Installation: c.Installation, StateDir: c.StateDir, Repository: c.Repository, PasswordFile: c.Credentials.PasswordFile, Socket: c.DockerSocket, CredentialsFile: c.Credentials.S3CredentialsFile})
	return plan, self, e
}

// WorkflowStart freezes discovery, persists intent/job/exact worker authorization,
// closes the launcher guard, then starts exactly ONE worker. It never retries a
// Docker side effect. On error durable ownership is retained for WorkflowRecover.
func WorkflowStart(ctx context.Context, c config.Config) (WorkflowHandle, error) {
	var h WorkflowHandle
	client, e := workflowClient(c)
	if e != nil {
		return h, e
	}
	defer client.Close()
	plan, self, e := runtimePlan(ctx, c, client)
	if e != nil {
		return h, e
	}
	opts := discoveryOptions(c)
	opts.RunnerContainerID = self.ID
	opts.ProtectedNodePaths = plan.ProtectedNodePaths
	targets, e := client.Discover(ctx, opts)
	if e != nil {
		return h, e
	}
	if len(targets) == 0 {
		return h, errors.New("no targets")
	}
	if len(targets) > maxWorkflowTargets {
		return h, errors.New("too many targets")
	}
	for _, target := range targets {
		if target.Kind != "volume" {
			continue
		}
		// Mount roots exclude bind aliases. Referenced files also need their own
		// identity: a directory root cannot exclude a child file's external link.
		protectedPaths := []string{c.SourceFile, c.Credentials.PasswordFile, c.Credentials.S3CredentialsFile, c.NotificationURLFile}
		for _, mount := range self.Mounts {
			if mount.Type != "bind" && mount.Type != "volume" {
				continue
			}
			protectedPaths = append(protectedPaths, mount.Destination)
		}
		for _, path := range protectedPaths {
			if path == "" {
				continue
			}
			proof, err := files.CaptureProtection(path)
			if err != nil {
				return h, errors.New("protected runtime identity unavailable")
			}
			plan.Protected = append(plan.Protected, proof)
		}
		break
	}
	return startWorkflow(ctx, c, client, plan, targets)
}

func startWorkflow(ctx context.Context, c config.Config, client *docker.Client, plan RuntimeMountPlan, targets []docker.Target, restore ...RestoreRequest) (WorkflowHandle, error) {
	var h WorkflowHandle
	o, e := state.Acquire(c.StateDir)
	if e != nil {
		return h, e
	}
	defer o.Close()
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		if e == nil {
			e = state.ErrOwned
		}
		return h, e
	}
	run, e := randomRun()
	if e != nil {
		return h, e
	}
	info, e := client.Info(ctx)
	if e != nil {
		return h, e
	}
	h = WorkflowHandle{Worker: docker.Worker{DaemonID: info.ID, Name: "bakabel-worker-" + run, RunID: run}, CreatedAt: time.Now().UTC()}
	spec := docker.WorkerSpec{Image: c.WorkerImage, Mode: "workflow", Resources: c.WorkerResources, Mounts: append([]docker.WorkerMount{}, plan.Mounts...), S3: strings.HasPrefix(c.Repository, "s3:"), S3Region: c.Credentials.S3Region}
	for _, t := range targets {
		if t.Source.DaemonID != info.ID {
			return h, docker.ErrQuarantine
		}
		if t.Kind == "volume" && len(restore) == 0 {
			if len(t.Mounts) != 1 {
				return h, errors.New("single file mount required")
			}
			v, e := client.PrepareFileVolume(ctx, t.Source, t.Mounts[0].Destination)
			if e != nil {
				return h, e
			}
			if v.Mountpoint != t.Mounts[0].Source {
				return h, docker.ErrQuarantine
			}
			spec.Files = true
			spec.Mounts = append(spec.Mounts, docker.WorkerMount{Source: v.Mountpoint, Target: files.WorkerPath(t.ID, v.Destination), ReadOnly: true})
		}
	}
	if len(restore) == 1 && targets[0].Kind == "volume" {
		consumers, err := client.FileRestoreConsumerMounts(ctx)
		if err != nil {
			return h, err
		}
		mirrors, err := PlanFileRestoreMounts(consumers, restore[0].Directory, spec.Mounts)
		if err != nil {
			return h, err
		}
		spec.Files = true
		spec.Mounts = append(spec.Mounts, mirrors...)
	}
	// Only bounded known entries from a previously terminal run are removed.
	dir := workflowDir(c)
	if e = os.Mkdir(dir, 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return h, e
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return h, errors.New("private workflow directory required")
	}
	for _, p := range []string{filepath.Join(dir, "output", "result.json"), filepath.Join(dir, "job.json"), filepath.Join(dir, "output")} {
		if e = os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
			return h, e
		}
	}
	if e = os.Mkdir(filepath.Join(dir, "output"), 0700); e != nil {
		return h, e
	}
	wc := c
	wc.WorkerResources = c.WorkerResources.Effective()
	wc.Repository = plan.Repository
	wc.Credentials.PasswordFile = workerPassword
	wc.DockerSocket = workerSocket
	if wc.Credentials.S3CredentialsFile != "" {
		wc.Credentials.S3CredentialsFile = "/run/secrets/aws"
	}
	j := workflowJob{Version: 1, RunID: run, CreatedAt: h.CreatedAt, Config: wc, Targets: targets, Protected: plan.Protected}
	if len(restore) == 1 {
		j.Restore = &restore[0]
	}
	r := state.Record{RunID: run, DaemonID: info.ID, WorkerName: h.Worker.Name, Phase: state.PhaseIntent, Status: state.StatusActive}
	if e = o.NewRun(r); e != nil {
		return h, e
	}
	if e = publishJSON(dir, "job.json", j, maxWorkflowBytes); e != nil {
		return h, e
	}
	nodeDir := filepath.Join(plan.NodeState, "workflow")
	spec.Mounts = append(spec.Mounts, docker.WorkerMount{Source: filepath.Join(nodeDir, "job.json"), Target: workerJobFile, ReadOnly: true}, docker.WorkerMount{Source: filepath.Join(nodeDir, "output"), Target: workerResultDir})
	createdWorker, e := client.CreateWorker(ctx, h.Worker, spec)
	if e != nil {
		return h, e
	}
	h.Worker = createdWorker
	r.WorkerContainerID = h.Worker.ContainerID
	if e = o.Save(r); e != nil {
		return h, e
	}
	r.WorkerStartAuthorized = true
	if e = o.Save(r); e != nil {
		return h, e
	}
	if e = o.Close(); e != nil {
		return h, e
	}
	e = client.StartWorker(ctx, h.Worker)
	return h, e
}
