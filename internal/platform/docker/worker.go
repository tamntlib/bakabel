package docker

import (
	"context"
	"time"
)

// Worker is a durable, never-reused name/run on one exact daemon. An empty ID
// permits name adoption after a lost create response, never a proof of absence.
type Worker struct{ DaemonID, ContainerID, Name, RunID string }
type WorkerProof struct {
	Worker   Worker
	Terminal bool
	Created  bool
	ExitCode int
}

type workerInspect struct {
	ID         string `json:"Id"`
	Name       string
	Config     struct{ Labels map[string]string }
	HostConfig struct {
		AutoRemove    *bool
		RestartPolicy struct{ Name string }
	}
	State struct {
		Status                    string
		Running, Restarting, Dead *bool
		ExitCode                  *int
	}
}

func (w Worker) valid() bool {
	return validID(w.Name) && validID(w.RunID) && w.DaemonID != "" && (w.ContainerID == "" || validID(w.ContainerID))
}
func (c *Client) inspectWorker(ctx context.Context, w Worker) (workerInspect, error) {
	var v workerInspect
	if !w.valid() {
		return v, ErrQuarantine
	}
	d, e := c.Info(ctx)
	if e != nil || d.ID != w.DaemonID {
		return v, ErrQuarantine
	}
	id := w.ContainerID
	if id == "" {
		id = w.Name
	}
	if e = c.request(ctx, "GET", "/containers/"+id+"/json", nil, &v); e != nil {
		if e == apiError(404) && w.ContainerID != "" {
			// ID was durably established before start. Exact ID AND reserved name must
			// both be absent; an absent intent-only name is never create-gap proof.
			var byName workerInspect
			if c.request(ctx, "GET", "/containers/"+w.Name+"/json", nil, &byName) == apiError(404) {
				return v, apiError(404)
			}
		}
		return v, ErrQuarantine
	}
	labels := v.Config.Labels
	if !validID(v.ID) || (w.ContainerID != "" && v.ID != w.ContainerID) || v.Name != "/"+w.Name || labels["bakabel.worker"] != "1" || labels["bakabel.run"] != w.RunID || labels["bakabel.daemon"] != w.DaemonID || v.HostConfig.AutoRemove == nil || *v.HostConfig.AutoRemove || v.HostConfig.RestartPolicy.Name != "no" || v.State.Running == nil || v.State.Restarting == nil || v.State.Dead == nil || v.State.ExitCode == nil || *v.State.Restarting {
		return v, ErrQuarantine
	}
	return v, nil
}
func workerProof(w Worker, v workerInspect) WorkerProof {
	w.ContainerID = v.ID
	return WorkerProof{Worker: w, Created: v.State.Status == "created" && !*v.State.Running, Terminal: !*v.State.Running && !*v.State.Restarting && (v.State.Status == "exited" || v.State.Status == "dead"), ExitCode: *v.State.ExitCode}
}

// DiscardCreatedWorker requires current Engine-created (never-running) state.
// Delete without force plus same-daemon 404 fences any pending/future start.
// If start won the race, nonforce DELETE fails: quarantine, never force removal.
func (c *Client) DiscardCreatedWorker(ctx context.Context, w Worker) (WorkerProof, error) {
	v, e := c.inspectWorker(ctx, w)
	if e != nil || w.ContainerID == "" || v.State.Status != "created" || *v.State.Running {
		return WorkerProof{}, ErrQuarantine
	}
	if e = c.request(ctx, "DELETE", "/containers/"+w.ContainerID, nil, nil); e != nil {
		return WorkerProof{}, ErrQuarantine
	}
	daemon, e := c.Info(ctx)
	if e != nil || daemon.ID != w.DaemonID {
		return WorkerProof{}, ErrQuarantine
	}
	var readback workerInspect
	if e = c.request(ctx, "GET", "/containers/"+w.ContainerID+"/json", nil, &readback); e != apiError(404) {
		return WorkerProof{}, ErrQuarantine
	}
	return WorkerProof{Worker: w, Terminal: true}, nil
}

// InspectWorker never substitutes a name match for a mismatched established ID.
func (c *Client) InspectWorker(ctx context.Context, w Worker) (WorkerProof, error) {
	v, e := c.inspectWorker(ctx, w)
	if e == apiError(404) {
		return WorkerProof{Worker: w, Terminal: true, ExitCode: -1}, nil
	}
	if e != nil {
		return WorkerProof{}, ErrQuarantine
	}
	return workerProof(w, v), nil
}

// TerminateWorker signals ONLY a freshly verified container ID, never the source.
// HTTP success, socket loss and a not-running error are not terminal evidence.
func (c *Client) TerminateWorker(ctx context.Context, w Worker) (WorkerProof, error) {
	proof, e := c.InspectWorker(ctx, w)
	if e != nil {
		return WorkerProof{}, ErrQuarantine
	}
	if proof.Terminal {
		return proof, nil
	}
	v, e := c.inspectWorker(ctx, w)
	if e != nil {
		return WorkerProof{}, ErrQuarantine
	}
	if v.State.Status != "running" || !*v.State.Running {
		return proof, ErrQuarantine
	}
	if e = c.request(ctx, "POST", "/containers/"+v.ID+"/kill?signal=KILL", nil, nil); e != nil {
		return proof, ErrQuarantine
	}
	for {
		proof, e = c.InspectWorker(ctx, proof.Worker)
		if e != nil {
			return proof, ErrQuarantine
		}
		if proof.Terminal {
			return proof, nil
		}
		select {
		case <-ctx.Done():
			return proof, ErrQuarantine
		case <-time.After(100 * time.Millisecond):
		}
	}
}
