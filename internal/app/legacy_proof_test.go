package app

// Legacy host-process probes retain their test-only fixture verifier. This is
// not a production handoff: production Recover uses concrete Docker identity.
import (
	"context"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func legacyRecover(ctx context.Context, o *state.Owner, c *docker.Client, worker func(context.Context, string) (bool, error), outcome state.Outcome) (docker.TerminalProof, error) {
	r, e := o.Load()
	if e != nil {
		return docker.TerminalProof{}, e
	}
	terminal := false
	if worker != nil {
		terminal, e = worker(ctx, r.WorkerName)
	}
	if e != nil || !terminal {
		r.Phase = state.PhaseQuarantine
		r.Status = state.StatusBlocked
		if e = o.Save(r); e != nil {
			return docker.TerminalProof{}, e
		}
		return docker.TerminalProof{}, docker.ErrQuarantine
	}
	return recoverSource(ctx, o, c, outcome, false)
}
