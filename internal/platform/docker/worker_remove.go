package docker

import "context"

// RemoveWorker is post-proof cleanup, not cancellation. Call only after source
// recovery proof, before releasing durable ownership. It rechecks concrete
// ownership and terminal state, never force-removes or kills anything.
func (c *Client) RemoveWorker(ctx context.Context, w Worker) error {
	if w.ContainerID == "" {
		return ErrQuarantine
	}
	proof, e := c.InspectWorker(ctx, w)
	if e != nil || !proof.Terminal {
		return ErrQuarantine
	}
	if proof.ExitCode == -1 {
		return nil
	} // exact ID AND name already absent, same daemon
	if e = c.request(ctx, "DELETE", "/containers/"+w.ContainerID, nil, nil); e != nil {
		return ErrQuarantine
	}
	proof, e = c.InspectWorker(ctx, w)
	if e != nil || !proof.Terminal || proof.ExitCode != -1 {
		return ErrQuarantine
	}
	return nil
}
