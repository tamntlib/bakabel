package docker

import "context"

// FileRestoreConsumerMounts freezes exact inspected bind/volume roots, including
// stopped consumers. This read-only inventory grants no restore permission: the
// native visibility + alias + empty-target gate must still run in the worker.
func (c *Client) FileRestoreConsumerMounts(ctx context.Context) ([]Mount, error) {
	var ids []struct {
		ID string `json:"Id"`
	}
	if e := c.request(ctx, "GET", "/containers/json?all=true", nil, &ids); e != nil {
		return nil, e
	}
	if len(ids) > 4096 {
		return nil, ErrQuarantine
	}
	mounts := []Mount{}
	for _, id := range ids {
		v, e := c.InspectContainer(ctx, id.ID)
		if e != nil || v.ID != id.ID {
			return nil, ErrQuarantine
		}
		for _, m := range v.Mounts {
			if m.Type == "bind" || m.Type == "volume" {
				if !filePath(m.Source) {
					return nil, ErrQuarantine
				}
				mounts = append(mounts, m)
				if len(mounts) > 4096 {
					return nil, ErrQuarantine
				}
			}
		}
	}
	return mounts, nil
}
