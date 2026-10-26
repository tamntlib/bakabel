package backup

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Retention is global per installation. Zero is disabled. Operators must prove
// a restore and approve deletion policy before enabling it; there is no automatic
// retention on initial setup or after a failed/empty backup run.
type Retention struct{ Daily, Weekly, Monthly int }

// Retain must run under the same installation mutex as backup/restore. It keeps
// native Restic locks and host,paths grouping; unknown, partial and foreign
// snapshots are never forget candidates. No direct-CLI overlap is supported.
func (r Repository) Retain(ctx context.Context, p Retention, host, installation string, successfulRun bool) error {
	if p.Daily < 0 || p.Weekly < 0 || p.Monthly < 0 {
		return errors.New("invalid retention policy")
	}
	if p.Daily == 0 && p.Weekly == 0 && p.Monthly == 0 {
		return nil
	}
	if !successfulRun {
		return errors.New("retention requires a complete data backup run")
	}
	if host == "" || installation == "" {
		return errors.New("missing retention installation identity")
	}
	snapshots, err := r.Snapshots(ctx)
	if err != nil {
		return err
	}
	protected := map[string]bool{}
	candidates := map[string]bool{}
	for _, s := range snapshots {
		if s.Hostname != host || !hasTag(s.Tags, "bakabel.status=complete") {
			protected[s.ID] = true
			continue
		}
		m, err := s.Restorable()
		if err != nil || !strings.HasPrefix(m.Source, installation+"/") {
			return errors.New("retention candidate has ambiguous recovery metadata")
		}
		candidates[s.ID] = true
	}
	if len(candidates) == 0 {
		return nil
	}
	args := []string{"forget", "--host", host, "--tag", "bakabel.status=complete", "--group-by", "host,paths"}
	for _, keep := range []struct {
		flag string
		n    int
	}{{"--keep-daily", p.Daily}, {"--keep-weekly", p.Weekly}, {"--keep-monthly", p.Monthly}} {
		if keep.n > 0 {
			args = append(args, keep.flag, strconv.Itoa(keep.n))
		}
	}
	if err = r.command(ctx, io.Discard, args...); err != nil {
		return err
	}
	after, err := r.Snapshots(ctx)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, s := range after {
		present[s.ID] = true
	}
	for id := range protected {
		if !present[id] {
			return errors.New("protected snapshot changed during retention; prune refused")
		}
	}
	removed := false
	for id := range candidates {
		if !present[id] {
			removed = true
		}
	}
	if !removed {
		return nil
	}
	return r.command(ctx, io.Discard, "prune", packSizeArg)
}
