package app

import (
	"errors"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/schedule"
	"github.com/tamntlib/bakabel/internal/state"
)

var errUnhealthy = errors.New("backup health check failed")

type HealthReport struct {
	Status      string        `json:"status"`
	Overdue     bool          `json:"overdue"`
	LastResult  *state.Result `json:"lastResult,omitempty"`
	ActiveRunID string        `json:"activeRunID,omitempty"`
	Deadline    time.Time     `json:"deadline,omitempty"`
}

// Health is a read-only state/clock check, not a Docker probe or a server. It
// cannot detect its own dead scheduler; an independent monitor must invoke it.
// A successful restore never resets backup freshness.
func Health(c config.Config, now time.Time) (HealthReport, error) {
	h := HealthReport{Status: "blocked", Overdue: true}
	if c.Validate() != nil || c.Schedule == "" {
		return h, errUnhealthy
	}
	sched, err := schedule.Parse(c.Schedule, c.Timezone)
	if err != nil {
		return h, errUnhealthy
	}
	last, err := state.ObserveResult(c.StateDir)
	if err != nil && !errors.Is(err, state.ErrNoResult) {
		return h, errUnhealthy
	}
	h.Status = "never"
	lastFailed := err == nil && last.Status != state.OutcomeSuccess
	if err == nil {
		h.LastResult = &last
		if last.LastBackupSuccessAt != "" {
			at, e := time.Parse(time.RFC3339Nano, last.LastBackupSuccessAt)
			if e != nil || at.After(now) {
				h.Status = "blocked"
				return h, errUnhealthy
			}
			next, e := sched.Next(at)
			if e != nil {
				return h, errUnhealthy
			}
			h.Deadline = next.Add(c.Timeout)
			h.Overdue = !now.Before(h.Deadline)
			h.Status = "healthy"
			if h.Overdue {
				h.Status = "overdue"
			}
		}
		if last.Status != state.OutcomeSuccess {
			h.Status = "failed"
		}
	}
	active, err := state.Observe(c.StateDir)
	if err != nil && !errors.Is(err, state.ErrNoRun) {
		h.Status = "blocked"
		return h, errUnhealthy
	}
	if err == nil {
		h.ActiveRunID = active.RunID
		j, e := loadWorkflow(c, active)
		if e != nil || active.Status == state.StatusBlocked || j.CreatedAt.After(now) || !now.Before(j.CreatedAt.Add(j.Config.Timeout)) {
			h.Status = "blocked"
			return h, errUnhealthy
		}
		h.Status = "running"
	}
	if h.Overdue || lastFailed || h.Status == "never" {
		return h, errUnhealthy
	}
	return h, nil
}
