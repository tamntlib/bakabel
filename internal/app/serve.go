package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/schedule"
	"github.com/tamntlib/bakabel/internal/state"
)

var errRecoveryBlocked = errors.New("workflow recovery blocked")

type serveEvent struct {
	Event     string          `json:"event"`
	Time      time.Time       `json:"time"`
	Operation string          `json:"operation,omitempty"`
	Failed    bool            `json:"failed,omitempty"`
	Result    *WorkflowResult `json:"result,omitempty"`
}

// Serve adopts an existing durable run without renewing its deadline, then
// sleeps on the single cron timer. Failed jobs are observed, not retried in a
// loop. Unproven recovery leaves ownership intact and stops scheduling.
func Serve(ctx context.Context, c config.Config, stdout, stderr io.Writer) error {
	if c.Validate() != nil || c.Schedule == "" {
		return config.ErrInvalid
	}
	sched, err := schedule.Parse(c.Schedule, c.Timezone)
	if err != nil {
		return config.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var outputErr error
	blocked := func() error {
		reportFailure(ctx, c, WorkflowResult{}, errRecoveryBlocked, stderr)
		return errRecoveryBlocked
	}
	observe := func(res WorkflowResult, runErr error, operation string) {
		if json.NewEncoder(stdout).Encode(serveEvent{Event: "run_finished", Time: time.Now().UTC(), Operation: operation, Failed: runErr != nil, Result: &res}) != nil {
			outputErr = errors.New("scheduler result output failed")
			cancel()
		}
		reportFailure(ctx, c, res, runErr, stderr)
	}
	h, err := WorkflowCurrent(c)
	if err != nil && !errors.Is(err, state.ErrNoRun) {
		return blocked()
	}
	if err == nil {
		r, e := state.Observe(c.StateDir)
		if e != nil {
			return blocked()
		}
		j, e := loadWorkflow(c, r)
		if e != nil {
			return blocked()
		}
		operation := "backup"
		if j.Restore != nil {
			operation = "restore"
		}
		res, runErr := WorkflowWait(ctx, c, h)
		observe(res, runErr, operation)
		if outputErr != nil {
			return outputErr
		}
		if _, e = state.Observe(c.StateDir); !errors.Is(e, state.ErrNoRun) {
			return blocked()
		}
	}
	var result WorkflowResult
	recoveryBlocked := false
	err = sched.Serve(ctx, func(ctx context.Context) error {
		var runErr error
		result, runErr = Run(ctx, c)
		if runErr != nil {
			current, ownerErr := state.Observe(c.StateDir)
			if ownerErr == nil && current.RunID == result.RunID || ownerErr != nil && !errors.Is(ownerErr, state.ErrNoRun) {
				recoveryBlocked = true
				cancel()
			}
		}
		return runErr
	}, func(_ time.Time, runErr error) { observe(result, runErr, "backup") })
	if outputErr != nil {
		return outputErr
	}
	if recoveryBlocked {
		return blocked()
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}
