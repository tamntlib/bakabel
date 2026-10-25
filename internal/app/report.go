package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/notify"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

// Notification failure is independent: never replace the run error or mark a
// completed data backup failed merely because delivery was unavailable.
func reportFailure(ctx context.Context, c config.Config, res WorkflowResult, runErr error, stderr io.Writer) {
	if runErr == nil || c.NotificationURLFile == "" {
		return
	}
	status := "failed"
	if errors.Is(runErr, state.ErrBusy) || errors.Is(runErr, state.ErrOwned) || errors.Is(runErr, docker.ErrQuarantine) || errors.Is(runErr, errRecoveryBlocked) {
		status = "blocked"
	}
	send, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if notify.Failure(send, c.NotificationURLFile, notify.Event{Installation: c.Installation, RunID: res.RunID, Status: status}) != nil {
		fmt.Fprintln(stderr, "bakabel: failure notification could not be delivered")
	}
}
