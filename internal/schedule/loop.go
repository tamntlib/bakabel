package schedule

import (
	"context"
	"errors"
	"time"
)

// Serve sleeps until each due occurrence and runs one job synchronously. Missed
// occurrences are skipped, not replayed in a catch-up burst. Observe is required
// so a job failure cannot silently turn into scheduler success.
func (s *Schedule) Serve(ctx context.Context, run func(context.Context) error, observe func(time.Time, error)) error {
	return s.loop(ctx, run, observe, time.Now, waitUntil)
}

func waitUntil(ctx context.Context, due time.Time) error {
	timer := time.NewTimer(time.Until(due))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Schedule) loop(ctx context.Context, run func(context.Context) error, observe func(time.Time, error), now func() time.Time, wait func(context.Context, time.Time) error) error {
	if run == nil || observe == nil {
		return errors.New("scheduler requires a job and result observer")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		due, err := s.Next(now())
		if err != nil {
			return err
		}
		for {
			if err = wait(ctx, due); err != nil {
				return err
			}
			if !now().Before(due) {
				break
			}
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		err = run(ctx)
		observe(now(), err)
	}
}
