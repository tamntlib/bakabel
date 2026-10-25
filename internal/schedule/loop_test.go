package schedule

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoopReportsFailureAndSkipsMissedOccurrences(t *testing.T) {
	s, err := Parse("0 * * * *", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 0, 15, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits, runs, reports := 0, 0, 0
	failure := errors.New("fixture failure")
	var first time.Time
	wait := func(ctx context.Context, due time.Time) error {
		waits++
		if waits == 1 {
			first = due
			now = due
			return nil
		}
		if !due.After(now) || !due.After(first.Add(7*time.Hour)) {
			t.Fatal("missed occurrences replayed", due, now)
		}
		cancel()
		return ctx.Err()
	}
	err = s.loop(ctx, func(context.Context) error { runs++; now = now.Add(7 * time.Hour); return failure }, func(at time.Time, e error) {
		reports++
		if !errors.Is(e, failure) || at != now {
			t.Fatal("job failure hidden", at, e)
		}
	}, func() time.Time { return now }, wait)
	if !errors.Is(err, context.Canceled) || runs != 1 || reports != 1 || waits != 2 {
		t.Fatalf("loop %v runs%d reports%d waits%d", err, runs, reports, waits)
	}
}

func TestLoopWaitsAgainIfWallClockMovedBackward(t *testing.T) {
	s, err := Parse("0 * * * *", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 0, 15, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits, runs := 0, 0
	var first time.Time
	err = s.loop(ctx, func(context.Context) error { runs++; cancel(); return nil }, func(time.Time, error) {}, func() time.Time { return now }, func(ctx context.Context, due time.Time) error {
		waits++
		if waits == 1 {
			first = due
			now = due.Add(-time.Minute)
			return nil
		}
		if due != first {
			t.Fatal("schedule lost while clock moved backward")
		}
		now = due
		return nil
	})
	if !errors.Is(err, context.Canceled) || runs != 1 || waits != 2 {
		t.Fatalf("loop %v runs%d waits%d", err, runs, waits)
	}
}

func TestServeCancellationNeverStartsJob(t *testing.T) {
	s, err := Parse("0 0 * * *", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = s.Serve(ctx, func(context.Context) error { t.Fatal("canceled scheduler ran job"); return nil }, func(time.Time, error) { t.Fatal("canceled scheduler reported fake job") })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = s.Serve(context.Background(), nil, nil); err == nil {
		t.Fatal("unobservable scheduler accepted")
	}
}
