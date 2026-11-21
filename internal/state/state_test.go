package state

import (
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

func TestLockExclusivity(t *testing.T) {
	s := New(t.TempDir())
	l1, err := s.AcquireLock()
	if err != nil {
		t.Fatalf("first AcquireLock failed: %v", err)
	}
	if !s.IsLocked() {
		t.Fatal("expected IsLocked=true while held")
	}
	if _, err := s.AcquireLock(); err != ErrLocked {
		t.Fatalf("second AcquireLock = %v, want ErrLocked", err)
	}
	l1.Release()
	if s.IsLocked() {
		t.Fatal("expected IsLocked=false after release")
	}
}

func TestRepoMetaAndLastResultPersistence(t *testing.T) {
	s := New(t.TempDir())
	if meta, err := s.LoadRepoMeta(); err != nil || meta != nil {
		t.Fatalf("empty LoadRepoMeta = %v, %v", meta, err)
	}
	want := RepoMeta{RepositoryID: "abc123", Repository: "/repository", RecordedAt: time.Now().UTC().Truncate(time.Second)}
	if err := s.SaveRepoMeta(want); err != nil {
		t.Fatalf("SaveRepoMeta failed: %v", err)
	}
	got, err := s.LoadRepoMeta()
	if err != nil || got == nil || got.RepositoryID != want.RepositoryID {
		t.Fatalf("LoadRepoMeta = %+v, %v", got, err)
	}

	t1 := time.Date(2026, 11, 21, 2, 0, 0, 0, time.UTC)
	if err := s.SaveLastResult(RunResult{Operation: "run", StartedAt: t1, FinishedAt: t1.Add(time.Minute), Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	t2 := t1.Add(24 * time.Hour)
	if err := s.SaveLastResult(RunResult{Operation: "run", StartedAt: t2, FinishedAt: t2.Add(time.Minute), Status: "failed", Error: "boom"}); err != nil {
		t.Fatal(err)
	}
	last, err := s.LoadLastResult()
	if err != nil || last == nil {
		t.Fatalf("LoadLastResult = %v, %v", last, err)
	}
	if last.Status != "failed" || last.LastSuccessAt == nil || !last.LastSuccessAt.Equal(t1.Add(time.Minute)) {
		t.Fatalf("failed run should preserve LastSuccessAt: %+v", last)
	}
}

func TestCheckHealthStates(t *testing.T) {
	s := New(t.TempDir())
	sched, err := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse("0 2 * * *")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

	rep, ok := s.CheckHealth(now, sched, time.UTC, time.Hour)
	if ok || rep.Status != "never" {
		t.Fatalf("initial health = %+v, ok=%v", rep, ok)
	}

	okTime := time.Date(2026, 11, 21, 2, 5, 0, 0, time.UTC)
	_ = s.SaveLastResult(RunResult{Operation: "run", StartedAt: okTime, FinishedAt: okTime, Status: "ok"})

	rep, ok = s.CheckHealth(now, sched, time.UTC, time.Hour)
	if !ok || rep.Status != "healthy" {
		t.Fatalf("expected healthy, got %+v ok=%v", rep, ok)
	}

	overdueNow := time.Date(2026, 11, 22, 3, 1, 0, 0, time.UTC)
	rep, ok = s.CheckHealth(overdueNow, sched, time.UTC, time.Hour)
	if ok || rep.Status != "overdue" {
		t.Fatalf("expected overdue, got %+v ok=%v", rep, ok)
	}
}
