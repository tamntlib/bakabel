// Package state manages Bakabel's local lockfile, repository guard, and health state.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
)

// ErrLocked is returned when another bakabel operation already holds the lock.
var ErrLocked = errors.New("another bakabel operation is currently running")

// TargetResult records the outcome of backing up a single discovered target.
type TargetResult struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	Status     string `json:"status"` // "ok" or "error"
	Error      string `json:"error,omitempty"`
}

// RunResult is persisted atomically after every backup run.
type RunResult struct {
	Operation     string         `json:"operation"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    time.Time      `json:"finished_at"`
	Status        string         `json:"status"` // "ok" or "failed"
	Targets       []TargetResult `json:"targets,omitempty"`
	Error         string         `json:"error,omitempty"`
	LastSuccessAt *time.Time     `json:"last_success_at,omitempty"`
}

// RepoMeta pins the Restic repository ID to prevent accidental re-initialization.
type RepoMeta struct {
	RepositoryID string    `json:"repository_id"`
	Repository   string    `json:"repository"`
	RecordedAt   time.Time `json:"recorded_at"`
}

// HealthReport describes the scheduler/backup health evaluated from local state.
type HealthReport struct {
	Status        string     `json:"status"` // "healthy", "running", "never", "failed", "overdue"
	LastStatus    string     `json:"last_status,omitempty"`
	LastFinished  *time.Time `json:"last_finished_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	NextDueAt     *time.Time `json:"next_due_at,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// Store owns files under BAKABEL_STATE_DIR.
type Store struct {
	Dir string
}

// New returns a Store rooted at dir.
func New(dir string) *Store {
	return &Store{Dir: dir}
}

// EnsureDir creates the state directory with private permissions if missing.
func (s *Store) EnsureDir() error {
	return os.MkdirAll(s.Dir, 0o700)
}

// Lock holds an advisory OS flock released automatically on Close or process exit.
type Lock struct {
	file *os.File
}

// AcquireLock takes a non-blocking exclusive flock on <state_dir>/bakabel.lock.
func (s *Store) AcquireLock() (*Lock, error) {
	if err := s.EnsureDir(); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, "bakabel.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("acquire lock: %w", err)
	}
	return &Lock{file: f}, nil
}

// Release unlocks and closes the lockfile.
func (l *Lock) Release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

// IsLocked reports whether another process currently holds the exclusive lock.
func (s *Store) IsLocked() bool {
	f, err := os.OpenFile(filepath.Join(s.Dir, "bakabel.lock"), os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// LoadRepoMeta loads repo.json if present; returns nil, nil when absent.
func (s *Store) LoadRepoMeta() (*RepoMeta, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "repo.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m RepoMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse repo.json: %w", err)
	}
	return &m, nil
}

// SaveRepoMeta atomically writes repo.json.
func (s *Store) SaveRepoMeta(m RepoMeta) error {
	return s.writeJSON("repo.json", m)
}

// LoadLastResult loads last-result.json if present; returns nil, nil when absent.
func (s *Store) LoadLastResult() (*RunResult, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, "last-result.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r RunResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse last-result.json: %w", err)
	}
	return &r, nil
}

// SaveLastResult preserves prior LastSuccessAt on failure and writes last-result.json atomically.
func (s *Store) SaveLastResult(r RunResult) error {
	if r.Status == "ok" {
		t := r.FinishedAt
		r.LastSuccessAt = &t
	} else if r.LastSuccessAt == nil {
		if prev, err := s.LoadLastResult(); err == nil && prev != nil {
			r.LastSuccessAt = prev.LastSuccessAt
		}
	}
	return s.writeJSON("last-result.json", r)
}

// CheckHealth evaluates backup health without making Docker or Restic API calls.
func (s *Store) CheckHealth(now time.Time, sched cron.Schedule, loc *time.Location, timeout time.Duration) (HealthReport, bool) {
	running := s.IsLocked()
	last, err := s.LoadLastResult()
	if err != nil {
		return HealthReport{Status: "failed", Error: err.Error()}, false
	}
	if last == nil {
		if running {
			return HealthReport{Status: "running"}, true
		}
		return HealthReport{Status: "never"}, false
	}

	report := HealthReport{
		LastStatus:    last.Status,
		LastFinished:  &last.FinishedAt,
		LastSuccessAt: last.LastSuccessAt,
		Error:         last.Error,
	}

	if last.LastSuccessAt != nil && sched != nil && loc != nil {
		nextDue := sched.Next(last.LastSuccessAt.In(loc)).Add(timeout)
		report.NextDueAt = &nextDue
		if now.After(nextDue) {
			report.Status = "overdue"
			return report, false
		}
	}

	if running {
		report.Status = "running"
		return report, true
	}
	if last.Status != "ok" {
		report.Status = "failed"
		return report, false
	}
	report.Status = "healthy"
	return report, true
}

func (s *Store) writeJSON(name string, v any) error {
	if err := s.EnsureDir(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(s.Dir, name+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(s.Dir, name)); err != nil {
		return err
	}
	cleanup = false
	return nil
}
