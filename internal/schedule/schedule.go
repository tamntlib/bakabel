// Package schedule implements one timer-based, timezone-aware schedule.
package schedule

import (
	"errors"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/robfig/cron/v3"
)

type Schedule struct{ spec *cron.SpecSchedule }

// Parse supports minute hour day-of-month month day-of-week, including lists,
// ranges, steps and cron month/day names. Seconds/descriptors/inline timezones
// are deliberately unsupported. Errors never include the input configuration.
func Parse(expression, timezone string) (*Schedule, error) {
	invalid := errors.New("invalid five-field schedule or timezone")
	if strings.ContainsAny(expression, "\r\n") || len(strings.Fields(expression)) != 5 {
		return nil, invalid
	}
	location, err := time.LoadLocation(timezone)
	if err != nil || timezone == "" {
		return nil, invalid
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	parsed, err := parser.Parse(expression)
	if err != nil {
		return nil, invalid
	}
	spec, ok := parsed.(*cron.SpecSchedule)
	if !ok {
		return nil, invalid
	}
	spec.Location = location
	if spec.Next(time.Now()).IsZero() {
		return nil, invalid
	}
	return &Schedule{spec: spec}, nil
}

func (s *Schedule) Next(after time.Time) (time.Time, error) {
	if s == nil || s.spec == nil {
		return time.Time{}, errors.New("missing schedule")
	}
	next := s.spec.Next(after)
	if next.IsZero() || !next.After(after) {
		return time.Time{}, errors.New("schedule has no future occurrence")
	}
	return next, nil
}
