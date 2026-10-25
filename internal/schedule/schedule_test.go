package schedule

import (
	"testing"
	"time"
)

func TestFiveFieldCronTimezoneAndSteps(t *testing.T) {
	s, err := Parse("0 */6 * * *", "Asia/Ho_Chi_Minh")
	if err != nil {
		t.Fatal(err)
	}
	after, err := time.Parse(time.RFC3339, "2026-10-25T04:59:30Z")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Next(after)
	if err != nil || got.Format(time.RFC3339) != "2026-10-25T05:00:00Z" {
		t.Fatalf("timezone/step mismatch: %v %v", got, err)
	}
}

func TestInvalidSchedulesNeverFallback(t *testing.T) {
	for _, expr := range []string{"", "0 0 0 * * *", "61 * * * *", "0 */0 * * *", "CRON_TZ=UTC * * * * *", "@every 1h", "0 0 31 2 *", "0 0 * * *\n"} {
		if _, err := Parse(expr, "UTC"); err == nil {
			t.Fatalf("invalid schedule accepted: %q", expr)
		}
	}
	if _, err := Parse("* * * * *", "No/Such_Timezone"); err == nil {
		t.Fatal("invalid timezone accepted")
	}
}
