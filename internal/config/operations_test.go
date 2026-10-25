package config

import (
	"strings"
	"testing"
)

func TestOptionalOperationsDefaultOffAndUseOnlyReferences(t *testing.T) {
	c, err := Parse(strings.NewReader(minimal))
	if err != nil || c.Retention.Daily != 0 || c.Retention.Weekly != 0 || c.Retention.Monthly != 0 || c.NotificationURLFile != "" {
		t.Fatal("optional operations not off", err)
	}
	c, err = Parse(strings.NewReader(minimal + "retention:\n  daily: 7\n  weekly: 4\n  monthly: 3\nnotification_url_file: /credentials/webhook\n"))
	if err != nil || c.Retention.Daily != 7 || c.Retention.Weekly != 4 || c.Retention.Monthly != 3 || c.NotificationURLFile != "/credentials/webhook" {
		t.Fatal("optional operation schema", err)
	}
}

func TestOperationsRejectWrongTypesAndInvalidCronAtStartup(t *testing.T) {
	for _, extra := range []string{"retention:\n  daily: -1\n", "retention:\n  daily: '7'\n", "retention:\n  enabled: true\n", "notification_url_file: https://private-endpoint\n", "schedule: '61 * * * *'\n", "schedule: '0 0 31 2 *'\n"} {
		if _, err := Parse(strings.NewReader(minimal + extra)); err == nil {
			t.Fatalf("invalid operation configuration accepted: %q", extra)
		}
	}
}
