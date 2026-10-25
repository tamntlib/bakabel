package backup

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryVerifierIsNotSerializedIntoTransportDescriptors(t *testing.T) {
	r := Repository{Binary: "/restic", Env: []string{"RESTIC_PASSWORD_FILE=/credentials/password"}, VerifySource: func(context.Context) error { return nil }}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "VerifySource") {
		t.Fatal("adapter callback serialized")
	}
	var restored Repository
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Binary != r.Binary || restored.VerifySource != nil {
		t.Fatal("transport descriptor changed")
	}
}
