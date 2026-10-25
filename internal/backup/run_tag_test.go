package backup

import (
	"strings"
	"testing"
)

func TestMetadataRunTagRejectsControlCharactersAndOversize(t *testing.T) {
	valid, err := EncodeTags(fileMetadata(), "unknown", "run")
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{"run\nstatus=complete", "run\x00tail", "../../other", strings.Repeat("r", 129)} {
		if _, err := EncodeTags(fileMetadata(), "unknown", run); err == nil {
			t.Fatalf("unsafe run accepted by encoder: %q", run)
		}
		tags := append([]string{}, valid...)
		tags[len(tags)-1] = "bakabel.run=" + run
		if _, _, _, err := DecodeTags(tags); err == nil {
			t.Fatalf("unsafe run accepted by decoder: %q", run)
		}
	}
}
