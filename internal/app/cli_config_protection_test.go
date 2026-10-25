package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadedConfigPathIsInternalProtectionProvenance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "version: 1\ninstallation: fixture\nplatform: compose\nscope: [fixture]\nrepository: /repository\ncredentials:\n  password_file: /password\nworker_image: sha256:" + strings.Repeat("a", 64) + "\n"
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil || cfg.SourceFile != path {
		t.Fatal("loaded path not retained for metadata-only protection", cfg.SourceFile, err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encoded), path) || strings.Contains(string(encoded), "SourceFile") {
		t.Fatal("CLI provenance leaked into worker config", err)
	}
	if err = os.WriteFile(path, []byte(yaml+"SourceFile: /not-a-user-setting\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadConfig(path); err == nil {
		t.Fatal("internal provenance accepted as a config knob")
	}
}
