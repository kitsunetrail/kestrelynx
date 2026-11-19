package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestBuildCVERecordSeverity(t *testing.T) {
	cfg := config.Config{}
	cfg.State.Path = "/var/lib/kestrelynx/state.json"
	cfg.Scan.CVERecordSeverity.Enabled = true

	src := buildCVERecordSeverity(cfg, slog.Default())
	if src == nil {
		t.Fatal("no source although the config enables it")
	}
	if want := filepath.Join("/var/lib/kestrelynx", "cve-records"); src.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q", src.CacheDir, want)
	}
	if src.BaseURL != "" {
		t.Errorf("the records must come from the CVE list repository: %q", src.BaseURL)
	}
	if tr := withUnscored(scanner.Trivy{}, src); tr.Unscored == nil {
		t.Error("the scanner was not given the source")
	}

	cfg.Scan.CVERecordSeverity.Enabled = false
	off := buildCVERecordSeverity(cfg, slog.Default())
	if off != nil {
		t.Fatal("a source although the config turns it off")
	}
	// A scanner must see no source at all, not one that is a nil pointer:
	// it asks Trivy for UNKNOWN findings whenever it has one.
	if tr := withUnscored(scanner.Trivy{}, off); tr.Unscored != nil {
		t.Error("the scanner was given a source although the config turns it off")
	}
}
