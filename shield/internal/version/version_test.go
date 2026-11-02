package version

import (
	"strings"
	"testing"
)

func TestVersion_InfoAndShort(t *testing.T) {
	origV, origC, origD := Version, Commit, BuildDate
	defer func() {
		Version, Commit, BuildDate = origV, origC, origD
	}()

	Version = "v0.1.0"
	Commit = "deadbeef"
	BuildDate = "2026-10-30"

	if Short() != "v0.1.0" {
		t.Errorf("expected Short() v0.1.0, got %s", Short())
	}
	info := Info()
	if !strings.Contains(info, "v0.1.0") || !strings.Contains(info, "deadbeef") || !strings.Contains(info, "2026-10-30") {
		t.Errorf("unexpected Info() output: %s", info)
	}
}
