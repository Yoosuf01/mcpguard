package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDockerDriver_BuildRunArgs(t *testing.T) {
	driver := NewDockerDriver(DockerOptions{
		Image:        "alpine:3.19",
		WorkspaceDir: "/workspace",
	})

	limits := Limits{
		CPUs:         2.0,
		MemoryBytes:  512 * 1024 * 1024,
		MaxProcesses: 32,
		WorkdirBytes: 50 * 1024 * 1024,
		Timeout:      10 * time.Second,
	}

	id := "mcpguard-sbx-test123"
	args := driver.BuildRunArgs(id, limits)
	cmdLine := strings.Join(args, " ")

	// Verify required hardening security invariants
	requiredFlags := []string{
		"--network none",
		"--read-only",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--pids-limit=32",
		"--memory=536870912",
		"--cpus=2.00",
		"--tmpfs=/workspace:rw,noexec=false,size=52428800",
		"-w /workspace",
		"alpine:3.19",
	}

	for _, flag := range requiredFlags {
		if !strings.Contains(cmdLine, flag) {
			t.Errorf("expected docker run command to contain %q, got: %s", flag, cmdLine)
		}
	}
}

func TestDockerDriver_CleanPath(t *testing.T) {
	driver := NewDockerDriver(DockerOptions{})
	inst := &DockerInstance{driver: driver}

	// Allowed paths within workspace
	p1, err := inst.cleanPath("/workspace/script.py")
	if err != nil || p1 != "/workspace/script.py" {
		t.Errorf("expected /workspace/script.py, got %q (err=%v)", p1, err)
	}

	p2, err := inst.cleanPath("relative.py")
	if err != nil || p2 != "/workspace/relative.py" {
		t.Errorf("expected /workspace/relative.py, got %q (err=%v)", p2, err)
	}

	// Disallowed paths attempting to write outside workspace
	_, err = inst.cleanPath("/etc/passwd")
	if err != ErrReadOnlyFS {
		t.Errorf("expected ErrReadOnlyFS for /etc/passwd, got %v", err)
	}

	_, err = inst.cleanPath("/usr/local/bin/malicious")
	if err != ErrReadOnlyFS {
		t.Errorf("expected ErrReadOnlyFS for /usr/local/bin/malicious, got %v", err)
	}
}

func TestDockerDriver_Defaults(t *testing.T) {
	driver := NewDockerDriver(DockerOptions{})
	if driver.opts.Image != "alpine:latest" {
		t.Errorf("expected default image alpine:latest, got %s", driver.opts.Image)
	}
	if driver.opts.DockerBin != "docker" {
		t.Errorf("expected default bin docker, got %s", driver.opts.DockerBin)
	}
	if driver.opts.WorkspaceDir != "/workspace" {
		t.Errorf("expected default workspace /workspace, got %s", driver.opts.WorkspaceDir)
	}
}

func TestDockerDriver_ConformanceLive(t *testing.T) {
	if os.Getenv("MCPGUARD_DOCKER_LIVE") != "1" {
		t.Skip("set MCPGUARD_DOCKER_LIVE=1 to run live Docker conformance tests")
	}

	ctx := context.Background()
	driver := NewDockerDriver(DockerOptions{})

	if !driver.IsAvailable(ctx) {
		t.Skip("Docker daemon not available; skipping live container execution")
	}

	RunDriverConformanceSuite(t, driver)
}
