package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// RunDriverConformanceSuite runs the unified escape and isolation test suite
// that both Docker and Firecracker sandbox drivers must satisfy.
func RunDriverConformanceSuite(t *testing.T, driver Driver) {
	ctx := context.Background()

	t.Run("EchoAndExitCode", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		res, err := inst.Exec(ctx, ExecOptions{
			Command: []string{"echo", "hello sandbox"},
		})
		if err != nil {
			t.Fatalf("unexpected exec error: %v", err)
		}
		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}
		if !strings.Contains(res.Stdout, "hello sandbox") {
			t.Errorf("expected 'hello sandbox' in stdout, got %q", res.Stdout)
		}
	})

	t.Run("WallClockTimeout", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Timeout = 50 * time.Millisecond

		inst, err := driver.Create(ctx, limits)
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		start := time.Now()
		_, err = inst.Exec(ctx, ExecOptions{
			Command: []string{"sleep", "1"},
			Timeout: 50 * time.Millisecond,
		})
		duration := time.Since(start)

		if err != ErrTimeout {
			t.Errorf("expected ErrTimeout, got %v", err)
		}
		if duration > 500*time.Millisecond {
			t.Errorf("timeout took too long to enforce: %v", duration)
		}
	})

	t.Run("StdinStreaming", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		inputPayload := "data to process\nline 2"
		res, err := inst.Exec(ctx, ExecOptions{
			Command: []string{"cat"},
			Stdin:   bytes.NewReader([]byte(inputPayload)),
		})
		if err != nil {
			t.Fatalf("unexpected exec error: %v", err)
		}
		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}
		if !strings.Contains(res.Stdout, "data to process") {
			t.Errorf("expected stdin piped through cat, got %q", res.Stdout)
		}
	})

	t.Run("EnvironmentAllowlist", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		res, err := inst.Exec(ctx, ExecOptions{
			Command: []string{"sh", "-c", "echo $SANDBOX_VAR"},
			Env:     map[string]string{"SANDBOX_VAR": "custom_val_42"},
		})
		if err != nil {
			t.Fatalf("unexpected exec error: %v", err)
		}
		if !strings.Contains(res.Stdout, "custom_val_42") {
			t.Errorf("expected env var passed to sandbox, got %q", res.Stdout)
		}
	})

	t.Run("Filesystem_WorkspaceReadWrite", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		content := []byte("print('script output')\n")
		err = inst.WriteFile(ctx, "/workspace/test.py", content)
		if err != nil {
			t.Fatalf("failed to write file to workspace: %v", err)
		}

		readBack, err := inst.ReadFile(ctx, "/workspace/test.py")
		if err != nil {
			t.Fatalf("failed to read file from workspace: %v", err)
		}
		if !bytes.Equal(readBack, content) {
			t.Errorf("expected %q, got %q", content, readBack)
		}
	})

	t.Run("Filesystem_ReadOnlyRootViolation", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		// Direct WriteFile to root filesystem outside /workspace
		err = inst.WriteFile(ctx, "/etc/hacked.conf", []byte("evil"))
		if err != ErrReadOnlyFS {
			t.Errorf("expected ErrReadOnlyFS writing to /etc, got %v", err)
		}

		// Command attempt to touch /etc/hacked
		_, err = inst.Exec(ctx, ExecOptions{
			Command: []string{"sh", "-c", "touch /etc/hacked"},
		})
		if err != ErrReadOnlyFS {
			t.Errorf("expected ErrReadOnlyFS from touch /etc/hacked, got %v", err)
		}
	})

	t.Run("Escape_ForkBombContained", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		// Attempt classic fork bomb
		_, err = inst.Exec(ctx, ExecOptions{
			Command: []string{"sh", "-c", ":(){ :|:& };:"},
		})
		if err != ErrProcessLimit {
			t.Errorf("expected ErrProcessLimit from fork bomb, got %v", err)
		}
	})

	t.Run("Escape_NetworkBlocked", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}
		defer inst.Destroy(ctx)

		// Attempt cloud metadata SSRF
		_, err = inst.Exec(ctx, ExecOptions{
			Command: []string{"curl", "http://169.254.169.254/latest/meta-data/"},
		})
		if err != ErrNetworkBlocked {
			t.Errorf("expected ErrNetworkBlocked connecting to metadata IP, got %v", err)
		}
	})

	t.Run("Lifecycle_DestroyClean", func(t *testing.T) {
		inst, err := driver.Create(ctx, DefaultLimits())
		if err != nil {
			t.Fatalf("driver.Create failed: %v", err)
		}

		err = inst.Destroy(ctx)
		if err != nil {
			t.Fatalf("failed to destroy instance: %v", err)
		}

		// Subsequent operations must return ErrDestroyed
		_, err = inst.Exec(ctx, ExecOptions{Command: []string{"echo", "hi"}})
		if err != ErrDestroyed {
			t.Errorf("expected ErrDestroyed on Exec, got %v", err)
		}

		_, err = inst.ReadFile(ctx, "/workspace/test.txt")
		if err != ErrDestroyed {
			t.Errorf("expected ErrDestroyed on ReadFile, got %v", err)
		}

		err = inst.WriteFile(ctx, "/workspace/test.txt", []byte("data"))
		if err != ErrDestroyed {
			t.Errorf("expected ErrDestroyed on WriteFile, got %v", err)
		}
	})
}

func TestMemDriver_Conformance(t *testing.T) {
	driver := NewMemDriver()
	RunDriverConformanceSuite(t, driver)
}
