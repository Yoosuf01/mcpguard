package sandbox

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestFirecracker_VsockFraming(t *testing.T) {
	msg := VsockMessage{
		Type:     "exec",
		Command:  []string{"python3", "-c", "print('hello')"},
		Env:      map[string]string{"ENV_A": "1"},
		Timeout:  5000,
		Stdout:   "hello\n",
		ExitCode: 0,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal vsock message: %v", err)
	}

	var decoded VsockMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal vsock message: %v", err)
	}

	if decoded.Type != "exec" || len(decoded.Command) != 3 || decoded.Stdout != "hello\n" {
		t.Errorf("vsock message framing mismatch: %+v", decoded)
	}
}

func TestFirecracker_WarmPoolLifecycle(t *testing.T) {
	ctx := context.Background()
	driver := NewFirecrackerDriver(FirecrackerOptions{
		PoolSize: 3,
	})
	defer driver.Close()

	if len(driver.pool) != 3 {
		t.Fatalf("expected 3 pre-warmed instances in pool, got %d", len(driver.pool))
	}

	// Acquire from warm pool
	inst1, err := driver.Create(ctx, DefaultLimits())
	if err != nil {
		t.Fatalf("failed to acquire instance 1: %v", err)
	}
	defer inst1.Destroy(ctx)

	if inst1.ID() == "" {
		t.Error("expected non-empty instance ID")
	}

	// Give background goroutine time to re-warm
	time.Sleep(50 * time.Millisecond)

	driver.mu.Lock()
	poolLen := len(driver.pool)
	driver.mu.Unlock()

	if poolLen == 0 {
		t.Errorf("expected pool to be replenished, got %d", poolLen)
	}
}

func TestFirecracker_IsAvailableSafe(t *testing.T) {
	ctx := context.Background()
	driver := NewFirecrackerDriver(FirecrackerOptions{})

	// Must return a boolean without panicking on any OS
	_ = driver.IsAvailable(ctx)
}

func TestFirecracker_Conformance(t *testing.T) {
	driver := NewFirecrackerDriver(FirecrackerOptions{})
	defer driver.Close()

	RunDriverConformanceSuite(t, driver)
}
