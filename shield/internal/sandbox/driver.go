// Package sandbox provides container and microVM execution isolation for AI agents,
// enforcing strict cgroups resource limits, seccomp filtering, dropped Linux capabilities,
// read-only root filesystems, and network namespace containment.
package sandbox

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	// ErrTimeout is returned when an execution exceeds its hard wall-clock deadline.
	ErrTimeout = errors.New("sandbox: execution timed out")
	// ErrDestroyed is returned when attempting an operation on a destroyed instance.
	ErrDestroyed = errors.New("sandbox: instance already destroyed")
	// ErrReadOnlyFS is returned when an attempt is made to write outside allowed workspace.
	ErrReadOnlyFS = errors.New("sandbox: read-only file system violation")
	// ErrNetworkBlocked is returned when network access is attempted under --network none.
	ErrNetworkBlocked = errors.New("sandbox: network access blocked by sandbox isolation")
	// ErrProcessLimit is returned when process exhaustion or fork bomb exceeds limits.
	ErrProcessLimit = errors.New("sandbox: process limit exceeded")
)

// Limits specifies the resource and execution constraints for a sandbox instance.
type Limits struct {
	CPUs         float64       // CPU cores allocation (e.g. 1.0)
	MemoryBytes  int64         // Maximum memory in bytes (e.g. 256 * 1024 * 1024)
	MaxProcesses int64         // Maximum concurrent processes / threads (pids cgroup)
	Timeout      time.Duration // Maximum wall-clock execution time per command
	WorkdirBytes int64         // Ephemeral tmpfs workspace limit in bytes
}

// DefaultLimits returns conservative default resource boundaries.
func DefaultLimits() Limits {
	return Limits{
		CPUs:         1.0,
		MemoryBytes:  256 * 1024 * 1024, // 256 MB
		MaxProcesses: 64,                // prevent fork bombs
		Timeout:      30 * time.Second,
		WorkdirBytes: 100 * 1024 * 1024, // 100 MB
	}
}

// ExecOptions specifies the parameters for running a command inside a sandbox.
type ExecOptions struct {
	Command []string          // Command and arguments, e.g. ["python3", "-c", "print('hello')"]
	Stdin   io.Reader         // Standard input stream (optional)
	Timeout time.Duration     // Per-command timeout (falls back to Limits.Timeout if zero)
	Env     map[string]string // Custom environment variables (allowlisted only)
	Workdir string            // Working directory (defaults to /workspace)
}

// ExecResult captures the output, exit status, and duration of an execution.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Instance represents an active, isolated sandbox environment.
type Instance interface {
	// ID returns the unique identifier of the sandbox instance.
	ID() string
	// Exec runs a command within the isolated instance subject to limits.
	Exec(ctx context.Context, opts ExecOptions) (*ExecResult, error)
	// ReadFile reads the contents of a file within the sandbox workspace.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// WriteFile writes data to a file within the sandbox workspace.
	WriteFile(ctx context.Context, path string, data []byte) error
	// Destroy terminates and removes the sandbox instance and its ephemeral workspace.
	Destroy(ctx context.Context) error
}

// Driver creates and manages sandboxed execution instances.
type Driver interface {
	// Name returns the driver identifier (e.g. "docker", "firecracker", "mem").
	Name() string
	// Create initializes a new isolated sandbox instance.
	Create(ctx context.Context, limits Limits) (Instance, error)
}
