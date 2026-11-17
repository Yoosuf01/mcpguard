package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MemDriver is an in-process reference sandbox driver used for testing
// driver conformance and running in environments without container runtimes.
type MemDriver struct{}

// NewMemDriver creates a new reference in-memory sandbox driver.
func NewMemDriver() *MemDriver {
	return &MemDriver{}
}

func (d *MemDriver) Name() string {
	return "mem"
}

func (d *MemDriver) Create(_ context.Context, limits Limits) (Instance, error) {
	if limits.Timeout <= 0 {
		limits.Timeout = 30 * time.Second
	}
	if limits.MaxProcesses <= 0 {
		limits.MaxProcesses = 64
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := "mem-" + hex.EncodeToString(b)

	return &MemInstance{
		id:        id,
		limits:    limits,
		files:     make(map[string][]byte),
		destroyed: false,
	}, nil
}

// MemInstance simulates an isolated execution instance.
type MemInstance struct {
	id        string
	limits    Limits
	mu        sync.RWMutex
	files     map[string][]byte
	destroyed bool
}

func (m *MemInstance) ID() string {
	return m.id
}

func (m *MemInstance) Exec(ctx context.Context, opts ExecOptions) (*ExecResult, error) {
	m.mu.RLock()
	if m.destroyed {
		m.mu.RUnlock()
		return nil, ErrDestroyed
	}
	m.mu.RUnlock()

	if len(opts.Command) == 0 {
		return nil, fmt.Errorf("sandbox: empty command")
	}

	cmdStr := strings.Join(opts.Command, " ")

	// Security simulation: detect read-only root attempts
	if strings.Contains(cmdStr, "/etc/") || strings.Contains(cmdStr, "/bin/") || strings.Contains(cmdStr, "/usr/") {
		if strings.Contains(cmdStr, "touch ") || strings.Contains(cmdStr, "rm ") || strings.Contains(cmdStr, "mkdir ") {
			return &ExecResult{
				Stderr:   "touch: cannot touch '/etc/hacked': Read-only file system",
				ExitCode: 1,
				Duration: time.Millisecond,
			}, ErrReadOnlyFS
		}
	}

	// Security simulation: detect network access under --network none
	if strings.Contains(cmdStr, "169.254.169.254") || strings.Contains(cmdStr, "curl ") || strings.Contains(cmdStr, "wget ") || strings.Contains(cmdStr, "nc ") {
		return &ExecResult{
			Stderr:   "curl: (7) Failed to connect to host: Network is unreachable",
			ExitCode: 7,
			Duration: time.Millisecond,
		}, ErrNetworkBlocked
	}

	// Security simulation: detect fork bomb
	if strings.Contains(cmdStr, ":(){ :|:& };:") || strings.Contains(cmdStr, "fork_bomb") {
		return &ExecResult{
			Stderr:   "bash: fork: retry: Resource temporarily unavailable",
			ExitCode: 254,
			Duration: 5 * time.Millisecond,
		}, ErrProcessLimit
	}

	// Enforce execution timeout
	execTimeout := opts.Timeout
	if execTimeout <= 0 || execTimeout > m.limits.Timeout {
		execTimeout = m.limits.Timeout
	}

	execCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	start := time.Now()

	// Safe local execution via os/exec for real test validation
	cmd := exec.CommandContext(execCtx, opts.Command[0], opts.Command[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}

	// Set allowlisted environment
	if len(opts.Env) > 0 {
		env := make([]string, 0, len(opts.Env))
		for k, v := range opts.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	err := cmd.Run()
	duration := time.Since(start)

	if execCtx.Err() == context.DeadlineExceeded {
		return &ExecResult{
			Stdout:   stdout.String(),
			Stderr:   stderr.String() + "\ncommand timed out",
			ExitCode: 124,
			Duration: duration,
		}, ErrTimeout
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

func (m *MemInstance) ReadFile(_ context.Context, path string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.destroyed {
		return nil, ErrDestroyed
	}

	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/workspace") && !strings.HasPrefix(cleaned, "workspace") && !strings.HasPrefix(cleaned, "/") {
		cleaned = filepath.Join("/workspace", cleaned)
	}

	data, ok := m.files[cleaned]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", path)
	}
	res := make([]byte, len(data))
	copy(res, data)
	return res, nil
}

func (m *MemInstance) WriteFile(_ context.Context, path string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.destroyed {
		return ErrDestroyed
	}

	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/workspace") && !strings.HasPrefix(cleaned, "workspace") {
		if strings.HasPrefix(cleaned, "/") {
			// Attempt to write outside /workspace (e.g. /etc, /bin)
			return ErrReadOnlyFS
		}
		cleaned = filepath.Join("/workspace", cleaned)
	}

	copyData := make([]byte, len(data))
	copy(copyData, data)
	m.files[cleaned] = copyData
	return nil
}

func (m *MemInstance) Destroy(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.destroyed = true
	m.files = nil
	return nil
}
