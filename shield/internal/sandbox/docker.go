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

// DockerOptions configures the Docker container isolation driver.
type DockerOptions struct {
	Image        string // Base container image (default: "alpine:latest")
	DockerBin    string // Path to docker binary (default: "docker")
	WorkspaceDir string // Ephemeral tmpfs workspace inside container (default: "/workspace")
}

// DockerDriver manages hardened container lifecycles via the Docker CLI/engine.
type DockerDriver struct {
	opts DockerOptions
}

// NewDockerDriver creates a new Docker sandbox driver.
func NewDockerDriver(opts DockerOptions) *DockerDriver {
	if opts.Image == "" {
		opts.Image = "alpine:latest"
	}
	if opts.DockerBin == "" {
		opts.DockerBin = "docker"
	}
	if opts.WorkspaceDir == "" {
		opts.WorkspaceDir = "/workspace"
	}
	return &DockerDriver{opts: opts}
}

func (d *DockerDriver) Name() string {
	return "docker"
}

// IsAvailable checks if the Docker daemon is responsive.
func (d *DockerDriver) IsAvailable(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(checkCtx, d.opts.DockerBin, "info")
	return cmd.Run() == nil
}

// BuildRunArgs constructs the full argument slice for `docker run` enforcing all security flags.
func (d *DockerDriver) BuildRunArgs(id string, limits Limits) []string {
	if limits.WorkdirBytes <= 0 {
		limits.WorkdirBytes = 100 * 1024 * 1024 // 100 MB default
	}
	if limits.MaxProcesses <= 0 {
		limits.MaxProcesses = 64
	}
	if limits.MemoryBytes <= 0 {
		limits.MemoryBytes = 256 * 1024 * 1024 // 256 MB default
	}
	if limits.CPUs <= 0 {
		limits.CPUs = 1.0
	}

	args := []string{
		"run",
		"-d",
		"--name", id,
		// Zero-network namespace isolation
		"--network", "none",
		// Read-only root filesystem
		"--read-only",
		// Drop all Linux kernel capabilities
		"--cap-drop", "ALL",
		// Prevent privilege escalation via setuid
		"--security-opt", "no-new-privileges",
		// In-memory ephemeral tmpfs workspace
		fmt.Sprintf("--tmpfs=%s:rw,noexec=false,size=%d", d.opts.WorkspaceDir, limits.WorkdirBytes),
		// Pids cgroup limit (contains fork bombs)
		fmt.Sprintf("--pids-limit=%d", limits.MaxProcesses),
		// Memory and CPU resource constraints
		fmt.Sprintf("--memory=%d", limits.MemoryBytes),
		fmt.Sprintf("--cpus=%.2f", limits.CPUs),
		"-w", d.opts.WorkspaceDir,
		d.opts.Image,
		"sleep", "infinity",
	}

	return args
}

// Create launches a new hardened container instance.
func (d *DockerDriver) Create(ctx context.Context, limits Limits) (Instance, error) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := fmt.Sprintf("mcpguard-sbx-%s", hex.EncodeToString(b))

	args := d.BuildRunArgs(id, limits)
	cmd := exec.CommandContext(ctx, d.opts.DockerBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker run failed: %w (stderr: %s)", err, stderr.String())
	}

	return &DockerInstance{
		id:     id,
		driver: d,
		limits: limits,
	}, nil
}

// DockerInstance manages an active hardened container sandbox.
type DockerInstance struct {
	id        string
	driver    *DockerDriver
	limits    Limits
	mu        sync.RWMutex
	destroyed bool
}

func (i *DockerInstance) ID() string {
	return i.id
}

func (i *DockerInstance) Exec(ctx context.Context, opts ExecOptions) (*ExecResult, error) {
	i.mu.RLock()
	if i.destroyed {
		i.mu.RUnlock()
		return nil, ErrDestroyed
	}
	i.mu.RUnlock()

	if len(opts.Command) == 0 {
		return nil, fmt.Errorf("sandbox: empty command")
	}

	execTimeout := opts.Timeout
	if execTimeout <= 0 || execTimeout > i.limits.Timeout {
		execTimeout = i.limits.Timeout
	}

	execCtx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	workdir := opts.Workdir
	if workdir == "" {
		workdir = i.driver.opts.WorkspaceDir
	}

	args := []string{"exec", "-i", "-w", workdir}
	for k, v := range opts.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}
	args = append(args, i.id)
	args = append(args, opts.Command...)

	start := time.Now()
	cmd := exec.CommandContext(execCtx, i.driver.opts.DockerBin, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
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

	errStr := stderr.String()
	res := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   errStr,
		ExitCode: exitCode,
		Duration: duration,
	}

	// Classify container kernel error signatures
	if strings.Contains(errStr, "Read-only file system") {
		return res, ErrReadOnlyFS
	}
	if strings.Contains(errStr, "Resource temporarily unavailable") || strings.Contains(errStr, "fork: retry") || strings.Contains(errStr, "can't fork") {
		return res, ErrProcessLimit
	}
	if strings.Contains(errStr, "Network is unreachable") || strings.Contains(errStr, "Failed to connect") || strings.Contains(errStr, "Could not resolve") {
		return res, ErrNetworkBlocked
	}

	return res, nil
}

func (i *DockerInstance) cleanPath(p string) (string, error) {
	cleaned := filepath.Clean(p)
	ws := i.driver.opts.WorkspaceDir
	if !strings.HasPrefix(cleaned, ws) && !strings.HasPrefix(cleaned, strings.TrimPrefix(ws, "/")) {
		if strings.HasPrefix(cleaned, "/") {
			return "", ErrReadOnlyFS
		}
		cleaned = filepath.Join(ws, cleaned)
	}
	return cleaned, nil
}

func (i *DockerInstance) ReadFile(ctx context.Context, path string) ([]byte, error) {
	i.mu.RLock()
	if i.destroyed {
		i.mu.RUnlock()
		return nil, ErrDestroyed
	}
	i.mu.RUnlock()

	target, err := i.cleanPath(path)
	if err != nil {
		return nil, err
	}

	res, err := i.Exec(ctx, ExecOptions{
		Command: []string{"cat", target},
	})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("read file failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	return []byte(res.Stdout), nil
}

func (i *DockerInstance) WriteFile(ctx context.Context, path string, data []byte) error {
	i.mu.RLock()
	if i.destroyed {
		i.mu.RUnlock()
		return ErrDestroyed
	}
	i.mu.RUnlock()

	target, err := i.cleanPath(path)
	if err != nil {
		return err
	}

	res, err := i.Exec(ctx, ExecOptions{
		Command: []string{"sh", "-c", fmt.Sprintf("cat > '%s'", target)},
		Stdin:   bytes.NewReader(data),
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("write file failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	return nil
}

func (i *DockerInstance) Destroy(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.destroyed {
		return nil
	}

	destroyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(destroyCtx, i.driver.opts.DockerBin, "rm", "-f", i.id)
	_ = cmd.Run()

	i.destroyed = true
	return nil
}
