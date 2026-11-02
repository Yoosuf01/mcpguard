// Package stdio manages local MCP servers launched as supervised child processes
// communicating over stdin/stdout with environment variable allowlisting and restart policies.
package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/mcp"
)

var (
	ErrProcessClosed  = errors.New("stdio process closed")
	ErrCommandMissing = errors.New("command is required")
)

type Config struct {
	Command       string   `yaml:"command"`
	Args          []string `yaml:"args"`
	Env           []string `yaml:"env"`            // Allowed env var names (or "KEY=val" explicit pairs)
	RestartPolicy string   `yaml:"restart_policy"` // "always", "on_failure", "never"
	WorkingDir    string   `yaml:"working_dir"`
	Timeout       time.Duration
}

type Process struct {
	cfg     Config
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	closed  atomic.Bool
	seq     atomic.Int64
	running bool
}

func NewProcess(cfg Config) *Process {
	if cfg.RestartPolicy == "" {
		cfg.RestartPolicy = "on_failure"
	}
	return &Process{cfg: cfg}
}

// Start launches the child process if not already running.
func (p *Process) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return ErrProcessClosed
	}
	if p.running && p.cmd != nil && p.cmd.Process != nil {
		return nil
	}
	return p.startLocked(ctx)
}

func (p *Process) startLocked(ctx context.Context) error {
	if p.cfg.Command == "" {
		return ErrCommandMissing
	}

	cmd := exec.CommandContext(ctx, p.cfg.Command, p.cfg.Args...)
	if p.cfg.WorkingDir != "" {
		cmd.Dir = p.cfg.WorkingDir
	}

	// Environment Allowlist - NEVER leak host credentials (AWS, GitHub, Sentinel secret) wholesale.
	cleanEnv := p.filterEnv(p.cfg.Env)
	cmd.Env = cleanEnv

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return fmt.Errorf("process start: %w", err)
	}

	p.cmd = cmd
	p.stdin = stdin
	p.stdout = bufio.NewScanner(stdout)
	p.stdout.Buffer(make([]byte, 64<<10), 8<<20) // up to 8 MiB per JSON line
	p.running = true
	return nil
}

// Call executes a single JSON-RPC call over stdin/stdout.
func (p *Process) Call(ctx context.Context, method string, params any) (*mcp.Response, error) {
	if p.closed.Load() {
		return nil, ErrProcessClosed
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running || p.cmd == nil {
		if err := p.startLocked(ctx); err != nil {
			return nil, err
		}
	}

	id := json.RawMessage(fmt.Sprintf(`"stdio-%d"`, p.seq.Add(1)))
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}

	rawReq, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	rawReq = append(rawReq, '\n')

	if _, err := p.stdin.Write(rawReq); err != nil {
		p.running = false
		if p.cfg.RestartPolicy != "never" {
			if startErr := p.startLocked(ctx); startErr == nil {
				if _, retryErr := p.stdin.Write(rawReq); retryErr == nil {
					return p.readResponseLocked(id)
				}
			}
		}
		return nil, fmt.Errorf("stdin write: %w", err)
	}

	resp, err := p.readResponseLocked(id)
	if err != nil && p.cfg.RestartPolicy != "never" {
		// Child might have exited right after writing or during; retry once
		if startErr := p.startLocked(ctx); startErr == nil {
			if _, retryErr := p.stdin.Write(rawReq); retryErr == nil {
				return p.readResponseLocked(id)
			}
		}
	}
	return resp, err
}

func (p *Process) readResponseLocked(targetID json.RawMessage) (*mcp.Response, error) {
	for p.stdout.Scan() {
		line := bytes.TrimSpace(p.stdout.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp mcp.Response
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(resp.ID), bytes.TrimSpace(targetID)) {
			return &resp, nil
		}
	}
	if err := p.stdout.Err(); err != nil {
		p.running = false
		return nil, fmt.Errorf("stdout read: %w", err)
	}
	p.running = false
	return nil, io.EOF
}

func (p *Process) Close() error {
	p.closed.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
	var err error
	if p.stdin != nil {
		_ = p.stdin.Close()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	return err
}

func (p *Process) filterEnv(allowlist []string) []string {
	safeDefaults := []string{"PATH", "HOME", "USER", "LANG", "TMPDIR"}
	allowedMap := make(map[string]bool)
	for _, k := range safeDefaults {
		allowedMap[k] = true
	}
	var explicitPairs []string
	for _, item := range allowlist {
		if strings.Contains(item, "=") {
			explicitPairs = append(explicitPairs, item)
		} else {
			allowedMap[item] = true
		}
	}

	var out []string
	for _, env := range os.Environ() {
		k, _, ok := strings.Cut(env, "=")
		if ok && allowedMap[k] {
			out = append(out, env)
		}
	}
	out = append(out, explicitPairs...)
	return out
}
