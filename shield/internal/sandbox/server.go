package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/mcp"
)

// ServerConfig configures the Sandbox MCP Server.
type ServerConfig struct {
	Driver     Driver
	Limits     Limits
	SessionTTL time.Duration
}

type sessionEntry struct {
	instance Instance
	lastSeen time.Time
}

// Server implements an MCP upstream server providing isolated sandbox execution.
type Server struct {
	driver     Driver
	limits     Limits
	sessionTTL time.Duration

	mu       sync.Mutex
	sessions map[string]*sessionEntry
}

// NewServer creates a new Sandbox MCP Server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Driver == nil {
		cfg.Driver = NewMemDriver()
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * time.Minute
	}
	if cfg.Limits.Timeout <= 0 {
		cfg.Limits = DefaultLimits()
	}

	return &Server{
		driver:     cfg.Driver,
		limits:     cfg.Limits,
		sessionTTL: cfg.SessionTTL,
		sessions:   make(map[string]*sessionEntry),
	}
}

func (s *Server) getOrCreateInstance(ctx context.Context, sessionID string) (Instance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}

	now := time.Now()
	// Check existing session
	if entry, ok := s.sessions[sessionID]; ok {
		if now.Sub(entry.lastSeen) < s.sessionTTL {
			entry.lastSeen = now
			return entry.instance, nil
		}
		// Session expired, clean up
		_ = entry.instance.Destroy(ctx)
		delete(s.sessions, sessionID)
	}

	// Create new sandbox instance
	inst, err := s.driver.Create(ctx, s.limits)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox instance: %w", err)
	}

	s.sessions[sessionID] = &sessionEntry{
		instance: inst,
		lastSeen: now,
	}

	return inst, nil
}

func (s *Server) resetSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}

	if entry, ok := s.sessions[sessionID]; ok {
		_ = entry.instance.Destroy(ctx)
		delete(s.sessions, sessionID)
	}
	return nil
}

// ServeHTTP handles incoming MCP JSON-RPC requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(mcp.NewError(nil, mcp.CodeInvalidRequest, "POST method required", nil))
		return
	}

	var req mcp.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(mcp.NewError(nil, mcp.CodeParseError, "failed to parse JSON-RPC request", nil))
		return
	}

	resp := s.HandleRequest(r.Context(), &req)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleRequest processes an MCP JSON-RPC request and returns the response.
func (s *Server) HandleRequest(ctx context.Context, req *mcp.Request) *mcp.Response {
	switch req.Method {
	case "initialize", "server/discover":
		return mcp.NewResult(req.ID, map[string]any{
			"protocolVersion": "2026-07-28",
			"serverInfo": map[string]any{
				"name":    "sentinel-sandbox",
				"version": "0.1.0",
			},
			"instructions": "Tools execute code and manipulate files inside an isolated, unprivileged compute sandbox. Outputs are strictly contained.",
			"capabilities": map[string]any{
				"tools": map[string]any{
					"listChanged": false,
				},
			},
		})

	case "tools/list":
		return mcp.NewResult(req.ID, map[string]any{
			"tools": s.toolDefinitions(),
		})

	case "tools/call":
		var params mcp.ToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return mcp.NewError(req.ID, mcp.CodeInvalidParams, "invalid tool call params", nil)
		}
		return s.handleToolCall(ctx, req.ID, params)

	case "ping":
		return mcp.NewResult(req.ID, map[string]any{})

	default:
		return mcp.NewError(req.ID, mcp.CodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method), nil)
	}
}

func (s *Server) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "run_bash",
			"description": "Execute a bash or shell command within an isolated unprivileged sandbox.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command":         map[string]any{"type": "string", "description": "Shell command to run"},
					"session_id":      map[string]any{"type": "string", "description": "Optional session identifier to maintain workspace across commands"},
					"timeout_seconds": map[string]any{"type": "number", "description": "Optional execution timeout in seconds"},
					"env":             map[string]any{"type": "object", "description": "Optional environment variables"},
				},
				"required": []string{"command"},
			},
		},
		{
			"name":        "run_python",
			"description": "Execute Python 3 code within an isolated unprivileged sandbox.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code":            map[string]any{"type": "string", "description": "Python source code to execute"},
					"session_id":      map[string]any{"type": "string", "description": "Optional session identifier to maintain workspace across commands"},
					"timeout_seconds": map[string]any{"type": "number", "description": "Optional execution timeout in seconds"},
					"env":             map[string]any{"type": "object", "description": "Optional environment variables"},
				},
				"required": []string{"code"},
			},
		},
		{
			"name":        "read_file",
			"description": "Read a file from the ephemeral sandbox workspace.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":       map[string]any{"type": "string", "description": "Path to file inside workspace"},
					"session_id": map[string]any{"type": "string", "description": "Optional session identifier"},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "write_file",
			"description": "Write a file into the ephemeral sandbox workspace.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":       map[string]any{"type": "string", "description": "Path to file inside workspace"},
					"content":    map[string]any{"type": "string", "description": "Content to write"},
					"session_id": map[string]any{"type": "string", "description": "Optional session identifier"},
				},
				"required": []string{"path", "content"},
			},
		},
		{
			"name":        "reset_session",
			"description": "Destroy the sandbox instance and discard all ephemeral workspace files for a session.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"session_id": map[string]any{"type": "string", "description": "Session identifier to reset"},
				},
				"required": []string{"session_id"},
			},
		},
	}
}

func (s *Server) handleToolCall(ctx context.Context, id json.RawMessage, params mcp.ToolCallParams) *mcp.Response {
	sessionID, _ := params.Arguments["session_id"].(string)

	switch params.Name {
	case "run_bash":
		cmdStr, ok := params.Arguments["command"].(string)
		if !ok || strings.TrimSpace(cmdStr) == "" {
			return mcp.NewResult(id, mcp.ToolErrorResult("command argument is required", nil))
		}

		inst, err := s.getOrCreateInstance(ctx, sessionID)
		if err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(err.Error(), nil))
		}

		opts := ExecOptions{
			Command: []string{"sh", "-c", cmdStr},
			Env:     extractEnv(params.Arguments["env"]),
			Timeout: extractTimeout(params.Arguments["timeout_seconds"]),
		}

		res, err := inst.Exec(ctx, opts)
		return formatExecResponse(id, res, err)

	case "run_python":
		code, ok := params.Arguments["code"].(string)
		if !ok || strings.TrimSpace(code) == "" {
			return mcp.NewResult(id, mcp.ToolErrorResult("code argument is required", nil))
		}

		inst, err := s.getOrCreateInstance(ctx, sessionID)
		if err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(err.Error(), nil))
		}

		opts := ExecOptions{
			Command: []string{"python3", "-c", code},
			Env:     extractEnv(params.Arguments["env"]),
			Timeout: extractTimeout(params.Arguments["timeout_seconds"]),
		}

		res, err := inst.Exec(ctx, opts)
		return formatExecResponse(id, res, err)

	case "read_file":
		path, ok := params.Arguments["path"].(string)
		if !ok || strings.TrimSpace(path) == "" {
			return mcp.NewResult(id, mcp.ToolErrorResult("path argument is required", nil))
		}

		inst, err := s.getOrCreateInstance(ctx, sessionID)
		if err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(err.Error(), nil))
		}

		data, err := inst.ReadFile(ctx, path)
		if err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(fmt.Sprintf("read error: %v", err), nil))
		}

		return mcp.NewResult(id, map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": string(data)},
			},
			"isError": false,
		})

	case "write_file":
		path, ok := params.Arguments["path"].(string)
		if !ok || strings.TrimSpace(path) == "" {
			return mcp.NewResult(id, mcp.ToolErrorResult("path argument is required", nil))
		}
		content, ok := params.Arguments["content"].(string)
		if !ok {
			return mcp.NewResult(id, mcp.ToolErrorResult("content argument is required", nil))
		}

		inst, err := s.getOrCreateInstance(ctx, sessionID)
		if err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(err.Error(), nil))
		}

		if err := inst.WriteFile(ctx, path, []byte(content)); err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(fmt.Sprintf("write error: %v", err), nil))
		}

		return mcp.NewResult(id, map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": fmt.Sprintf("file written successfully: %s (%d bytes)", path, len(content))},
			},
			"isError": false,
		})

	case "reset_session":
		if sessionID == "" {
			return mcp.NewResult(id, mcp.ToolErrorResult("session_id argument is required", nil))
		}
		if err := s.resetSession(ctx, sessionID); err != nil {
			return mcp.NewResult(id, mcp.ToolErrorResult(err.Error(), nil))
		}
		return mcp.NewResult(id, map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": fmt.Sprintf("session %s reset and workspace cleared", sessionID)},
			},
			"isError": false,
		})

	default:
		return mcp.NewError(id, mcp.CodeInvalidParams, fmt.Sprintf("unknown tool: %s", params.Name), nil)
	}
}

func extractEnv(v any) map[string]string {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	res := make(map[string]string)
	for k, val := range m {
		res[k] = fmt.Sprint(val)
	}
	return res
}

func extractTimeout(v any) time.Duration {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return time.Duration(n * float64(time.Second))
	case int:
		return time.Duration(n) * time.Second
	case int64:
		return time.Duration(n) * time.Second
	default:
		return 0
	}
}

func formatExecResponse(id json.RawMessage, res *ExecResult, err error) *mcp.Response {
	if err != nil {
		msg := err.Error()
		if res != nil && res.Stderr != "" {
			msg = fmt.Sprintf("%s\n%s", msg, res.Stderr)
		}
		return mcp.NewResult(id, mcp.ToolErrorResult(msg, nil))
	}

	if res.ExitCode != 0 {
		output := res.Stdout
		if res.Stderr != "" {
			output += "\n" + res.Stderr
		}
		return mcp.NewResult(id, map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": fmt.Sprintf("exit code %d\n%s", res.ExitCode, output)},
			},
			"isError": true,
		})
	}

	output := res.Stdout
	if output == "" && res.Stderr != "" {
		output = res.Stderr
	}

	return mcp.NewResult(id, map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": output},
		},
		"isError": false,
	})
}
