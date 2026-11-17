package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/mcp"
)

func TestServer_DiscoverAndToolsList(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})
	ctx := context.Background()

	// 1. server/discover
	reqDiscover := &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"1"`),
		Method:  "server/discover",
	}
	respDiscover := server.HandleRequest(ctx, reqDiscover)
	if respDiscover.Error != nil {
		t.Fatalf("unexpected discover error: %v", respDiscover.Error)
	}

	var discResult struct {
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	_ = json.Unmarshal(respDiscover.Result, &discResult)
	if discResult.ServerInfo.Name != "sentinel-sandbox" {
		t.Errorf("expected server name sentinel-sandbox, got %s", discResult.ServerInfo.Name)
	}

	// 2. tools/list
	reqTools := &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"2"`),
		Method:  "tools/list",
	}
	respTools := server.HandleRequest(ctx, reqTools)
	if respTools.Error != nil {
		t.Fatalf("unexpected tools/list error: %v", respTools.Error)
	}

	var toolList struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(respTools.Result, &toolList)
	if len(toolList.Tools) != 5 {
		t.Fatalf("expected 5 tools, got %d", len(toolList.Tools))
	}

	names := make(map[string]bool)
	for _, tool := range toolList.Tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"run_bash", "run_python", "read_file", "write_file", "reset_session"} {
		if !names[expected] {
			t.Errorf("missing tool in tools/list: %s", expected)
		}
	}
}

func TestServer_RunBash(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})
	ctx := context.Background()

	params, _ := json.Marshal(mcp.ToolCallParams{
		Name: "run_bash",
		Arguments: map[string]any{
			"command": "echo 'sandbox execution ok'",
		},
	})

	req := &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  params,
	}

	resp := server.HandleRequest(ctx, req)
	if resp.Error != nil {
		t.Fatalf("unexpected tool call error: %v", resp.Error)
	}

	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(resp.Result, &res)

	if res.IsError {
		t.Errorf("expected isError false, got true")
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "sandbox execution ok") {
		t.Errorf("expected output to contain 'sandbox execution ok', got: %v", res.Content)
	}
}

func TestServer_MultiStepWorkspacePersistence(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})
	ctx := context.Background()
	sessionID := "sess_calc_test"

	// 1. write_file
	writeParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "write_file",
		Arguments: map[string]any{
			"session_id": sessionID,
			"path":       "/workspace/script.py",
			"content":    "print(2 + 2)\n",
		},
	})
	respWrite := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  writeParams,
	})
	if respWrite.Error != nil {
		t.Fatalf("write_file error: %v", respWrite.Error)
	}

	// 2. read_file in same session
	readParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "read_file",
		Arguments: map[string]any{
			"session_id": sessionID,
			"path":       "/workspace/script.py",
		},
	})
	respRead := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  readParams,
	})
	if respRead.Error != nil {
		t.Fatalf("read_file error: %v", respRead.Error)
	}

	var readRes struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(respRead.Result, &readRes)
	if len(readRes.Content) == 0 || !strings.Contains(readRes.Content[0].Text, "print(2 + 2)") {
		t.Errorf("expected read_file to return script content, got %v", readRes.Content)
	}

	// 3. run_python in same session
	pyParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "run_python",
		Arguments: map[string]any{
			"session_id": sessionID,
			"code":       "print('python result: 4')",
		},
	})
	respPy := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "tools/call",
		Params:  pyParams,
	})
	if respPy.Error != nil {
		t.Fatalf("run_python error: %v", respPy.Error)
	}
	var pyRes struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(respPy.Result, &pyRes)
	if pyRes.IsError || !strings.Contains(pyRes.Content[0].Text, "python result: 4") {
		t.Errorf("expected python output 'python result: 4', got %v", pyRes)
	}
}

func TestServer_SessionBoundaryIsolation(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})
	ctx := context.Background()

	// Write file in session A
	writeParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "write_file",
		Arguments: map[string]any{
			"session_id": "session_A",
			"path":       "/workspace/secret.txt",
			"content":    "top-secret-A",
		},
	})
	_ = server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  writeParams,
	})

	// Try reading file from session B
	readParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "read_file",
		Arguments: map[string]any{
			"session_id": "session_B",
			"path":       "/workspace/secret.txt",
		},
	})
	respRead := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  readParams,
	})

	var readRes struct {
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(respRead.Result, &readRes)
	if !readRes.IsError {
		t.Error("expected reading session_A file from session_B to fail with isError=true")
	}
}

func TestServer_ResetSession(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})
	ctx := context.Background()
	sessionID := "sess_to_reset"

	// Write file
	writeParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "write_file",
		Arguments: map[string]any{
			"session_id": sessionID,
			"path":       "/workspace/temp.txt",
			"content":    "will be deleted",
		},
	})
	_ = server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  writeParams,
	})

	// Reset session
	resetParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "reset_session",
		Arguments: map[string]any{
			"session_id": sessionID,
		},
	})
	respReset := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  resetParams,
	})
	if respReset.Error != nil {
		t.Fatalf("reset_session error: %v", respReset.Error)
	}

	// Reading temp.txt after reset must fail (fresh workspace)
	readParams, _ := json.Marshal(mcp.ToolCallParams{
		Name: "read_file",
		Arguments: map[string]any{
			"session_id": sessionID,
			"path":       "/workspace/temp.txt",
		},
	})
	respRead := server.HandleRequest(ctx, &mcp.Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "tools/call",
		Params:  readParams,
	})

	var readRes struct {
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(respRead.Result, &readRes)
	if !readRes.IsError {
		t.Error("expected reading file after reset to fail")
	}
}

func TestServer_HTTPHandler(t *testing.T) {
	server := NewServer(ServerConfig{Driver: NewMemDriver()})

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp mcp.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error in response: %v", resp.Error)
	}
}
