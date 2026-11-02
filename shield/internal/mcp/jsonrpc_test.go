package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseRequest_ValidRequest(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calculator","arguments":{"a":5,"b":10}}}`
	req, err := ParseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}
	if req.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", req.JSONRPC)
	}
	if string(req.ID) != "1" {
		t.Errorf("expected id 1, got %s", string(req.ID))
	}
	if req.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %s", req.Method)
	}
	if req.IsNotification() {
		t.Error("expected IsNotification to be false")
	}

	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
	if params.Name != "calculator" {
		t.Errorf("expected tool name calculator, got %s", params.Name)
	}
}

func TestParseRequest_Notification(t *testing.T) {
	// No ID field
	raw := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}`
	req, err := ParseRequest([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}
	if !req.IsNotification() {
		t.Error("expected IsNotification to be true when id is omitted")
	}

	// Null ID
	rawNull := `{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}`
	reqNull, err := ParseRequest([]byte(rawNull))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}
	if !reqNull.IsNotification() {
		t.Error("expected IsNotification to be true when id is null")
	}
}

func TestParseRequest_BatchRejection(t *testing.T) {
	rawBatch := `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`
	_, err := ParseRequest([]byte(rawBatch))
	if err != ErrBatchNotSupported {
		t.Fatalf("expected ErrBatchNotSupported for batch request, got %v", err)
	}
}

func TestParseRequest_InvalidRequests(t *testing.T) {
	// Wrong version
	rawBadVersion := `{"jsonrpc":"1.0","id":1,"method":"ping"}`
	if _, err := ParseRequest([]byte(rawBadVersion)); err != ErrInvalidRequest {
		t.Errorf("expected ErrInvalidRequest for jsonrpc 1.0, got %v", err)
	}

	// Missing method
	rawNoMethod := `{"jsonrpc":"2.0","id":1}`
	if _, err := ParseRequest([]byte(rawNoMethod)); err != ErrInvalidRequest {
		t.Errorf("expected ErrInvalidRequest for missing method, got %v", err)
	}

	// Malformed JSON
	rawMalformed := `{"jsonrpc": 2.0`
	if _, err := ParseRequest([]byte(rawMalformed)); err == nil {
		t.Error("expected syntax error for malformed json")
	}
}

func TestNewResultAndNewError(t *testing.T) {
	id := json.RawMessage(`"req-42"`)

	// NewResult
	res := NewResult(id, map[string]string{"status": "ok"})
	if res.JSONRPC != JSONRPCVersion {
		t.Errorf("expected jsonrpc 2.0, got %s", res.JSONRPC)
	}
	if string(res.ID) != string(id) {
		t.Errorf("expected id %s, got %s", id, res.ID)
	}
	if string(res.Result) != `{"status":"ok"}` {
		t.Errorf("unexpected result: %s", string(res.Result))
	}

	// NewError
	errRes := NewError(id, CodePolicyDenied, "blocked by policy", map[string]string{"rule": "step_limit"})
	if errRes.Error == nil {
		t.Fatal("expected non-nil Error")
	}
	if errRes.Error.Code != CodePolicyDenied {
		t.Errorf("expected code %d, got %d", CodePolicyDenied, errRes.Error.Code)
	}
	if errRes.Error.Message != "blocked by policy" {
		t.Errorf("expected message blocked by policy, got %s", errRes.Error.Message)
	}
}

func TestToolErrorResult(t *testing.T) {
	res := ToolErrorResult("Command failed with exit code 1", map[string]any{"exit_code": 1})
	if res["isError"] != true {
		t.Errorf("expected isError=true, got %v", res["isError"])
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("expected non-empty content array")
	}
	firstBlock, ok := content[0].(map[string]any)
	if !ok || firstBlock["text"] != "Command failed with exit code 1" {
		t.Errorf("unexpected content block: %v", firstBlock)
	}
	meta, ok := res["_meta"].(map[string]any)
	if !ok || meta["exit_code"] != 1 {
		t.Errorf("unexpected _meta: %v", meta)
	}
}
