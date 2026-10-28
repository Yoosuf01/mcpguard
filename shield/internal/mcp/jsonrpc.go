// Package mcp contains the minimal JSON-RPC 2.0 / MCP wire types Sentinel Shield
// needs to inspect traffic. It deliberately keeps unknown fields as raw JSON so
// the gateway never silently drops data it does not understand.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
)

const JSONRPCVersion = "2.0"

// Standard JSON-RPC error codes plus Sentinel-specific codes in the
// implementation-defined server error range (-32000 to -32099).
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603

	CodePolicyDenied    = -32001
	CodePendingApproval = -32002
	CodeUnauthorized    = -32003
	CodeUpstream        = -32004
	CodeHeaderMismatch  = -32005
)

var (
	ErrBatchNotSupported = errors.New("JSON-RPC batching is not supported by MCP (removed in 2025-06-18)")
	ErrInvalidRequest    = errors.New("invalid JSON-RPC 2.0 request")
)

// Request is a JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the message has no id (no response expected).
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ToolCallParams are the params of a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments map[string]any  `json:"arguments,omitempty"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

// ParseRequest decodes and validates a single JSON-RPC request.
func ParseRequest(body []byte) (*Request, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, ErrBatchNotSupported
	}
	var r Request
	if err := json.Unmarshal(trimmed, &r); err != nil {
		return nil, err
	}
	if r.JSONRPC != JSONRPCVersion || r.Method == "" {
		return nil, ErrInvalidRequest
	}
	return &r, nil
}

// NewResult builds a success response.
func NewResult(id json.RawMessage, result any) *Response {
	b, err := json.Marshal(result)
	if err != nil {
		return NewError(id, CodeInternal, "failed to encode result", nil)
	}
	return &Response{JSONRPC: JSONRPCVersion, ID: normID(id), Result: b}
}

// NewError builds an error response.
func NewError(id json.RawMessage, code int, msg string, data any) *Response {
	return &Response{JSONRPC: JSONRPCVersion, ID: normID(id), Error: &Error{Code: code, Message: msg, Data: data}}
}

// ToolErrorResult builds a CallToolResult with isError=true. MCP recommends
// reporting tool-level failures inside the result (not as protocol errors) so
// the model can see why the call failed and adapt instead of retrying blindly.
func ToolErrorResult(text string, meta map[string]any) map[string]any {
	res := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": true,
	}
	if meta != nil {
		res["_meta"] = meta
	}
	return res
}

func normID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
