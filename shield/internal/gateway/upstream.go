package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/your-org/sentinel/shield/internal/mcp"
)

// Protocol revisions Shield knows how to speak upstream.
const (
	ProtoStateless = "2026-07-28" // no initialize, no Mcp-Session-Id, routing headers
	ProtoLegacy    = "2025-06-18" // initialize handshake + Mcp-Session-Id (also used for 2025-11-25)
)

// Backend is one upstream MCP server (Streamable HTTP transport).
type Backend struct {
	Name     string            `yaml:"name"`     // namespace prefix; also the verified server identity
	URL      string            `yaml:"url"`      // e.g. http://localhost:9001/mcp
	Protocol string            `yaml:"protocol"` // "2026-07-28" (default) or "2025-06-18"
	Headers  map[string]string `yaml:"headers"`  // upstream credentials; NEVER the client's token
	Timeout  time.Duration     `yaml:"timeout"`

	mu           sync.Mutex
	sessionID    string
	instructions string
	infoLoaded   bool
	nextID       atomic.Int64
	failures     atomic.Int32
	openUntil    atomic.Int64 // circuit breaker: unix nanos
}

var errCircuitOpen = errors.New("upstream circuit open")

type upstream struct {
	client *http.Client
}

func (u *upstream) id(b *Backend) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`"sentinel-%d"`, b.nextID.Add(1)))
}

// call sends one JSON-RPC request upstream and returns the decoded response.
func (u *upstream) call(ctx context.Context, b *Backend, method string, params any, name string) (*mcp.Response, error) {
	if until := b.openUntil.Load(); until > 0 && time.Now().UnixNano() < until {
		return nil, errCircuitOpen
	}
	if b.Protocol == ProtoLegacy && method != "initialize" {
		if err := u.ensureSession(ctx, b); err != nil {
			return nil, err
		}
	}
	resp, status, err := u.do(ctx, b, method, params, name)
	if b.Protocol == ProtoLegacy && status == http.StatusNotFound && method != "initialize" {
		// Session expired upstream: re-initialize once.
		b.mu.Lock()
		b.sessionID, b.infoLoaded = "", false
		b.mu.Unlock()
		if err := u.ensureSession(ctx, b); err != nil {
			return nil, err
		}
		resp, _, err = u.do(ctx, b, method, params, name)
	}
	if err != nil {
		if b.failures.Add(1) >= 5 {
			b.openUntil.Store(time.Now().Add(30 * time.Second).UnixNano())
			b.failures.Store(0)
		}
		return nil, err
	}
	b.failures.Store(0)
	return resp, nil
}

func (u *upstream) do(ctx context.Context, b *Backend, method string, params any, name string) (*mcp.Response, int, error) {
	id := u.id(b)
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	body, _ := json.Marshal(req)
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json, text/event-stream")
	proto := b.Protocol
	if proto == "" {
		proto = ProtoStateless
	}
	hreq.Header.Set("MCP-Protocol-Version", proto)
	if proto == ProtoStateless {
		hreq.Header.Set("Mcp-Method", method)
		if name != "" {
			hreq.Header.Set("Mcp-Name", name)
		}
	}
	b.mu.Lock()
	if b.sessionID != "" {
		hreq.Header.Set("Mcp-Session-Id", b.sessionID)
	}
	b.mu.Unlock()
	for k, v := range b.Headers {
		hreq.Header.Set(k, v)
	}
	hres, err := u.client.Do(hreq)
	if err != nil {
		return nil, 0, err
	}
	defer hres.Body.Close()
	if sid := hres.Header.Get("Mcp-Session-Id"); sid != "" && method == "initialize" {
		b.mu.Lock()
		b.sessionID = sid
		b.mu.Unlock()
	}
	if hres.StatusCode == http.StatusAccepted {
		return nil, hres.StatusCode, nil // notification ack
	}
	if hres.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(hres.Body, 1<<16))
		return nil, hres.StatusCode, fmt.Errorf("upstream %s returned HTTP %d", b.Name, hres.StatusCode)
	}
	ct, _, _ := mime.ParseMediaType(hres.Header.Get("Content-Type"))
	limited := io.LimitReader(hres.Body, 8<<20) // 8 MiB per response
	if ct == "text/event-stream" {
		r, err := readSSEResponse(limited, id)
		return r, hres.StatusCode, err
	}
	var r mcp.Response
	if err := json.NewDecoder(limited).Decode(&r); err != nil {
		return nil, hres.StatusCode, fmt.Errorf("upstream %s: bad JSON-RPC response: %w", b.Name, err)
	}
	return &r, hres.StatusCode, nil
}

// readSSEResponse returns the first JSON-RPC response on the stream whose id
// matches ours. Server->client requests/notifications on the stream are
// ignored in the MVP (Shield does not yet relay sampling/elicitation).
func readSSEResponse(r io.Reader, id json.RawMessage) (*mcp.Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var data strings.Builder
	flush := func() (*mcp.Response, bool) {
		defer data.Reset()
		if data.Len() == 0 {
			return nil, false
		}
		var resp mcp.Response
		if json.Unmarshal([]byte(data.String()), &resp) != nil {
			return nil, false
		}
		if bytes.Equal(bytes.TrimSpace(resp.ID), bytes.TrimSpace(id)) && (resp.Result != nil || resp.Error != nil) {
			return &resp, true
		}
		return nil, false
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if resp, ok := flush(); ok {
				return resp, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	return nil, errors.New("upstream SSE stream ended without a response")
}

// ensureSession performs the legacy initialize handshake once per backend.
func (u *upstream) ensureSession(ctx context.Context, b *Backend) error {
	b.mu.Lock()
	ready := b.infoLoaded
	b.mu.Unlock()
	if ready {
		return nil
	}
	resp, _, err := u.do(ctx, b, "initialize", map[string]any{
		"protocolVersion": b.Protocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "sentinel-shield", "version": Version},
	}, "")
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("upstream %s initialize: %s", b.Name, resp.Error.Message)
	}
	var res struct {
		Instructions string `json:"instructions"`
	}
	_ = json.Unmarshal(resp.Result, &res)
	b.mu.Lock()
	b.instructions = res.Instructions
	b.infoLoaded = true
	b.mu.Unlock()
	_, _, _ = u.do(ctx, b, "notifications/initialized", nil, "") // best effort
	return nil
}

// instructions returns the backend's raw (unvetted) instructions.
func (u *upstream) instructions(ctx context.Context, b *Backend) (string, error) {
	if b.Protocol == ProtoLegacy {
		if err := u.ensureSession(ctx, b); err != nil {
			return "", err
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.instructions, nil
	}
	resp, err := u.call(ctx, b, "server/discover", nil, "")
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", nil // server does not implement discovery; nothing to vet
	}
	var res struct {
		Instructions string `json:"instructions"`
	}
	_ = json.Unmarshal(resp.Result, &res)
	return res.Instructions, nil
}
