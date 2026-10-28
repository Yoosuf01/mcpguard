// Package hitl implements human-in-the-loop approvals. A tool call that needs
// approval is parked with a fingerprint (session + tool + arguments). Once a
// human approves it, the next identical call from the same session is allowed
// exactly once. Any change to the arguments needs a new approval.
package hitl

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Denied   Status = "denied"
	Used     Status = "used"
)

type Request struct {
	ID          string         `json:"id"`
	SessionID   string         `json:"session_id"`
	AgentID     string         `json:"agent_id"`
	Subject     string         `json:"subject"`
	Tool        string         `json:"tool"`
	Arguments   map[string]any `json:"arguments"`
	Fingerprint string         `json:"fingerprint"`
	Status      Status         `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
}

type Store struct {
	mu   sync.Mutex
	byID map[string]*Request
	byFP map[string]*Request
	ttl  time.Duration
}

func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Store{byID: map[string]*Request{}, byFP: map[string]*Request{}, ttl: ttl}
}

func Fingerprint(sessionID, tool string, args map[string]any) string {
	b, _ := json.Marshal(args) // map keys are sorted by encoding/json => canonical
	h := sha256.Sum256([]byte(sessionID + "\x00" + tool + "\x00" + string(b)))
	return hex.EncodeToString(h[:])
}

// Check returns (true, nil) if an approved request exists for this exact call
// and consumes it. Otherwise it returns (false, req) where req is the pending
// request (created if needed).
func (s *Store) Check(sessionID, agentID, subject, tool string, args map[string]any) (bool, *Request) {
	fp := Fingerprint(sessionID, tool, args)
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.byFP[fp]; ok && time.Since(r.CreatedAt) < s.ttl {
		switch r.Status {
		case Approved:
			r.Status = Used
			delete(s.byFP, fp)
			return true, r
		case Pending, Denied:
			return false, r
		}
	}
	r := &Request{ID: newID(), SessionID: sessionID, AgentID: agentID, Subject: subject, Tool: tool,
		Arguments: args, Fingerprint: fp, Status: Pending, CreatedAt: time.Now()}
	s.byID[r.ID] = r
	s.byFP[fp] = r
	return false, r
}

func (s *Store) Decide(id string, approve bool) (*Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok || r.Status != Pending {
		return nil, false
	}
	if approve {
		r.Status = Approved
	} else {
		r.Status = Denied
	}
	return r, true
}

func (s *Store) List() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Request, 0, len(s.byID))
	for _, r := range s.byID {
		if r.Status == Pending {
			out = append(out, r)
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "apr_" + hex.EncodeToString(b)
}
