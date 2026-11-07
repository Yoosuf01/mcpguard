package policy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/guard"
	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
)

// Decision is the outcome of evaluating one step.
type Decision struct {
	Action         Action
	Rule           string // stable id for dashboards/alerts, e.g. "deny_arg_pattern"
	Reason         string // human-readable, safe to show the model
	ApprovalID     string
	DryRun         bool   // true if evaluated in dry_run simulation mode
	OriginalAction Action // the underlying action that would have occurred without dry_run
}

// Counters tracks per-session steps and per-minute rate. In-memory for the
// MVP; move to Redis (INCR + EXPIRE) when you run more than one replica.
type Counters struct {
	mu     sync.Mutex
	steps  map[string]int
	window map[string]rateWindow
	now    func() time.Time
}

type rateWindow struct {
	start time.Time
	n     int
}

func NewCounters() *Counters {
	return &Counters{steps: map[string]int{}, window: map[string]rateWindow{}, now: time.Now}
}

func (c *Counters) step(session string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps[session]++
	return c.steps[session]
}

func (c *Counters) rate(session string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	w := c.window[session]
	if now.Sub(w.start) >= time.Minute {
		w = rateWindow{start: now}
	}
	w.n++
	c.window[session] = w
	return w.n
}

// Engine evaluates steps against a compiled policy.
type Engine struct {
	mu        sync.RWMutex
	pol       *Compiled
	rego      *RegoEngine
	counters  *Counters
	approvals *hitl.Store
}

func (e *Engine) WithRego(r *RegoEngine) *Engine {
	e.mu.Lock()
	e.rego = r
	e.mu.Unlock()
	return e
}

func (e *Engine) RegoEngine() *RegoEngine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rego
}

func NewEngine(p *Compiled, approvals *hitl.Store) *Engine {
	if approvals == nil {
		approvals = hitl.NewStore(0)
	}
	return &Engine{pol: p, counters: NewCounters(), approvals: approvals}
}

// Swap hot-reloads the policy (wire it to SIGHUP or a file watcher).
func (e *Engine) Swap(p *Compiled) { e.mu.Lock(); e.pol = p; e.mu.Unlock() }

func (e *Engine) Policy() *Compiled { e.mu.RLock(); defer e.mu.RUnlock(); return e.pol }

func (e *Engine) Approvals() *hitl.Store { return e.approvals }

// ToolVisible decides whether a tool appears in tools/list for this agent.
// Hiding forbidden tools means the model never plans around them.
func (e *Engine) ToolVisible(p *identity.Principal, tool string) bool {
	pol := e.Policy()
	a := pol.agent(p.AgentID)
	if a == nil {
		return pol.File.DefaultAction == Allow
	}
	r, ok := a.matchTool(tool)
	if !ok {
		return pol.File.DefaultAction == Allow
	}
	if r.Deny {
		return false
	}
	return r.RequireScope == "" || p.HasScope(r.RequireScope)
}

// Evaluate is the step-level interceptor. Order matters: cheap, global
// circuit breakers first; argument inspection next; human approval last so a
// human is never asked to approve something policy would deny anyway.
func (e *Engine) Evaluate(p *identity.Principal, tool string, args map[string]any) Decision {
	e.mu.RLock()
	regoEng := e.rego
	e.mu.RUnlock()

	if regoEng != nil {
		steps := e.counters.step(p.SessionID)
		rate := e.counters.rate(p.SessionID)
		dec, err := regoEng.Evaluate(context.Background(), p, tool, args, steps, rate)
		if err != nil {
			return Decision{Action: Deny, Rule: "rego_eval_error", Reason: err.Error()}
		}
		if dec.Action == Pending && dec.Rule == "require_approval" && e.approvals != nil {
			ok, req := e.approvals.Check(p.SessionID, p.AgentID, p.Subject, tool, args)
			if !ok {
				if req.Status == hitl.Denied {
					dec.Action = Deny
					dec.Rule = "approval_denied"
					dec.Reason = "a human denied this exact call"
					dec.ApprovalID = req.ID
					return dec
				}
				dec.ApprovalID = req.ID
				dec.Reason = "this call needs human approval (id " + req.ID + "); retry the identical call after approval"
				return dec
			}
			dec.Action = Allow
			dec.Rule = "approved_by_human"
			dec.ApprovalID = req.ID
			return dec
		}
		return dec
	}

	pol := e.Policy()
	a := pol.agent(p.AgentID)

	decide := func(d Decision) Decision {
		dryRun := pol.File.DryRun
		if a != nil && a.DryRun != nil {
			dryRun = *a.DryRun
		}
		if dryRun && (d.Action == Deny || d.Action == Pending) {
			d.DryRun = true
			d.OriginalAction = d.Action
			d.Action = Allow
		}
		return d
	}

	// 1. Runaway-loop breaker: every attempt counts, allowed or not.
	steps := e.counters.step(p.SessionID)
	if a != nil && a.MaxStepsPerSession > 0 && steps > a.MaxStepsPerSession {
		return decide(Decision{Action: Deny, Rule: "max_steps_per_session",
			Reason: fmt.Sprintf("session exceeded %d tool calls; a human must start a new session", a.MaxStepsPerSession)})
	}
	if a != nil && a.RateLimitPerMinute > 0 && e.counters.rate(p.SessionID) > a.RateLimitPerMinute {
		return decide(Decision{Action: Deny, Rule: "rate_limit", Reason: "rate limit exceeded for this agent session"})
	}

	// 2. Is this tool allowed for this agent at all?
	var rule *compiledTool
	if a != nil {
		rule, _ = a.matchTool(tool)
	}
	switch {
	case rule == nil && pol.File.DefaultAction != Allow:
		return decide(Decision{Action: Deny, Rule: "tool_not_allowed", Reason: fmt.Sprintf("tool %q is not on this agent's allowlist", tool)})
	case rule != nil && rule.Deny:
		return decide(Decision{Action: Deny, Rule: "tool_denied", Reason: fmt.Sprintf("tool %q is explicitly denied", tool)})
	case rule != nil && rule.RequireScope != "" && !p.HasScope(rule.RequireScope):
		return decide(Decision{Action: Deny, Rule: "missing_scope", Reason: fmt.Sprintf("agent token lacks scope %q", rule.RequireScope)})
	}

	// 3. Argument inspection.
	strs := guard.CollectStrings(map[string]any(args))
	patterns := append([]*regexp.Regexp{}, pol.globalDeny...)
	if rule != nil {
		patterns = append(patterns, rule.deny...)
	}
	for _, s := range strs {
		for _, re := range patterns {
			if re.MatchString(s) {
				return decide(Decision{Action: Deny, Rule: "deny_arg_pattern",
					Reason: "arguments match a blocked pattern: " + re.String()})
			}
		}
	}
	if pol.File.Global.BlockSecretsInArguments {
		det := guard.NewRedactor([]string{"aws_access_key", "github_token", "private_key", "jwt", "openai_key", "anthropic_key", "slack_token"})
		if kinds := det.Detect(map[string]any(args)); len(kinds) > 0 {
			return decide(Decision{Action: Deny, Rule: "secret_in_arguments",
				Reason: "arguments contain credentials (" + strings.Join(kinds, ",") + "); possible exfiltration"})
		}
	}
	eg := pol.File.Global.Egress
	if a != nil && a.Egress != nil {
		eg = mergeEgress(eg, *a.Egress)
	}
	if d, bad := checkEgress(eg, strs); bad {
		return decide(d)
	}

	// 4. Human-in-the-loop.
	if rule != nil && rule.RequireApproval {
		ok, req := e.approvals.Check(p.SessionID, p.AgentID, p.Subject, tool, args)
		if !ok {
			if req.Status == hitl.Denied {
				return decide(Decision{Action: Deny, Rule: "approval_denied", Reason: "a human denied this exact call", ApprovalID: req.ID})
			}
			return decide(Decision{Action: Pending, Rule: "require_approval", ApprovalID: req.ID,
				Reason: "this call needs human approval (id " + req.ID + "); retry the identical call after approval"})
		}
		return decide(Decision{Action: Allow, Rule: "approved_by_human", ApprovalID: req.ID})
	}
	return decide(Decision{Action: Allow, Rule: "allow"})
}

func mergeEgress(g, a Egress) Egress {
	out := g
	if len(a.AllowDomains) > 0 {
		out.AllowDomains = a.AllowDomains
	}
	out.DenyDomains = append(append([]string{}, g.DenyDomains...), a.DenyDomains...)
	if a.BlockPrivateNetworks != nil {
		out.BlockPrivateNetworks = a.BlockPrivateNetworks
	}
	return out
}

var (
	urlRe  = regexp.MustCompile(`(?i)\b(?:https?|ftp|gopher|file)://[^\s'"<>()]+`)
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

var internalHostnames = []string{"localhost", "metadata.google.internal", "metadata", "instance-data"}

// checkEgress inspects every URL / IP literal in the arguments. It defends the
// classic agent SSRF: "fetch http://169.254.169.254/latest/meta-data/".
// NOTE: hostnames are not resolved here; DNS-rebinding protection belongs in
// the Sandbox egress proxy, which pins resolved IPs at connect time.
func checkEgress(eg Egress, strs []string) (Decision, bool) {
	blockPrivate := boolOr(eg.BlockPrivateNetworks, true)
	for _, s := range strs {
		for _, raw := range urlRe.FindAllString(s, -1) {
			u, err := url.Parse(raw)
			if err != nil || u.Hostname() == "" {
				if strings.HasPrefix(strings.ToLower(raw), "file://") {
					return Decision{Action: Deny, Rule: "egress_scheme", Reason: "file:// URLs are not allowed"}, true
				}
				continue
			}
			scheme := strings.ToLower(u.Scheme)
			if scheme != "http" && scheme != "https" {
				return Decision{Action: Deny, Rule: "egress_scheme", Reason: "URL scheme " + scheme + " is not allowed"}, true
			}
			host := strings.ToLower(u.Hostname())
			if blockPrivate && isInternalHost(host) {
				return Decision{Action: Deny, Rule: "egress_private_network", Reason: "blocked request to internal address " + host}, true
			}
			if domainMatch(host, eg.DenyDomains) {
				return Decision{Action: Deny, Rule: "egress_deny_domain", Reason: "domain " + host + " is denied"}, true
			}
			if len(eg.AllowDomains) > 0 && !domainMatch(host, eg.AllowDomains) {
				return Decision{Action: Deny, Rule: "egress_not_allowlisted", Reason: "domain " + host + " is not on the egress allowlist"}, true
			}
		}
		if blockPrivate {
			for _, ip := range ipv4Re.FindAllString(s, -1) {
				if isInternalHost(ip) {
					return Decision{Action: Deny, Rule: "egress_private_network", Reason: "blocked reference to internal address " + ip}, true
				}
			}
		}
	}
	return Decision{}, false
}

func isInternalHost(host string) bool {
	host = strings.Trim(host, "[]")
	for _, h := range internalHostnames {
		if host == h {
			return true
		}
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast()
}

func domainMatch(host string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// CheckEgressURI validates a single URI against the global and agent-specific egress policies.
func (e *Engine) CheckEgressURI(p *identity.Principal, rawURI string) (Decision, bool) {
	pol := e.Policy()
	a := pol.agent(p.AgentID)
	eg := pol.File.Global.Egress
	if a != nil && a.Egress != nil {
		eg = mergeEgress(eg, *a.Egress)
	}
	return checkEgress(eg, []string{rawURI})
}

// EvaluatePrompt validates arguments for prompts/get steps (checking secrets and deny patterns).
func (e *Engine) EvaluatePrompt(p *identity.Principal, prompt string, args map[string]any) Decision {
	pol := e.Policy()
	strs := guard.CollectStrings(args)
	for _, s := range strs {
		for _, re := range pol.globalDeny {
			if re.MatchString(s) {
				return Decision{Action: Deny, Rule: "deny_arg_pattern",
					Reason: "prompt arguments match a blocked pattern: " + re.String()}
			}
		}
	}
	if pol.File.Global.BlockSecretsInArguments {
		det := guard.NewRedactor([]string{"aws_access_key", "github_token", "private_key", "jwt", "openai_key", "anthropic_key", "slack_token"})
		if kinds := det.Detect(args); len(kinds) > 0 {
			return Decision{Action: Deny, Rule: "secret_in_arguments",
				Reason: "prompt arguments contain credentials (" + strings.Join(kinds, ",") + ")"}
		}
	}
	return Decision{Action: Allow, Rule: "allow"}
}
