package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/open-policy-agent/opa/v1/rego"
)

// RegoEngine evaluates step decisions using an embedded Open Policy Agent instance.
type RegoEngine struct {
	query   rego.PreparedEvalQuery
	rawRego string
}

// RegoInput represents the input document passed to the Rego query.
type RegoInput struct {
	Principal RegoPrincipal  `json:"principal"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Counters  RegoCounters   `json:"counters"`
}

type RegoPrincipal struct {
	Subject   string   `json:"subject"`
	AgentID   string   `json:"agent_id"`
	SessionID string   `json:"session_id"`
	Scopes    []string `json:"scopes"`
}

type RegoCounters struct {
	Steps int `json:"steps"`
	Rate  int `json:"rate"`
}

type regoDecisionOutput struct {
	Action         string `json:"action"`
	Rule           string `json:"rule"`
	Reason         string `json:"reason"`
	ApprovalID     string `json:"approval_id"`
	DryRun         bool   `json:"dry_run"`
	OriginalAction string `json:"original_action"`
}

// NewRegoEngine compiles and prepares a Rego policy for fast step evaluation.
func NewRegoEngine(ctx context.Context, regoSource string) (*RegoEngine, error) {
	query, err := rego.New(
		rego.Query("decision = data.mcpguard.policy.decision"),
		rego.Module("mcpguard_policy.rego", regoSource),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego prepare error: %w", err)
	}

	return &RegoEngine{
		query:   query,
		rawRego: regoSource,
	}, nil
}

// Evaluate evaluates a step against the compiled Rego policy.
func (r *RegoEngine) Evaluate(ctx context.Context, p *identity.Principal, tool string, args map[string]any, steps, rate int) (Decision, error) {
	var scopes []string
	var subject, agentID, sessionID string
	if p != nil {
		subject = p.Subject
		agentID = p.AgentID
		sessionID = p.SessionID
		scopes = p.Scopes
	}

	in := RegoInput{
		Principal: RegoPrincipal{
			Subject:   subject,
			AgentID:   agentID,
			SessionID: sessionID,
			Scopes:    scopes,
		},
		Tool:      tool,
		Arguments: args,
		Counters: RegoCounters{
			Steps: steps,
			Rate:  rate,
		},
	}

	rs, err := r.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{Action: Deny, Rule: "rego_eval_error", Reason: err.Error()}, err
	}
	if len(rs) == 0 {
		return Decision{Action: Deny, Rule: "rego_no_decision", Reason: "rego policy produced no decision"}, nil
	}

	rawDec, ok := rs[0].Bindings["decision"]
	if !ok {
		return Decision{Action: Deny, Rule: "rego_missing_binding", Reason: "decision binding missing from rego evaluation"}, nil
	}

	b, err := json.Marshal(rawDec)
	if err != nil {
		return Decision{Action: Deny, Rule: "rego_marshal_error", Reason: err.Error()}, err
	}

	var out regoDecisionOutput
	if err := json.Unmarshal(b, &out); err != nil {
		return Decision{Action: Deny, Rule: "rego_unmarshal_error", Reason: err.Error()}, err
	}

	return Decision{
		Action:         Action(out.Action),
		Rule:           out.Rule,
		Reason:         out.Reason,
		ApprovalID:     out.ApprovalID,
		DryRun:         out.DryRun,
		OriginalAction: Action(out.OriginalAction),
	}, nil
}

// Source returns the raw Rego source code.
func (r *RegoEngine) Source() string {
	return r.rawRego
}
