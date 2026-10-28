// Package policy loads policy.yaml and evaluates every tool call (every agent
// "step") against it. The evaluator is a pure function of (principal, tool,
// arguments, counters), which keeps it fast, testable and easy to port to
// OPA/Rego later: the Rego bundle receives the same input document.
package policy

import (
	"fmt"
	"os"
	"path"
	"regexp"

	"github.com/Yoosuf01/mcpguard/shield/internal/guard"
	"gopkg.in/yaml.v3"
)

type Action string

const (
	Allow   Action = "allow"
	Deny    Action = "deny"
	Pending Action = "pending" // human approval required
)

type File struct {
	Version       string         `yaml:"version"`
	DefaultAction Action         `yaml:"default_action"`
	Global        Global         `yaml:"global"`
	Agents        []AgentProfile `yaml:"agents"`
}

type Global struct {
	DenyArgPatterns         []string        `yaml:"deny_arg_patterns"`
	MaskInResults           []string        `yaml:"mask_in_results"`
	MaskInArguments         []string        `yaml:"mask_in_arguments"`
	BlockSecretsInArguments bool            `yaml:"block_secrets_in_arguments"`
	Egress                  Egress          `yaml:"egress"`
	Discovery               DiscoveryPolicy `yaml:"discovery"`
	OutputScanning          OutputScanning  `yaml:"output_scanning"`
}

type DiscoveryPolicy struct {
	UpstreamInstructions string `yaml:"upstream_instructions"` // drop | wrap
	MaxInstructionChars  int    `yaml:"max_instruction_chars"`
	PinInstructions      *bool  `yaml:"pin_instructions"`
	PinToolDefinitions   *bool  `yaml:"pin_tool_definitions"`
	BlockPoisonedTools   *bool  `yaml:"block_poisoned_tools"`
}

type OutputScanning struct {
	OnInjection string `yaml:"on_injection"` // flag | block | off
}

type Egress struct {
	AllowDomains         []string `yaml:"allow_domains"`
	DenyDomains          []string `yaml:"deny_domains"`
	BlockPrivateNetworks *bool    `yaml:"block_private_networks"`
}

type AgentProfile struct {
	ID                 string     `yaml:"id"` // matches Principal.AgentID; "*" is the fallback
	MaxStepsPerSession int        `yaml:"max_steps_per_session"`
	RateLimitPerMinute int        `yaml:"rate_limit_per_minute"`
	Tools              []ToolRule `yaml:"tools"`
	Egress             *Egress    `yaml:"egress"`
}

type ToolRule struct {
	Name            string   `yaml:"name"` // exposed name, glob allowed: "github__*"
	RequireScope    string   `yaml:"require_scope"`
	RequireApproval bool     `yaml:"require_approval"`
	DenyArgPatterns []string `yaml:"deny_arg_patterns"`
	Deny            bool     `yaml:"deny"` // explicit deny wins over a later allow glob
}

// compiled forms
type compiledTool struct {
	ToolRule
	deny []*regexp.Regexp
}

type compiledAgent struct {
	AgentProfile
	tools []compiledTool
}

type Compiled struct {
	File       File
	globalDeny []*regexp.Regexp
	agents     map[string]*compiledAgent
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (c *Compiled) DiscoveryConfig() guard.DiscoveryConfig {
	d := c.File.Global.Discovery
	return guard.DiscoveryConfig{
		Mode:               guard.InstructionsMode(d.UpstreamInstructions),
		MaxInstructionChar: d.MaxInstructionChars,
		PinInstructions:    boolOr(d.PinInstructions, true),
		PinTools:           boolOr(d.PinToolDefinitions, true),
		BlockInjectedTools: boolOr(d.BlockPoisonedTools, true),
	}
}

// LoadFile reads and compiles a policy file. ${ENV} references are expanded.
func LoadFile(p string) (*Compiled, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return Parse([]byte(os.ExpandEnv(string(b))))
}

func Parse(b []byte) (*Compiled, error) {
	var f File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if f.Version != "1" {
		return nil, fmt.Errorf("policy: unsupported version %q (want \"1\")", f.Version)
	}
	if f.DefaultAction == "" {
		f.DefaultAction = Deny
	}
	if f.DefaultAction != Deny && f.DefaultAction != Allow {
		return nil, fmt.Errorf("policy: default_action must be allow or deny")
	}
	switch f.Global.Discovery.UpstreamInstructions {
	case "", "drop", "wrap":
	default:
		return nil, fmt.Errorf("policy: discovery.upstream_instructions must be drop or wrap")
	}
	switch f.Global.OutputScanning.OnInjection {
	case "":
		f.Global.OutputScanning.OnInjection = "flag"
	case "flag", "block", "off":
	default:
		return nil, fmt.Errorf("policy: output_scanning.on_injection must be flag, block or off")
	}
	for _, k := range append(append([]string{}, f.Global.MaskInResults...), f.Global.MaskInArguments...) {
		if !guard.KnownKind(k) {
			return nil, fmt.Errorf("policy: unknown masking kind %q", k)
		}
	}
	c := &Compiled{File: f, agents: map[string]*compiledAgent{}}
	var err error
	if c.globalDeny, err = compileAll(f.Global.DenyArgPatterns); err != nil {
		return nil, err
	}
	for _, a := range f.Agents {
		if a.ID == "" {
			return nil, fmt.Errorf("policy: agent profile without id")
		}
		ca := &compiledAgent{AgentProfile: a}
		for _, t := range a.Tools {
			if _, err := path.Match(t.Name, ""); err != nil {
				return nil, fmt.Errorf("policy: bad tool glob %q: %w", t.Name, err)
			}
			res, err := compileAll(t.DenyArgPatterns)
			if err != nil {
				return nil, err
			}
			ca.tools = append(ca.tools, compiledTool{ToolRule: t, deny: res})
		}
		c.agents[a.ID] = ca
	}
	return c, nil
}

func compileAll(ps []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(ps))
	for _, p := range ps {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("policy: bad pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func (c *Compiled) agent(id string) *compiledAgent {
	if a, ok := c.agents[id]; ok {
		return a
	}
	return c.agents["*"]
}

// matchTool returns the first rule matching the tool name. Explicit `deny`
// rules are checked first so a broad allow glob cannot override them.
func (a *compiledAgent) matchTool(name string) (*compiledTool, bool) {
	for i := range a.tools {
		if ok, _ := path.Match(a.tools[i].Name, name); ok && a.tools[i].Deny {
			return &a.tools[i], true
		}
	}
	for i := range a.tools {
		if ok, _ := path.Match(a.tools[i].Name, name); ok {
			return &a.tools[i], true
		}
	}
	return nil, false
}
