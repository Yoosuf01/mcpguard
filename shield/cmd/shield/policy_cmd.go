package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/Yoosuf01/mcpguard/shield/internal/policy"
)

type FixturePrincipal struct {
	Subject   string   `json:"subject"`
	AgentID   string   `json:"agent_id"`
	SessionID string   `json:"session_id"`
	Scopes    []string `json:"scopes"`
}

type policyFixture struct {
	Name      string                `json:"name"`
	Principal *FixturePrincipal     `json:"principal"`
	Tool      string                `json:"tool"`
	Arguments map[string]any        `json:"arguments"`
	Counters  *policy.RegoCounters  `json:"counters"`
	Expected  policyFixtureExpected `json:"expected"`
}

type policyFixtureExpected struct {
	Action string `json:"action"`
	Rule   string `json:"rule"`
}

func handlePolicyCommand(args []string) {
	if len(args) == 0 {
		printPolicyUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "test":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: mcpguard policy test <policy.yaml|policy.rego> [fixtures.json]")
			os.Exit(1)
		}
		fixturesPath := ""
		if len(args) > 2 {
			fixturesPath = args[2]
		}
		runPolicyTest(args[1], fixturesPath)

	case "compile":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: mcpguard policy compile <policy.yaml> [-o output.rego]")
			os.Exit(1)
		}
		outPath := ""
		for i := 2; i < len(args); i++ {
			if args[i] == "-o" && i+1 < len(args) {
				outPath = args[i+1]
				i++
			}
		}
		runPolicyCompile(args[1], outPath)

	default:
		fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\n", args[0])
		printPolicyUsage()
		os.Exit(1)
	}
}

func printPolicyUsage() {
	fmt.Println("Usage: mcpguard policy <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  test <policy.yaml|policy.rego> [fixtures.json]  Test step-level policy against fixture assertions")
	fmt.Println("  compile <policy.yaml> [-o output.rego]          Compile declarative YAML policy to native Rego")
}

func resolveFilePath(p string) string {
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if !filepath.IsAbs(p) {
		candidate := filepath.Join("shield", p)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return p
}

func runPolicyCompile(policyPath, outPath string) {
	resolved := resolveFilePath(policyPath)
	b, err := os.ReadFile(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading policy file %s: %v\n", policyPath, err)
		os.Exit(1)
	}

	regoSrc, err := policy.CompileYAMLBytesToRego(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compilation error: %v\n", err)
		os.Exit(1)
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(regoSrc), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output file %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("Compiled Rego policy written to %s\n", outPath)
	} else {
		fmt.Print(regoSrc)
	}
}

func runPolicyTest(policyPath, fixturesPath string) {
	resolvedPolicy := resolveFilePath(policyPath)
	b, err := os.ReadFile(resolvedPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading policy %s: %v\n", policyPath, err)
		os.Exit(1)
	}

	var regoSrc string
	ext := strings.ToLower(filepath.Ext(resolvedPolicy))
	if ext == ".yaml" || ext == ".yml" {
		regoSrc, err = policy.CompileYAMLBytesToRego(b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "YAML policy compilation error: %v\n", err)
			os.Exit(1)
		}
	} else if ext == ".rego" {
		regoSrc = string(b)
	} else {
		fmt.Fprintf(os.Stderr, "unsupported policy file extension %q (want .yaml, .yml or .rego)\n", ext)
		os.Exit(1)
	}

	ctx := context.Background()
	engine, err := policy.NewRegoEngine(ctx, regoSrc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Rego engine initialization error: %v\n", err)
		os.Exit(1)
	}

	// Try to locate fixtures if not explicitly provided
	if fixturesPath == "" {
		dir := filepath.Dir(resolvedPolicy)
		candidate := filepath.Join(dir, "policy_test.json")
		if _, err := os.Stat(candidate); err == nil {
			fixturesPath = candidate
		} else {
			candidateRoot := resolveFilePath("configs/policy_test.json")
			if _, err := os.Stat(candidateRoot); err == nil {
				fixturesPath = candidateRoot
			}
		}
	}

	if fixturesPath == "" {
		fmt.Printf("✓ Policy %s compiled successfully without errors.\n", policyPath)
		fmt.Println("  (No fixtures.json found; pass [fixtures.json] to evaluate assertions)")
		return
	}

	resolvedFixtures := resolveFilePath(fixturesPath)
	fb, err := os.ReadFile(resolvedFixtures)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading fixtures %s: %v\n", fixturesPath, err)
		os.Exit(1)
	}

	var fixtures []policyFixture
	if err := json.Unmarshal(fb, &fixtures); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing fixtures JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Evaluating Policy: %s (%d test cases) ===\n", policyPath, len(fixtures))
	startTime := time.Now()
	passCount := 0
	failCount := 0

	for _, fix := range fixtures {
		steps := 1
		rate := 1
		if fix.Counters != nil {
			if fix.Counters.Steps > 0 {
				steps = fix.Counters.Steps
			}
			if fix.Counters.Rate > 0 {
				rate = fix.Counters.Rate
			}
		}

		var principal *identity.Principal
		if fix.Principal != nil {
			principal = &identity.Principal{
				Subject:   fix.Principal.Subject,
				AgentID:   fix.Principal.AgentID,
				SessionID: fix.Principal.SessionID,
				Scopes:    fix.Principal.Scopes,
			}
		}

		t0 := time.Now()
		dec, err := engine.Evaluate(ctx, principal, fix.Tool, fix.Arguments, steps, rate)
		dur := time.Since(t0)

		if err != nil {
			fmt.Printf("✗ FAIL [%.2fms] %s\n", float64(dur.Microseconds())/1000.0, fix.Name)
			fmt.Printf("     error: %v\n", err)
			failCount++
			continue
		}

		actionMatches := fix.Expected.Action == "" || string(dec.Action) == fix.Expected.Action
		ruleMatches := fix.Expected.Rule == "" || dec.Rule == fix.Expected.Rule

		if actionMatches && ruleMatches {
			fmt.Printf("✓ PASS [%.2fms] %s (%s / %s)\n", float64(dur.Microseconds())/1000.0, fix.Name, dec.Action, dec.Rule)
			passCount++
		} else {
			fmt.Printf("✗ FAIL [%.2fms] %s\n", float64(dur.Microseconds())/1000.0, fix.Name)
			fmt.Printf("     expected: %s / %s\n", fix.Expected.Action, fix.Expected.Rule)
			fmt.Printf("     got:      %s / %s (Reason: %s)\n", dec.Action, dec.Rule, dec.Reason)
			failCount++
		}
	}

	totalDur := time.Since(startTime)
	fmt.Println("============================================================")
	fmt.Printf("Results: %d passed, %d failed in %.2fms\n", passCount, failCount, float64(totalDur.Microseconds())/1000.0)

	if failCount > 0 {
		os.Exit(1)
	}
}
