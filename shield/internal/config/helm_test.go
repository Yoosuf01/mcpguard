package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

func TestHelmChart_StructureAndSyntax(t *testing.T) {
	// Root of repo is two directories up from shield/internal/config
	repoRoot := filepath.Join("..", "..", "..")
	chartDir := filepath.Join(repoRoot, "deploy", "helm", "mcpguard")

	// 1. Verify existence of all required chart files
	requiredFiles := []string{
		"Chart.yaml",
		"values.yaml",
		"README.md",
		filepath.Join("templates", "_helpers.tpl"),
		filepath.Join("templates", "deployment.yaml"),
		filepath.Join("templates", "service.yaml"),
		filepath.Join("templates", "configmap.yaml"),
		filepath.Join("templates", "secret.yaml"),
		filepath.Join("templates", "serviceaccount.yaml"),
		filepath.Join("templates", "hpa.yaml"),
		filepath.Join("templates", "pdb.yaml"),
		filepath.Join("templates", "networkpolicy.yaml"),
		filepath.Join("templates", "ingress.yaml"),
		filepath.Join("templates", "servicemonitor.yaml"),
	}

	for _, file := range requiredFiles {
		fullPath := filepath.Join(chartDir, file)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Fatalf("Required Helm chart file missing: %s", fullPath)
		}
	}

	// 2. Validate Chart.yaml YAML syntax
	chartBytes, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatalf("Failed to read Chart.yaml: %v", err)
	}
	var chartMeta map[string]interface{}
	if err := yaml.Unmarshal(chartBytes, &chartMeta); err != nil {
		t.Fatalf("Chart.yaml is invalid YAML: %v", err)
	}
	if chartMeta["name"] != "mcpguard" {
		t.Errorf("Expected chart name 'mcpguard', got %v", chartMeta["name"])
	}
	if chartMeta["apiVersion"] != "v2" {
		t.Errorf("Expected apiVersion 'v2', got %v", chartMeta["apiVersion"])
	}

	// 3. Validate values.yaml YAML syntax and security invariants
	valuesBytes, err := os.ReadFile(filepath.Join(chartDir, "values.yaml"))
	if err != nil {
		t.Fatalf("Failed to read values.yaml: %v", err)
	}
	var values map[string]interface{}
	if err := yaml.Unmarshal(valuesBytes, &values); err != nil {
		t.Fatalf("values.yaml is invalid YAML: %v", err)
	}

	// Check SecurityContext in values.yaml
	secCtx, ok := values["securityContext"].(map[string]interface{})
	if !ok {
		t.Fatalf("securityContext missing in values.yaml")
	}
	if secCtx["readOnlyRootFilesystem"] != true {
		t.Errorf("Expected readOnlyRootFilesystem=true, got %v", secCtx["readOnlyRootFilesystem"])
	}
	if secCtx["runAsNonRoot"] != true {
		t.Errorf("Expected runAsNonRoot=true, got %v", secCtx["runAsNonRoot"])
	}

	// Check ServiceAccount automountServiceAccountToken = false (Zero Trust)
	sa, ok := values["serviceAccount"].(map[string]interface{})
	if !ok {
		t.Fatalf("serviceAccount missing in values.yaml")
	}
	if sa["automountServiceAccountToken"] != false {
		t.Errorf("Expected automountServiceAccountToken=false, got %v", sa["automountServiceAccountToken"])
	}

	// Check NetworkPolicy blockMetadata = true
	netPol, ok := values["networkPolicy"].(map[string]interface{})
	if !ok {
		t.Fatalf("networkPolicy missing in values.yaml")
	}
	egress, ok := netPol["egress"].(map[string]interface{})
	if !ok || egress["blockMetadata"] != true {
		t.Errorf("Expected networkPolicy.egress.blockMetadata=true, got %v", egress["blockMetadata"])
	}

	// 4. Validate template syntax with Go text/template
	tmpl := template.New("helm").Funcs(template.FuncMap{
		"include": func(name string, data interface{}) string { return "mock" },
		"toYaml":  func(data interface{}) string { return "mock: yaml" },
		"nindent": func(n int, s string) string { return s },
		"indent":  func(n int, s string) string { return s },
		"quote":   func(s interface{}) string { return "\"mock\"" },
		"default": func(def interface{}, val interface{}) interface{} {
			if val != nil && val != "" {
				return val
			}
			return def
		},
		"trunc":      func(n int, s string) string { return s },
		"trimSuffix": func(suffix, s string) string { return s },
		"replace":    func(old, new, src string) string { return src },
		"contains":   func(substr, s string) bool { return true },
		"sha256sum":  func(s string) string { return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		"print":      func(args ...interface{}) string { return "mock" },
	})

	templateFiles, err := filepath.Glob(filepath.Join(chartDir, "templates", "*.yaml"))
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	helpersFile := filepath.Join(chartDir, "templates", "_helpers.tpl")
	templateFiles = append(templateFiles, helpersFile)

	for _, tplFile := range templateFiles {
		content, err := os.ReadFile(tplFile)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", tplFile, err)
		}
		_, err = tmpl.Parse(string(content))
		if err != nil {
			t.Errorf("Template syntax error in %s: %v", tplFile, err)
		}
	}
}

