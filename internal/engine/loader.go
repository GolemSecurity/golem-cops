package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type RuleFile struct {
	Version  string     `yaml:"version"`
	Category string     `yaml:"category"`
	Scanner  string     `yaml:"scanner"`
	Rules    []YAMLRule `yaml:"rules"`
}

type YAMLRule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Pattern     string   `yaml:"pattern"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Remediation string   `yaml:"remediation"`
	Languages   []string `yaml:"languages"`
	Tags        []string `yaml:"tags"`
}

type CompiledRule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Severity    string
	Description string
	Remediation string
	Languages   []string
	Tags        []string
}

func LoadRules(rulesDir string) ([]CompiledRule, error) {
	var compiled []CompiledRule

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		rules, err := loadFile(path)
		if err != nil {
			return nil
		}

		compiled = append(compiled, rules...)
		return nil
	})

	return compiled, err
}

func loadFile(path string) ([]CompiledRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ruleFile RuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, err
	}

	var compiled []CompiledRule
	for _, rule := range ruleFile.Rules {
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}

		compiled = append(compiled, CompiledRule{
			ID:          rule.ID,
			Name:        rule.Name,
			Pattern:     pattern,
			Severity:    rule.Severity,
			Description: rule.Description,
			Remediation: rule.Remediation,
			Languages:   rule.Languages,
			Tags:        rule.Tags,
		})
	}

	return compiled, nil
}

func FindRulesDir() string {
	candidates := []string{
		"rules",
		"../rules",
		"../../rules",
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return "rules"
}