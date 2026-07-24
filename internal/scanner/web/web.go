package web

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GolemSecurity/golem-cops/internal/engine"
	"gopkg.in/yaml.v3"
)

type Finding struct {
	URL      string
	Rule     string
	Severity string
	Message  string
	Found    bool
}

type WebRule struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Header      string `yaml:"header"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Remediation string `yaml:"remediation"`
}

type WebRuleFile struct {
	Version  string    `yaml:"version"`
	Category string    `yaml:"category"`
	Scanner  string    `yaml:"scanner"`
	Rules    []WebRule `yaml:"rules"`
}

func loadWebRules() ([]WebRule, error) {
	rulesDir := filepath.Join(engine.FindRulesDir(), "code", "web")
	rulesFile := filepath.Join(rulesDir, "rules.yaml")

	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("could not load web rules from %s", rulesFile)
	}

	var ruleFile WebRuleFile
	if err := yaml.Unmarshal(data, &ruleFile); err != nil {
		return nil, err
	}

	return ruleFile.Rules, nil
}

func Scan(target string) ([]Finding, error) {
	rules, err := loadWebRules()
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	fmt.Printf("  Connecting to %s...\n", target)

	resp, err := client.Get(target)
	if err != nil {
		if strings.HasPrefix(target, "https://") {
			target = strings.Replace(target, "https://", "http://", 1)
			resp, err = client.Get(target)
			if err != nil {
				return nil, fmt.Errorf("could not connect to %s: %v", target, err)
			}
		} else {
			return nil, fmt.Errorf("could not connect to %s: %v", target, err)
		}
	}
	defer resp.Body.Close()

	fmt.Printf("  Response: %d %s\n\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	var findings []Finding

	for _, rule := range rules {
		value := resp.Header.Get(rule.Header)

		// headers we flag when PRESENT (info disclosure)
		if rule.Header == "X-Powered-By" || rule.Header == "Server" {
			if value != "" {
				findings = append(findings, Finding{
					URL:      target,
					Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
					Severity: rule.Severity,
					Message:  fmt.Sprintf("%s Value: %s", rule.Description, value),
					Found:    true,
				})
			}
			continue
		}

		// headers we flag when MISSING (protection headers)
		if value == "" {
			findings = append(findings, Finding{
				URL:      target,
				Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
				Severity: rule.Severity,
				Message:  rule.Description,
				Found:    false,
			})
		}
	}

	return findings, nil
}