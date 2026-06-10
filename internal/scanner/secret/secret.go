package secret

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	File    string
	Line    int
	Rule    string
	Match   string
	Severity string
}

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

var rules = []Rule{
	{
		ID:       "GOLEM001",
		Name:     "Hardcoded Password",
		Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*["'][^"']{3,}["']`),
		Severity: "HIGH",
	},
	{
		ID:       "GOLEM002",
		Name:     "Hardcoded API Key",
		Pattern:  regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*=\s*["'][^"']{8,}["']`),
		Severity: "HIGH",
	},
	{
		ID:       "GOLEM003",
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "CRITICAL",
	},
	{
		ID:       "GOLEM004",
		Name:     "Generic Secret",
		Pattern:  regexp.MustCompile(`(?i)(secret|token)\s*=\s*["'][^"']{8,}["']`),
		Severity: "MEDIUM",
	},
	{
		ID:       "GOLEM005",
		Name:     "Private Key Header",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
		Severity: "CRITICAL",
	},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
}

var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".exe": true, ".bin": true, ".zip": true, ".pdf": true,
}

func Scan(target string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		fileFindings, err := scanFile(path)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func scanFile(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				findings = append(findings, Finding{
					File:     path,
					Line:     lineNum,
					Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
					Match:    redact(match),
					Severity: rule.Severity,
				})
			}
		}
	}

	return findings, nil
}

func redact(match string) string {
	if len(match) <= 6 {
		return "***"
	}
	return match[:6] + "***"
}