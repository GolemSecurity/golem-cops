package secret

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GolemSecurity/golem-cops/internal/engine"
)

type Finding struct {
	File        string
	Line        int
	Rule        string
	Match       string
	Severity    string
	Description string
	Remediation string
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
}

var skipExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".exe": true, ".bin": true, ".zip": true, ".pdf": true,
}

func Scan(target string) ([]Finding, error) {
	rulesDir := filepath.Join(engine.FindRulesDir(), "code", "secret")
	rules, err := engine.LoadRules(rulesDir)
	if err != nil || len(rules) == 0 {
		return nil, fmt.Errorf("could not load secret rules from %s", rulesDir)
	}

	var findings []Finding

	err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
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

		fileFindings, err := scanFile(path, rules)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func scanFile(path string, rules []engine.CompiledRule) ([]Finding, error) {
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
					File:        path,
					Line:        lineNum,
					Rule:        fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
					Match:       redact(match),
					Severity:    rule.Severity,
					Description: rule.Description,
					Remediation: rule.Remediation,
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