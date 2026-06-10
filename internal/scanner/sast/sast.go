package sast

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	File     string
	Line     int
	Rule     string
	Code     string
	Severity string
	Message  string
}

type Rule struct {
	ID       string
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Message  string
	Languages []string
}

var rules = []Rule{
	{
		ID:       "SAST001",
		Name:     "Unsafe Eval Usage",
		Pattern:  regexp.MustCompile(`\beval\s*\(`),
		Severity: "HIGH",
		Message:  "eval() executes arbitrary code and is a major injection risk.",
		Languages: []string{".js", ".ts", ".py"},
	},
	{
		ID:       "SAST002",
		Name:     "SQL Injection Risk",
		Pattern:  regexp.MustCompile(`(?i)(query|execute|exec)\s*\(.*\+`),
		Severity: "CRITICAL",
		Message:  "String concatenation in SQL query may allow SQL injection.",
		Languages: []string{".go", ".js", ".py", ".java", ".php"},
	},
	{
		ID:       "SAST003",
		Name:     "Hardcoded IP Address",
		Pattern:  regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`),
		Severity: "LOW",
		Message:  "Hardcoded IP address detected. Use config or environment variables.",
		Languages: []string{".go", ".js", ".py", ".java", ".ts"},
	},
	{
		ID:       "SAST004",
		Name:     "Insecure Random",
		Pattern:  regexp.MustCompile(`(?i)(math\.random|rand\.intn|random\.random)\s*\(`),
		Severity: "MEDIUM",
		Message:  "Insecure random number generator. Use crypto/rand for security-sensitive operations.",
		Languages: []string{".go", ".js", ".py"},
	},
	{
		ID:       "SAST005",
		Name:     "Command Injection Risk",
		Pattern:  regexp.MustCompile(`(?i)(exec\.command|os\.system|subprocess\.call|child_process)\s*\(`),
		Severity: "HIGH",
		Message:  "Dynamic command execution detected. Validate and sanitize all inputs.",
		Languages: []string{".go", ".py", ".js"},
	},
	{
		ID:       "SAST006",
		Name:     "Weak Hash Algorithm",
		Pattern:  regexp.MustCompile(`(?i)(md5|sha1)\s*\.`),
		Severity: "MEDIUM",
		Message:  "Weak hashing algorithm. Use SHA-256 or stronger.",
		Languages: []string{".go", ".js", ".py", ".java"},
	},
	{
		ID:       "SAST007",
		Name:     "TODO Security Comment",
		Pattern:  regexp.MustCompile(`(?i)//\s*TODO.*(auth|security|sanitize|validate|encrypt)`),
		Severity: "LOW",
		Message:  "Unresolved security-related TODO comment.",
		Languages: []string{".go", ".js", ".py", ".java", ".ts"},
	},
	{
		ID:       "SAST008",
		Name:     "Insecure TLS Verification",
		Pattern:  regexp.MustCompile(`(?i)(insecureskipverify|verify\s*=\s*false|ssl_verify\s*=\s*false)`),
		Severity: "HIGH",
		Message:  "TLS certificate verification is disabled. This allows MITM attacks.",
		Languages: []string{".go", ".py", ".js"},
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

		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		fileFindings, err := scanFile(path, ext)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func scanFile(path string, ext string) ([]Finding, error) {
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
			if !languageMatches(ext, rule.Languages) {
				continue
			}
			if rule.Pattern.MatchString(line) {
				findings = append(findings, Finding{
					File:     path,
					Line:     lineNum,
					Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
					Code:     strings.TrimSpace(line),
					Severity: rule.Severity,
					Message:  rule.Message,
				})
			}
		}
	}

	return findings, nil
}

func languageMatches(ext string, languages []string) bool {
	if len(languages) == 0 {
		return true
	}
	for _, l := range languages {
		if l == ext {
			return true
		}
	}
	return false
}