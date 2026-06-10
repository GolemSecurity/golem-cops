package deps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	File     string
	Package  string
	Version  string
	Rule     string
	Severity string
	Message  string
}

// Known vulnerable packages (simplified - in real world this hits a CVE database)
var knownVulnerable = map[string]VulnInfo{
	"lodash": {
		Severity: "HIGH",
		Message:  "Versions below 4.17.21 have prototype pollution vulnerabilities (CVE-2021-23337).",
		SafeVersion: "4.17.21",
	},
	"axios": {
		Severity: "MEDIUM",
		Message:  "Versions below 1.6.0 may have SSRF vulnerabilities.",
		SafeVersion: "1.6.0",
	},
	"log4j": {
		Severity: "CRITICAL",
		Message:  "Log4Shell vulnerability (CVE-2021-44228). Upgrade immediately.",
		SafeVersion: "2.17.1",
	},
	"django": {
		Severity: "HIGH",
		Message:  "Versions below 4.2.0 have known security patches missing.",
		SafeVersion: "4.2.0",
	},
	"express": {
		Severity: "LOW",
		Message:  "Ensure you are using latest express for security patches.",
		SafeVersion: "4.18.0",
	},
	"requests": {
		Severity: "MEDIUM",
		Message:  "Versions below 2.28.0 have known vulnerabilities.",
		SafeVersion: "2.28.0",
	},
	"numpy": {
		Severity: "MEDIUM",
		Message:  "Versions below 1.22.0 have buffer overflow vulnerabilities.",
		SafeVersion: "1.22.0",
	},
	"pyyaml": {
		Severity: "HIGH",
		Message:  "Versions below 6.0 allow arbitrary code execution via yaml.load().",
		SafeVersion: "6.0",
	},
}

type VulnInfo struct {
	Severity    string
	Message     string
	SafeVersion string
}

func Scan(target string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		var fileFindings []Finding
		var scanErr error

		switch info.Name() {
		case "package.json":
			fileFindings, scanErr = scanPackageJSON(path)
		case "requirements.txt":
			fileFindings, scanErr = scanRequirementsTxt(path)
		case "go.mod":
			fileFindings, scanErr = scanGoMod(path)
		}

		if scanErr == nil {
			findings = append(findings, fileFindings...)
		}

		return nil
	})

	return findings, err
}

// package.json parser
func scanPackageJSON(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var findings []Finding

	allDeps := map[string]string{}
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for name, version := range allDeps {
		findings = append(findings, checkPackage(path, name, version)...)
	}

	return findings, nil
}

// requirements.txt parser
func scanRequirementsTxt(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-]+)\s*([><=!]+\s*[\d\.]+)?`)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			name := strings.ToLower(matches[1])
			version := ""
			if len(matches) >= 3 {
				version = strings.TrimSpace(matches[2])
			}
			findings = append(findings, checkPackage(path, name, version)...)
		}
	}

	return findings, nil
}

// go.mod parser
func scanGoMod(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	re := regexp.MustCompile(`^\s*require\s+([^\s]+)\s+(v[\d\.]+)`)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			name := matches[1]
			version := matches[2]
			findings = append(findings, checkPackage(path, name, version)...)
		}
	}

	return findings, nil
}

func checkPackage(file, name, version string) []Finding {
	var findings []Finding
	lname := strings.ToLower(name)

	for vulnPkg, info := range knownVulnerable {
		if strings.Contains(lname, vulnPkg) {
			findings = append(findings, Finding{
				File:     file,
				Package:  name,
				Version:  version,
				Rule:     fmt.Sprintf("[DEPS] Vulnerable Package: %s", name),
				Severity: info.Severity,
				Message:  fmt.Sprintf("%s Safe version: %s+", info.Message, info.SafeVersion),
			})
		}
	}

	return findings
}