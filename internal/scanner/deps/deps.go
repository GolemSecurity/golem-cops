package deps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GolemSecurity/golem-cops/internal/engine"
)

type Finding struct {
	File     string
	Package  string
	Version  string
	Rule     string
	Severity string
	Message  string
	FixedIn  string
	CVEID    string
	URL      string
}

func Scan(target string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == ".git" ||
				info.Name() == "vendor" || info.Name() == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		var fileFindings []Finding
		var scanErr error

		switch info.Name() {
		case "package.json":
			fileFindings, scanErr = scanPackageJSON(path)
		case "package-lock.json":
			return nil
		case "requirements.txt":
			fileFindings, scanErr = scanRequirementsTxt(path)
		case "go.mod":
			fileFindings, scanErr = scanGoMod(path)
		case "pom.xml":
			fileFindings, scanErr = scanPomXML(path)
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

	fmt.Printf("  Checking %d npm packages via OSV...\n", len(allDeps))

	for name, version := range allDeps {
		version = cleanVersion(version)
		vulns, err := engine.QueryOSV(name, version, "npm")
		if err != nil {
			continue
		}
		for _, vuln := range vulns {
			findings = append(findings, Finding{
				File:     path,
				Package:  name,
				Version:  version,
				Rule:     fmt.Sprintf("[OSV] %s", vuln.ID),
				Severity: vuln.Severity,
				Message:  vuln.Summary,
				FixedIn:  vuln.FixedIn,
				CVEID:    vuln.ID,
				URL:      vuln.URL,
			})
		}
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

	var packages [][]string
	re := regexp.MustCompile(`^([a-zA-Z0-9_\-]+)\s*[><=!]+\s*([\d\.]+)`)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			packages = append(packages, []string{matches[1], matches[2]})
		}
	}

	fmt.Printf("  Checking %d PyPI packages via OSV...\n", len(packages))

	var findings []Finding
	for _, pkg := range packages {
		name, version := pkg[0], pkg[1]
		vulns, err := engine.QueryOSV(name, version, "PyPI")
		if err != nil {
			continue
		}
		for _, vuln := range vulns {
			findings = append(findings, Finding{
				File:     path,
				Package:  name,
				Version:  version,
				Rule:     fmt.Sprintf("[OSV] %s", vuln.ID),
				Severity: vuln.Severity,
				Message:  vuln.Summary,
				FixedIn:  vuln.FixedIn,
				CVEID:    vuln.ID,
				URL:      vuln.URL,
			})
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

	var packages [][]string
	re := regexp.MustCompile(`^\s*([^\s]+)\s+(v[\d\.]+)`)
	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		}
		if inRequire || strings.HasPrefix(line, "require ") {
			matches := re.FindStringSubmatch(line)
			if len(matches) >= 3 {
				packages = append(packages, []string{matches[1], matches[2]})
			}
		}
	}

	fmt.Printf("  Checking %d Go packages via OSV...\n", len(packages))

	var findings []Finding
	for _, pkg := range packages {
		name, version := pkg[0], pkg[1]
		vulns, err := engine.QueryOSV(name, version, "Go")
		if err != nil {
			continue
		}
		for _, vuln := range vulns {
			findings = append(findings, Finding{
				File:     path,
				Package:  name,
				Version:  version,
				Rule:     fmt.Sprintf("[OSV] %s", vuln.ID),
				Severity: vuln.Severity,
				Message:  vuln.Summary,
				FixedIn:  vuln.FixedIn,
				CVEID:    vuln.ID,
				URL:      vuln.URL,
			})
		}
	}

	return findings, nil
}

// pom.xml parser (Maven)
func scanPomXML(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	artifactRe := regexp.MustCompile(`<artifactId>([^<]+)</artifactId>`)
	versionRe := regexp.MustCompile(`<version>([^<]+)</version>`)

	artifacts := artifactRe.FindAllStringSubmatch(content, -1)
	versions := versionRe.FindAllStringSubmatch(content, -1)

	var packages [][]string
	for i, artifact := range artifacts {
		if i < len(versions) {
			packages = append(packages, []string{artifact[1], versions[i][1]})
		}
	}

	fmt.Printf("  Checking %d Maven packages via OSV...\n", len(packages))

	var findings []Finding
	for _, pkg := range packages {
		name, version := pkg[0], pkg[1]
		vulns, err := engine.QueryOSV(name, version, "Maven")
		if err != nil {
			continue
		}
		for _, vuln := range vulns {
			findings = append(findings, Finding{
				File:     path,
				Package:  name,
				Version:  version,
				Rule:     fmt.Sprintf("[OSV] %s", vuln.ID),
				Severity: vuln.Severity,
				Message:  vuln.Summary,
				FixedIn:  vuln.FixedIn,
				CVEID:    vuln.ID,
				URL:      vuln.URL,
			})
		}
	}

	return findings, nil
}

func cleanVersion(version string) string {
	version = strings.TrimSpace(version)
	prefixes := []string{"^", "~", ">=", "<=", ">", "<", "="}
	for _, p := range prefixes {
		version = strings.TrimPrefix(version, p)
	}
	return strings.TrimSpace(version)
}