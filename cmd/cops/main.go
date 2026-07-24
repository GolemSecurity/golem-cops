package main

import (
	"fmt"
	"os"

	"github.com/GolemSecurity/golem-cops/internal/report"
	"github.com/GolemSecurity/golem-cops/internal/scanner/deps"
	"github.com/GolemSecurity/golem-cops/internal/scanner/sast"
	"github.com/GolemSecurity/golem-cops/internal/scanner/secret"
	"github.com/GolemSecurity/golem-cops/internal/scanner/web"
)

var outputFormat = "text"
var outputFile = ""

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		os.Exit(1)
	}

	// parse flags
	// parse flags
	filtered := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			outputFormat = "json"
		case "--sarif":
			outputFormat = "sarif"
		case "--output", "-o":
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			}
		default:
			filtered = append(filtered, args[i])
		}
	}

	if len(filtered) == 0 {
		printHelp()
		os.Exit(1)
	}

	// CLI structure: golem-cops <layer> <command> [target]
	// e.g. golem-cops code secret .
	// e.g. golem-cops code scan .
	// e.g. golem-cops scan . (runs all)

	switch filtered[0] {
	case "code":
		handleCode(filtered[1:])
	case "scan":
		target := "."
		if len(filtered) >= 2 {
			target = filtered[1]
		}
		runFullScan(target)
	default:
		fmt.Printf("[GOLEM COPS] Unknown command: %s\n", filtered[0])
		printHelp()
		os.Exit(1)
	}
}

func handleCode(args []string) {
	if len(args) == 0 {
		printCodeHelp()
		os.Exit(1)
	}

	command := args[0]
	target := "."
	if len(args) >= 2 {
		target = args[1]
	}

	switch command {
	case "secret":
		runSecretScan(target)
	case "sast":
		runSASTScan(target)
	case "deps":
		runDepsScan(target)
	case "web":
		if len(args) < 2 {
			fmt.Println("[ERROR] Please provide a URL. Example: golem-cops code web https://example.com")
			os.Exit(1)
		}
		runWebScan(args[1])
	case "scan":
		runCodeScan(target)
	default:
		fmt.Printf("[GOLEM COPS] Unknown code command: %s\n", command)
		printCodeHelp()
		os.Exit(1)
	}
}

func runSecretScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Scanning for secrets in: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
	}

	findings, err := secret.Scan(target)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	for _, f := range findings {
		r.AddFindings([]report.Finding{{
			Scanner:     "secret",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Match:       f.Match,
			Message:     f.Description,
			Remediation: f.Remediation,
		}})
	}

	outputReport(r)
}

func runSASTScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Running SAST scan in: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
	}

	findings, err := sast.Scan(target)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	for _, f := range findings {
		r.AddFindings([]report.Finding{{
			Scanner:     "sast",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Code:        f.Code,
			Message:     f.Message,
			Remediation: f.Remediation,
		}})
	}

	outputReport(r)
}

func runDepsScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Scanning dependencies in: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
	}

	findings, err := deps.Scan(target)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	for _, f := range findings {
		r.AddFindings([]report.Finding{{
			Scanner:     "deps",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Package:     f.Package,
			Version:     f.Version,
			FixedIn:     f.FixedIn,
			CVEID:       f.CVEID,
			AdvisoryURL: f.URL,
			Message:     f.Message,
		}})
	}

	outputReport(r)
}

func runWebScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Scanning web headers for: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
	}

	findings, err := web.Scan(target)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	for _, f := range findings {
		r.AddFindings([]report.Finding{{
			Scanner:  "web",
			Rule:     f.Rule,
			Severity: f.Severity,
			URL:      f.URL,
			Message:  f.Message,
		}})
	}

	outputReport(r)
}

func runCodeScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Running full code scan on: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
		fmt.Println("  Running secret scan...")
	}

	secretFindings, _ := secret.Scan(target)
	for _, f := range secretFindings {
		r.AddFindings([]report.Finding{{
			Scanner:     "secret",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Match:       f.Match,
			Message:     f.Description,
			Remediation: f.Remediation,
		}})
	}

	if outputFormat == "text" {
		fmt.Println("  Running SAST scan...")
	}

	sastFindings, _ := sast.Scan(target)
	for _, f := range sastFindings {
		r.AddFindings([]report.Finding{{
			Scanner:     "sast",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Code:        f.Code,
			Message:     f.Message,
			Remediation: f.Remediation,
		}})
	}

	if outputFormat == "text" {
		fmt.Println("  Running dependency scan...")
	}

	depsFindings, _ := deps.Scan(target)
	for _, f := range depsFindings {
		r.AddFindings([]report.Finding{{
			Scanner:  "deps",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Package:  f.Package,
			Version:  f.Version,
			Message:  f.Message,
		}})
	}

	outputReport(r)
}

func runFullScan(target string) {
	r := report.NewReport(target)

	if outputFormat == "text" {
		fmt.Printf("\n[GOLEM COPS] Running full scan on: %s\n", target)
		fmt.Println("─────────────────────────────────────────")
		fmt.Println("  Running secret scan...")
	}

	secretFindings, _ := secret.Scan(target)
	for _, f := range secretFindings {
		r.AddFindings([]report.Finding{{
			Scanner:     "secret",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Match:       f.Match,
			Message:     f.Description,
			Remediation: f.Remediation,
		}})
	}

	if outputFormat == "text" {
		fmt.Println("  Running SAST scan...")
	}

	sastFindings, _ := sast.Scan(target)
	for _, f := range sastFindings {
		r.AddFindings([]report.Finding{{
			Scanner:     "sast",
			Rule:        f.Rule,
			Severity:    f.Severity,
			File:        f.File,
			Line:        f.Line,
			Code:        f.Code,
			Message:     f.Message,
			Remediation: f.Remediation,
		}})
	}

	if outputFormat == "text" {
		fmt.Println("  Running dependency scan...")
	}

	depsFindings, _ := deps.Scan(target)
	for _, f := range depsFindings {
		r.AddFindings([]report.Finding{{
			Scanner:  "deps",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Package:  f.Package,
			Version:  f.Version,
			Message:  f.Message,
		}})
	}

	outputReport(r)
}

func outputReport(r *report.Report) {
	r.Calculate()

	switch outputFormat {
	case "json":
		if outputFile != "" {
			err := r.SaveJSON(outputFile)
			if err != nil {
				fmt.Printf("[ERROR] Could not save report: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[✓] JSON report saved to %s\n", outputFile)
		} else {
			r.PrintJSON()
		}

	case "sarif":
		if outputFile != "" {
			err := r.SaveSARIF(outputFile)
			if err != nil {
				fmt.Printf("[ERROR] Could not save SARIF report: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[✓] SARIF report saved to %s\n", outputFile)
		} else {
			r.PrintSARIF()
		}

	default:
		r.PrintText()
		if outputFile != "" {
			err := r.SaveJSON(outputFile)
			if err != nil {
				fmt.Printf("[ERROR] Could not save report: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[✓] Report saved to %s\n", outputFile)
		}
	}
}

func printHelp() {
	fmt.Println(`
GOLEM COPS - Continuous Operations Protection System
Version 1.0.0

Usage:
  golem-cops <layer> <command> [target] [flags]

Layers:
  code     Protect your source code
  scan     Run all available scans

Code Commands:
  secret   Scan for hardcoded secrets and API keys
  sast     Static analysis for code vulnerabilities
  deps     Scan dependencies for known issues
  web      Scan web endpoints for security headers
  scan     Run all code scanners at once

Flags:
  --json        Output results as JSON
  --sarif       Output results in SARIF format (for GitHub, VS Code, CI tools)
  -o <file>     Save report to file

Examples:
  golem-cops code secret .
  golem-cops code sast .
  golem-cops code deps .
  golem-cops code web https://example.com
  golem-cops code scan .
  golem-cops scan .
  golem-cops scan . --json
  golem-cops scan . --sarif
  golem-cops scan . --sarif -o results.sarif
  golem-cops scan . -o report.json
`)
}

func printCodeHelp() {
	fmt.Println(`
GOLEM COPS - Code Protection

Usage:
  golem-cops code <command> [target]

Commands:
  secret   Scan for hardcoded secrets and API keys
  sast     Static analysis for code vulnerabilities
  deps     Scan dependencies for known issues
  web      Scan web endpoints for security headers
  scan     Run all code scanners

Examples:
  golem-cops code secret .
  golem-cops code sast .
  golem-cops code scan .
  golem-cops code web https://example.com
`)
}