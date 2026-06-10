package main

import (
	"fmt"
	"os"

	"github.com/GolemSecurity/golem/internal/report"
	"github.com/GolemSecurity/golem/internal/scanner/deps"
	"github.com/GolemSecurity/golem/internal/scanner/sast"
	"github.com/GolemSecurity/golem/internal/scanner/secret"
	"github.com/GolemSecurity/golem/internal/scanner/web"
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
	filtered := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			outputFormat = "json"
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

	command := filtered[0]

	switch command {
	case "secret":
		target := "."
		if len(filtered) >= 2 {
			target = filtered[1]
		}
		runSecretScan(target)
	case "sast":
		target := "."
		if len(filtered) >= 2 {
			target = filtered[1]
		}
		runSASTScan(target)
	case "deps":
		target := "."
		if len(filtered) >= 2 {
			target = filtered[1]
		}
		runDepsScan(target)
	case "web":
		if len(filtered) < 2 {
			fmt.Println("[ERROR] Please provide a URL. Example: golem-cops web https://example.com")
			os.Exit(1)
		}
		runWebScan(filtered[1])
	case "scan":
		target := "."
		if len(filtered) >= 2 {
			target = filtered[1]
		}
		runFullScan(target)
	default:
		fmt.Printf("[GOLEM COPS] Unknown command: %s\n", command)
		printHelp()
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
			Scanner:  "secret",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Match:    f.Match,
			Message:  f.Rule,
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
			Scanner:  "sast",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Code:     f.Code,
			Message:  f.Message,
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
			Scanner:  "secret",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Match:    f.Match,
			Message:  f.Rule,
		}})
	}

	if outputFormat == "text" {
		fmt.Println("  Running SAST scan...")
	}

	sastFindings, _ := sast.Scan(target)
	for _, f := range sastFindings {
		r.AddFindings([]report.Finding{{
			Scanner:  "sast",
			Rule:     f.Rule,
			Severity: f.Severity,
			File:     f.File,
			Line:     f.Line,
			Code:     f.Code,
			Message:  f.Message,
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

	if outputFormat == "json" {
		if outputFile != "" {
			err := r.SaveJSON(outputFile)
			if err != nil {
				fmt.Printf("[ERROR] Could not save report: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("[✓] Report saved to %s\n", outputFile)
		} else {
			r.PrintJSON()
		}
		return
	}

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

func printHelp() {
	fmt.Println(`
GOLEM COPS - Code Offensive Prevention System
Version 0.1.0

Usage:
  golem-cops <command> [target] [flags]

Commands:
  secret   Scan for hardcoded secrets and API keys
  sast     Static analysis for code vulnerabilities
  deps     Scan dependencies for known issues
  web      Scan web endpoints for security headers
  scan     Run all scanners at once

Flags:
  --json        Output results as JSON
  -o <file>     Save report to file

Examples:
  golem-cops secret .
  golem-cops sast .
  golem-cops deps .
  golem-cops web https://example.com
  golem-cops scan .
  golem-cops scan . --json
  golem-cops scan . -o report.json
`)
}