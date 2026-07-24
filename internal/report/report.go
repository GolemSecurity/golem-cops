package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Severity string

const (
	CRITICAL Severity = "CRITICAL"
	HIGH     Severity = "HIGH"
	MEDIUM   Severity = "MEDIUM"
	LOW      Severity = "LOW"
)

type Finding struct {
	Scanner     string `json:"scanner"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	URL         string `json:"url,omitempty"`
	Package     string `json:"package,omitempty"`
	Version     string `json:"version,omitempty"`
	FixedIn     string `json:"fixed_in,omitempty"`
	CVEID       string `json:"cve_id,omitempty"`
	AdvisoryURL string `json:"advisory_url,omitempty"`
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	Match       string `json:"match,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Timestamp string    `json:"timestamp"`
	Summary   Summary   `json:"summary"`
	Findings  []Finding `json:"findings"`
}

type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func NewReport(target string) *Report {
	return &Report{
		Tool:      "GOLEM COPS",
		Version:   "1.0.0",
		Target:    target,
		Timestamp: time.Now().Format(time.RFC3339),
		Findings:  []Finding{},
	}
}

func (r *Report) AddFindings(findings []Finding) {
	r.Findings = append(r.Findings, findings...)
}

func (r *Report) Calculate() {
	r.Summary.Total = len(r.Findings)
	for _, f := range r.Findings {
		switch f.Severity {
		case "CRITICAL":
			r.Summary.Critical++
		case "HIGH":
			r.Summary.High++
		case "MEDIUM":
			r.Summary.Medium++
		case "LOW":
			r.Summary.Low++
		}
	}
}

func (r *Report) PrintText() {
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("  GOLEM COPS — Scan Summary")
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Target    : %s\n", r.Target)
	fmt.Printf("  Timestamp : %s\n", r.Timestamp)
	fmt.Printf("  Total     : %d finding(s)\n", r.Summary.Total)
	fmt.Println()
	fmt.Printf("  CRITICAL  : %d\n", r.Summary.Critical)
	fmt.Printf("  HIGH      : %d\n", r.Summary.High)
	fmt.Printf("  MEDIUM    : %d\n", r.Summary.Medium)
	fmt.Printf("  LOW       : %d\n", r.Summary.Low)
	fmt.Println("─────────────────────────────────────────")

	if r.Summary.Total == 0 {
		fmt.Println("  [✓] No issues found.")
		fmt.Println("─────────────────────────────────────────")
		return
	}

	fmt.Println()
	for _, f := range r.Findings {
		fmt.Printf("  [%s] %s\n", f.Severity, f.Rule)
		if f.File != "" {
			line := ""
			if f.Line > 0 {
				line = fmt.Sprintf(":%d", f.Line)
			}
			fmt.Printf("  File    : %s%s\n", f.File, line)
		}
		if f.URL != "" {
			fmt.Printf("  URL     : %s\n", f.URL)
		}
		if f.Package != "" {
			fmt.Printf("  Package : %s %s\n", f.Package, f.Version)
		}
		if f.FixedIn != "" {
			fmt.Printf("  Fixed In: %s\n", f.FixedIn)
		}
		if f.AdvisoryURL != "" {
			fmt.Printf("  Advisory: %s\n", f.AdvisoryURL)
		}
		if f.Code != "" {
			fmt.Printf("  Code    : %s\n", f.Code)
		}
		if f.Match != "" {
			fmt.Printf("  Match   : %s\n", f.Match)
		}
		if f.Message != "" {
			fmt.Printf("  Why     : %s\n", f.Message)
		}
		if f.Remediation != "" {
			fmt.Printf("  Fix     : %s\n", f.Remediation)
		}
		fmt.Println()
	}
}

func (r *Report) PrintJSON() error {
	r.Calculate()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (r *Report) SaveJSON(path string) error {
	r.Calculate()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}