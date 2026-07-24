package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const osvAPIURL = "https://api.osv.dev/v1/query"

type OSVQuery struct {
	Version string     `json:"version"`
	Package OSVPackage `json:"package"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []OSVSeverity `json:"severity"`
	Affected []OSVAffected `json:"affected"`
	References []OSVReference `json:"references"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Ranges []OSVRange `json:"ranges"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type VulnResult struct {
	ID       string
	Summary  string
	Severity string
	FixedIn  string
	URL      string
}

func QueryOSV(name, version, ecosystem string) ([]VulnResult, error) {
	query := OSVQuery{
		Version: version,
		Package: OSVPackage{
			Name:      name,
			Ecosystem: ecosystem,
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(osvAPIURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("OSV API unreachable: %v", err)
	}
	defer resp.Body.Close()

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	var results []VulnResult
	for _, vuln := range osvResp.Vulns {
		result := VulnResult{
			ID:      vuln.ID,
			Summary: vuln.Summary,
		}

		// extract severity
		result.Severity = extractSeverity(vuln)

		// extract fix version
		result.FixedIn = extractFixVersion(vuln)

		// extract reference URL
		for _, ref := range vuln.References {
			if ref.Type == "WEB" || ref.Type == "ADVISORY" {
				result.URL = ref.URL
				break
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func extractSeverity(vuln OSVVuln) string {
	for _, s := range vuln.Severity {
		score := s.Score
		// CVSS score to severity mapping
		if len(score) > 0 {
			switch {
			case contains(score, "9.") || contains(score, "10."):
				return "CRITICAL"
			case contains(score, "7.") || contains(score, "8."):
				return "HIGH"
			case contains(score, "4.") || contains(score, "5.") || contains(score, "6."):
				return "MEDIUM"
			default:
				return "LOW"
			}
		}
	}

	// fallback based on ID prefix
	if len(vuln.ID) > 0 {
		switch {
		case contains(vuln.ID, "GHSA"):
			return "HIGH"
		case contains(vuln.ID, "CVE"):
			return "MEDIUM"
		default:
			return "LOW"
		}
	}

	return "MEDIUM"
}

func extractFixVersion(vuln OSVVuln) string {
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return "No fix available"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}