package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// SARIF 2.1.0 schema structures
type SARIFReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []SARIFRun  `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
	Rules   []SARIFRule   `json:"rules"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name"`
	ShortDescription SARIFMessage              `json:"shortDescription"`
	FullDescription  SARIFMessage              `json:"fullDescription"`
	HelpURI          string                    `json:"helpUri,omitempty"`
	Properties       SARIFRuleProperties       `json:"properties"`
}

type SARIFRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations,omitempty"`
	WebRequest *SARIFWebRequest `json:"webRequest,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFWebRequest struct {
	Target string `json:"target"`
}

func (r *Report) ToSARIF() SARIFReport {
	rules := []SARIFRule{}
	rulesSeen := map[string]bool{}
	results := []SARIFResult{}

	for _, f := range r.Findings {
		ruleID := extractRuleID(f.Rule)

		// add rule definition if not seen
		if !rulesSeen[ruleID] {
			rulesSeen[ruleID] = true
			rule := SARIFRule{
				ID:   ruleID,
				Name: f.Rule,
				ShortDescription: SARIFMessage{
					Text: f.Message,
				},
				FullDescription: SARIFMessage{
					Text: f.Message,
				},
				Properties: SARIFRuleProperties{
					Severity: f.Severity,
					Tags:     []string{f.Scanner},
				},
			}
			if f.AdvisoryURL != "" {
				rule.HelpURI = f.AdvisoryURL
			}
			rules = append(rules, rule)
		}

		// build result
		result := SARIFResult{
			RuleID: ruleID,
			Level:  severityToLevel(f.Severity),
			Message: SARIFMessage{
				Text: buildMessage(f),
			},
		}

		// add location for file findings
		if f.File != "" {
			line := f.Line
			if line == 0 {
				line = 1
			}
			uri := strings.ReplaceAll(f.File, "\\", "/")
			result.Locations = []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: uri,
						},
						Region: SARIFRegion{
							StartLine: line,
						},
					},
				},
			}
		}

		// add web request for URL findings
		if f.URL != "" {
			result.WebRequest = &SARIFWebRequest{
				Target: f.URL,
			}
		}

		results = append(results, result)
	}

	return SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "GOLEM COPS",
						Version:        r.Version,
						InformationURI: "https://github.com/GolemSecurity/golem-cops",
						Rules:          rules,
					},
				},
				Results: results,
				Rules:   rules,
			},
		},
	}
}

func (r *Report) PrintSARIF() error {
	sarif := r.ToSARIF()
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (r *Report) SaveSARIF(path string) error {
	sarif := r.ToSARIF()
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func severityToLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "note"
	}
}

func extractRuleID(rule string) string {
	// extract ID from "[GOLEM-S001] Hardcoded Password" → "GOLEM-S001"
	if len(rule) > 0 && rule[0] == '[' {
		end := strings.Index(rule, "]")
		if end > 0 {
			return rule[1:end]
		}
	}
	return rule
}

func buildMessage(f Finding) string {
	msg := f.Message
	if f.Match != "" {
		msg += fmt.Sprintf(" Match: %s", f.Match)
	}
	if f.Package != "" {
		msg += fmt.Sprintf(" Package: %s %s", f.Package, f.Version)
	}
	if f.FixedIn != "" {
		msg += fmt.Sprintf(" Fixed in: %s", f.FixedIn)
	}
	if f.Remediation != "" {
		msg += fmt.Sprintf(" Remediation: %s", f.Remediation)
	}
	return msg
}