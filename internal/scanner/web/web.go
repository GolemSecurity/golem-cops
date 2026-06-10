package web

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Finding struct {
	URL      string
	Rule     string
	Severity string
	Message  string
	Found    bool
}

type HeaderRule struct {
	ID           string
	Header       string
	Name         string
	Severity     string
	MissingMsg   string
	PresentMsg   string
	ValidateFunc func(value string) (bool, string)
}

var headerRules = []HeaderRule{
	{
		ID:         "WEB001",
		Header:     "Strict-Transport-Security",
		Name:       "Missing HSTS",
		Severity:   "HIGH",
		MissingMsg: "HSTS not set. Browser connections can be downgraded to HTTP.",
		PresentMsg: "HSTS is configured.",
	},
	{
		ID:         "WEB002",
		Header:     "Content-Security-Policy",
		Name:       "Missing CSP",
		Severity:   "HIGH",
		MissingMsg: "No Content Security Policy. XSS attacks are more likely to succeed.",
		PresentMsg: "CSP is configured.",
	},
	{
		ID:         "WEB003",
		Header:     "X-Frame-Options",
		Name:       "Missing X-Frame-Options",
		Severity:   "MEDIUM",
		MissingMsg: "X-Frame-Options not set. Site may be vulnerable to clickjacking.",
		PresentMsg: "Clickjacking protection is enabled.",
	},
	{
		ID:         "WEB004",
		Header:     "X-Content-Type-Options",
		Name:       "Missing X-Content-Type-Options",
		Severity:   "MEDIUM",
		MissingMsg: "X-Content-Type-Options not set. MIME sniffing attacks are possible.",
		PresentMsg: "MIME sniffing protection enabled.",
	},
	{
		ID:         "WEB005",
		Header:     "Referrer-Policy",
		Name:       "Missing Referrer-Policy",
		Severity:   "LOW",
		MissingMsg: "Referrer-Policy not set. Sensitive URLs may leak to third parties.",
		PresentMsg: "Referrer-Policy is configured.",
	},
	{
		ID:         "WEB006",
		Header:     "Permissions-Policy",
		Name:       "Missing Permissions-Policy",
		Severity:   "LOW",
		MissingMsg: "Permissions-Policy not set. Browser features are not restricted.",
		PresentMsg: "Permissions-Policy is configured.",
	},
	{
		ID:         "WEB007",
		Header:     "X-Powered-By",
		Name:       "Technology Disclosure",
		Severity:   "LOW",
		MissingMsg: "",
		PresentMsg: "X-Powered-By header exposes technology stack. Consider removing it.",
	},
	{
		ID:         "WEB008",
		Header:     "Server",
		Name:       "Server Version Disclosure",
		Severity:   "LOW",
		MissingMsg: "",
		PresentMsg: "Server header exposes software version. Consider removing it.",
	},
}

func Scan(target string) ([]Finding, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	fmt.Printf("  Connecting to %s...\n", target)

	resp, err := client.Get(target)
	if err != nil {
		// try http if https fails
		if strings.HasPrefix(target, "https://") {
			target = strings.Replace(target, "https://", "http://", 1)
			resp, err = client.Get(target)
			if err != nil {
				return nil, fmt.Errorf("could not connect to %s: %v", target, err)
			}
		} else {
			return nil, fmt.Errorf("could not connect to %s: %v", target, err)
		}
	}
	defer resp.Body.Close()

	fmt.Printf("  Response: %d %s\n\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	var findings []Finding

	for _, rule := range headerRules {
		value := resp.Header.Get(rule.Header)

		// headers we flag when PRESENT (info disclosure)
		if rule.Header == "X-Powered-By" || rule.Header == "Server" {
			if value != "" {
				findings = append(findings, Finding{
					URL:      target,
					Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
					Severity: rule.Severity,
					Message:  fmt.Sprintf("%s Value: %s", rule.PresentMsg, value),
					Found:    true,
				})
			}
			continue
		}

		// headers we flag when MISSING (protection headers)
		if value == "" {
			findings = append(findings, Finding{
				URL:      target,
				Rule:     fmt.Sprintf("[%s] %s", rule.ID, rule.Name),
				Severity: rule.Severity,
				Message:  rule.MissingMsg,
				Found:    false,
			})
		}
	}

	return findings, nil
}