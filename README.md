<div align="center">

# GOLEM COPS
### Continuous Operations Protection System

**An open-source security scanner for developers and DevSecOps teams.**

![Version](https://img.shields.io/badge/version-1.0.0-red)
![License](https://img.shields.io/badge/license-MIT-green)
![Language](https://img.shields.io/badge/built%20with-Go-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

</div>

---

## What is GOLEM COPS?

GOLEM COPS is a command-line security scanner that helps developers find vulnerabilities before attackers do.

It integrates directly into your CI/CD pipeline and runs automatically on every code push — blocking deployments when critical security issues are found.

GOLEM COPS is part of the [GOLEM Security](https://github.com/GolemSecurity) ecosystem — an open-source suite of security tools built for developers.

---

## Features

- **Secret Scanner** — detects hardcoded passwords, API keys, tokens, private keys
- **SAST Scanner** — static analysis for dangerous code patterns
- **Dependency Scanner** — live CVE data via OSV API (no stale databases)
- **Web Scanner** — checks HTTP security headers on any URL
- **YAML Rule Engine** — add your own rules without touching Go code
- **SARIF Output** — native integration with GitHub, VS Code, and CI tools
- **CI/CD Ready** — GitHub Actions and GitLab CI integration out of the box

---

## Installation

### Linux / macOS (one command)

```bash
curl -sSL https://raw.githubusercontent.com/GolemSecurity/golem-cops/main/install.sh | bash
```

### Windows

Download the latest `golem-cops-windows-amd64.exe` from [Releases](https://github.com/GolemSecurity/golem-cops/releases/latest) and add it to your PATH.

### Build from source

```bash
git clone https://github.com/GolemSecurity/golem-cops.git
cd golem-cops
go build -o golem-cops ./cmd/cops
```

---

## Usage

```bash
# Scan for hardcoded secrets
golem-cops code secret .

# Static analysis (SAST)
golem-cops code sast .

# Scan dependencies (live CVE data)
golem-cops code deps .

# Scan web security headers
golem-cops code web https://example.com

# Run all code scanners at once
golem-cops code scan .

# Run everything
golem-cops scan .

# Output as JSON
golem-cops scan . --json

# Output as SARIF (for GitHub, VS Code, CI tools)
golem-cops scan . --sarif

# Save report to file
golem-cops scan . --sarif -o results.sarif
golem-cops scan . -o report.json
```

---

## CI/CD Integration

### GitHub Actions

Add this to your repository at `.github/workflows/golem-cops.yml`:

```yaml
name: GOLEM COPS Security Scan

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

permissions:
  contents: read
  security-events: write

jobs:
  golem-cops-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download GOLEM COPS
        run: |
          curl -sSL https://github.com/GolemSecurity/golem-cops/releases/latest/download/golem-cops-linux-amd64 -o golem-cops
          chmod +x golem-cops

      - name: Run security scan
        run: ./golem-cops code scan . --sarif -o results.sarif
        continue-on-error: true

      - name: Upload results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on critical findings
        run: |
          ./golem-cops code scan . --json -o results.json
          CRITICAL=$(cat results.json | grep -c '"severity": "CRITICAL"' || true)
          if [ "$CRITICAL" -gt "0" ]; then
            echo "GOLEM COPS found $CRITICAL CRITICAL issue(s). Pipeline blocked."
            exit 1
          fi
          echo "No critical issues found."
```

### GitLab CI

Add this to your `.gitlab-ci.yml`:

```yaml
golem-cops-security-scan:
  stage: security
  image: ubuntu:latest
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl
    - curl -sSL https://github.com/GolemSecurity/golem-cops/releases/latest/download/golem-cops-linux-amd64 -o golem-cops
    - chmod +x golem-cops
  script:
    - ./golem-cops code scan . --sarif -o results.sarif
    - ./golem-cops code scan . --json -o results.json
    - |
      CRITICAL=$(cat results.json | grep -c '"severity": "CRITICAL"' || true)
      if [ "$CRITICAL" -gt "0" ]; then
        echo "GOLEM COPS found $CRITICAL CRITICAL issue(s). Pipeline blocked."
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - results.sarif
      - results.json
    expire_in: 30 days
```

### Any Other Pipeline

```bash
# Install
curl -sSL https://raw.githubusercontent.com/GolemSecurity/golem-cops/main/install.sh | bash

# Scan and fail on critical findings
golem-cops code scan . --json -o results.json
CRITICAL=$(cat results.json | grep -c '"severity": "CRITICAL"' || true)
if [ "$CRITICAL" -gt "0" ]; then exit 1; fi
```

---

## Custom Rules

GOLEM COPS uses a YAML rule engine. Add your own rules without touching Go code.

Example — add a custom secret rule in `rules/code/secret/rules.yaml`:

```yaml
  - id: GOLEM-S009
    name: Stripe API Key
    pattern: 'YOUR_REGEX_PATTERN_HERE'
    severity: CRITICAL
    description: Stripe live API key detected in source code.
    remediation: Revoke immediately and use environment variables.
    tags: [secret, stripe, payment]
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full rule writing guide.

---

## Scanners

| Scanner | Description | Data Source | Status |
|---------|-------------|-------------|--------|
| Secret | Detects hardcoded secrets | YAML rules | ✅ Active |
| SAST | Static analysis for dangerous patterns | YAML rules | ✅ Active |
| Deps | Vulnerable dependency detection | Live OSV API | ✅ Active |
| Web | HTTP security header checks | YAML rules | ✅ Active |

---

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | default | Human readable terminal output |
| JSON | `--json` | Machine readable, custom integrations |
| SARIF | `--sarif` | GitHub, VS Code, CI/CD platforms |

---

## Roadmap

```
v0.1.0  ✅  Manual scanner — secret, SAST, deps, web
v1.0.0  ✅  YAML rules, live OSV data, SARIF, CI/CD integration
v2.0.0  🔜  Build environment protection
v3.0.0  🔜  Container and Kubernetes protection
v4.0.0  🔜  Deployment protection
v5.0.0  🔜  Post-production operational protection
```
---

## Contributing

Contributions are welcome. The easiest way to contribute is by adding detection rules.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with purpose by <a href="https://github.com/GolemSecurity">GolemSecurity</a>
</div>