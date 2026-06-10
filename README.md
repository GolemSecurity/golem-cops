<div align="center">

# GOLEM COPS
### Code Offensive Prevention System

**An open-source security scanner for developers and DevSecOps teams.**

![Version](https://img.shields.io/badge/version-0.1.0-red)
![License](https://img.shields.io/badge/license-MIT-green)
![Language](https://img.shields.io/badge/built%20with-Go-blue)
![Status](https://img.shields.io/badge/status-active-brightgreen)

</div>

---

## What is GOLEM COPS?

GOLEM COPS is a command-line security scanner that helps developers find vulnerabilities before attackers do.

It scans your codebase for:
- Hardcoded secrets and API keys
- Dangerous code patterns (SAST)
- Vulnerable dependencies
- Missing HTTP security headers

GOLEM COPS is part of the [GOLEM Security](https://github.com/GolemSecurity) ecosystem — an open-source suite of security tools built for developers.

---

## Installation

### Windows

Download the latest `golem-cops.exe` from [Releases](https://github.com/GolemSecurity/golem-cops/releases) and add it to your PATH.

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
golem-cops secret .

# Static analysis (SAST)
golem-cops sast .

# Scan dependencies
golem-cops deps .

# Scan web security headers
golem-cops web https://example.com

# Run all scanners at once
golem-cops scan .

# Output as JSON
golem-cops scan . --json

# Save report to file
golem-cops scan . -o report.json
```

---

## Example Output