# Contributing to GOLEM COPS

Thank you for your interest in contributing to GOLEM COPS.

GOLEM COPS is a community-driven security tool. The most impactful way to contribute is by adding new detection rules.

---

## Adding New Rules

Rules live in the `rules/` folder and are written in YAML. No Go knowledge required.

### Rule Structure

```yaml
version: "1.0"
category: code
scanner: secret  # secret | sast | web

rules:
  - id: GOLEM-S009          # unique ID, increment from last
    name: My Rule Name
    pattern: 'your-regex-here'
    severity: HIGH           # CRITICAL | HIGH | MEDIUM | LOW
    description: What this rule detects.
    remediation: How to fix it.
    languages: [.js, .py]   # omit for all languages
    tags: [secret, api-key]
```

### Rule Locations

| Scanner | Rule File |
|---------|-----------|
| Secret detection | `rules/code/secret/rules.yaml` |
| Static analysis | `rules/code/sast/rules.yaml` |
| Web headers | `rules/code/web/rules.yaml` |
| Build security | `rules/build/` *(coming in v2.0.0)* |
| Container security | `rules/container/` *(coming in v3.0.0)* |
| Deployment security | `rules/deploy/` *(coming in v4.0.0)* |
| Operational security | `rules/ops/` *(coming in v5.0.0)* |

### Example — Adding a Secret Rule

Open `rules/code/secret/rules.yaml` and add:

```yaml
  - id: GOLEM-S009
    name: Stripe API Key
    pattern: 'sk_live_[a-zA-Z0-9]{24,}'
    severity: CRITICAL
    description: Stripe live API key detected in source code.
    remediation: Revoke the key immediately on Stripe dashboard and use environment variables.
    tags: [secret, stripe, payment, credential]
```

### Example — Adding a SAST Rule

Open `rules/code/sast/rules.yaml` and add:

```yaml
  - id: GOLEM-A011
    name: Unsafe Deserialization
    pattern: '(?i)(pickle\.loads|unserialize|yaml\.load\()'
    severity: HIGH
    description: Unsafe deserialization detected. Can lead to remote code execution.
    remediation: Use safe alternatives like yaml.safe_load() or avoid deserializing untrusted data.
    languages: [.py, .php]
    tags: [injection, deserialization, rce]
```

---

## Testing Your Rule

After adding a rule, test it:

```bash
# create a test file with a pattern your rule should catch
echo 'sk_live_abcdefghijklmnopqrstuvwx' > test_rule.txt

# run the scanner
golem-cops code secret .

# verify your rule fires, then delete the test file
del test_rule.txt
```

---

## Submitting a Pull Request

1. Fork the repository
2. Add your rule to the appropriate YAML file
3. Test it locally
4. Submit a PR with:
   - What the rule detects
   - Why it is a security risk
   - A test case that triggers it

---

## Reporting False Positives

If a rule is producing too many false positives, open an issue with:
- The rule ID
- Example code that triggers it incorrectly
- Why it should not be flagged

---

## Code Contributions

If you want to contribute Go code:

```bash
git clone https://github.com/GolemSecurity/golem-cops.git
cd golem-cops
go build ./cmd/cops
go run cmd/cops/main.go code scan .
```

---

## Roadmap

See the full version roadmap in the README. Future versions will add rules for:
- Build environment security (v2.0.0)
- Container and Kubernetes security (v3.0.0)
- Infrastructure as Code security (v4.0.0)
- Operational security monitoring (v5.0.0)

---

Built with purpose by [GolemSecurity](https://github.com/GolemSecurity)