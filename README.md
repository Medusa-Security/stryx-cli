# STRYX

**AI-Powered Dynamic Application Security Testing (DAST)**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Build Status](https://github.com/medusa-Security/stryx/actions/workflows/ci.yml/badge.svg)](https://github.com/medusa-Security/stryx/actions)

STRYX is a developer-first, AI-assisted DAST engine that crawls, maps, and tests the live attack surface of web applications. It discovers hidden endpoints, simulates real attacker behavior, and detects exploitable vulnerabilities with minimal false positives. Every finding carries full evidence (request, response, status code, payload, confidence score) -- no heuristic-only results.

**Design philosophy: high signal, low noise.**

## How It Fits Into MEDUSA

- **Remy** -- SAST, analyzes source code pre-deployment.
- **STRYX** -- DAST, validates a running application's live attack surface and exploitability.
- **MEDUSA** -- Aggregates findings from both, correlates static and runtime issues, estimates business impact, provides centralized security management.

## Architecture

```
CLI -> Configuration -> Attack Orchestrator -> { Endpoint Discovery }
                                                        |
                                         Authentication Engine
                                         Authorization Engine
                                         Injection Engine
                                         API Fuzzer
                                         AI Attack Planner
                                         Evidence Collector
                                         Report Generator
                                                        |
                                              Target Application
```

## Installation

```bash
# From PyPI
pip install stryx

# From source
git clone https://github.com/medusa-Security/stryx.git
cd stryx
pip install -e .
```

## Quickstart

```bash
# Run a full scan
stryx scan http://localhost:8000

# Output:
# STRYX Scan Results
# Target: http://localhost:8000
# Total Findings: 3
# Breakdown: CRITICAL: 1 | HIGH: 1 | MEDIUM: 1
```

## Core Modules

| Module | Purpose |
|--------|---------|
| Endpoint Discovery | Crawls targets, extracts APIs from OpenAPI/Swagger, sitemaps, JS files, GraphQL |
| Authentication Scanner | Tests missing auth, weak JWTs, session fixation, cookie security |
| Authorization Scanner | Tests IDOR, privilege escalation, admin access, multi-tenant escape |
| Injection Engine | SQL, NoSQL, command, SSRF, path traversal, XXE, SSTI, LDAP injection |
| API Fuzzer | Parameter mutation, boundary values, type confusion, nested JSON |
| CORS Scanner | Detects misconfigured CORS policies and origin reflection |
| GraphQL Scanner | Tests introspection exposure, query depth limiting |
| AI Attack Planner | Constructs multi-step attack chains across findings |
| Evidence Engine | Enforces evidence requirements on every finding |

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `stryx scan <url>` | Run full security scan |
| `stryx crawl <url>` | Crawl and discover endpoints |
| `stryx auth <url>` | Run authentication tests |
| `stryx fuzz <url>` | Run API fuzzing tests |
| `stryx report <url>` | Generate reports |
| `stryx config` | View/update configuration |
| `stryx providers` | List supported AI providers |
| `stryx update` | Update STRYX |

### Flags

| Flag | Description |
|------|-------------|
| `--deep` | Enable deep scanning |
| `--json <file>` | Output JSON report |
| `--html <file>` | Output HTML report |
| `--markdown <file>` | Output Markdown report |
| `--threads <n>` | Concurrent threads (1-200) |
| `--timeout <s>` | HTTP timeout in seconds |
| `--headers <json>` | Custom headers |
| `--cookies <str>` | Authentication cookies |
| `--proxy <url>` | HTTP proxy |
| `--wordlist <file>` | Custom wordlist |
| `--rate <n>` | Requests per second limit |

## Configuration

```yaml
provider: groq
model: llama-3.3-70b-versatile
threads: 20
timeout: 10
crawl_depth: 5
respect_robots: false
ai_attack_planning: true
modules:
  auth: true
  authorization: true
  injection: true
  fuzzing: true
```

Supported AI providers: Groq, OpenAI, Anthropic, OpenRouter, Ollama, XAI, NVIDIA NIM.

## Sample Report

```
+--------------------------------------------------------------------+
| STRYX Scan Results                                                 |
| Target: http://localhost:8000                                      |
| Total Findings: 3                                                  |
| Breakdown: CRITICAL: 1 | HIGH: 1 | MEDIUM: 1                     |
+--------------------------------------------------------------------+

[#] [CRITICAL] Unauthenticated access to /admin
    Endpoint: http://localhost:8000/admin
    CWE: CWE-306 | Scanner: auth
    Confidence: 70%
    Evidence: GET http://localhost:8000/admin -> 200
```

## Roadmap

### v0.1 (this build)

- [ ] HTTP crawler
- [ ] Endpoint discovery
- [ ] Authentication scanning
- [ ] Authorization testing
- [ ] Basic injection testing
- [ ] JSON/HTML reports

### v0.5

- [ ] Browser automation
- [ ] GraphQL support
- [ ] Multi-threaded fuzzing
- [ ] AI attack planning
- [ ] Custom payloads
- [ ] Plugin SDK

### v1.0

- [ ] Autonomous attack chaining
- [ ] Headless browser exploitation
- [ ] CI/CD integration
- [ ] Distributed scanning
- [ ] Cloud dashboards (MEDUSA integration)
- [ ] AI-powered exploit reasoning

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Policy

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in STRYX itself.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

Built by Akhilesh Varma (ak495867) under Medusa Security.
