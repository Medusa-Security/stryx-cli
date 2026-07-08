# STRYX Usage Guide

Practical, task-oriented guide for using STRYX.

## 1. Installation

```bash
pip install stryx
```

Or from source:

```bash
git clone https://github.com/medusa-Security/stryx.git
cd stryx
pip install -e .
```

## 2. First Scan

```bash
stryx scan http://localhost:8000
```

STRYX will:
1. Crawl the target and discover endpoints
2. Fingerprint the framework
3. Run all enabled scanner modules
4. Display a terminal report with findings and evidence

## 3. CLI Commands

### stryx scan

Run a full security scan against a target.

```bash
stryx scan http://target.com
stryx scan http://target.com --deep
stryx scan http://target.com --json report.json --html report.html
```

### stryx crawl

Crawl a target and discover endpoints.

```bash
stryx crawl http://target.com
stryx crawl http://target.com --depth 10
```

### stryx auth

Run authentication vulnerability tests.

```bash
stryx auth http://target.com
stryx auth http://target.com --cookies "session=abc123"
```

### stryx fuzz

Run API fuzzing tests.

```bash
stryx fuzz http://target.com
```

### stryx report

Generate reports from scan results.

```bash
stryx report http://target.com --json report.json --markdown report.md
```

### stryx config

View or update configuration.

```bash
stryx config
```

### stryx providers

List supported AI providers.

```bash
stryx providers
```

### stryx update

Update STRYX to the latest version.

```bash
stryx update
pip install --upgrade stryx
```

## 4. CLI Flags

### --deep

Enable deep scanning with extended crawling and more thorough tests.

```bash
stryx scan http://target.com --deep
```

### --json, --html, --markdown

Generate additional report formats alongside the terminal output.

```bash
stryx scan http://target.com --json report.json --html report.html --markdown report.md
```

### --threads

Control concurrent request threads (1-200).

```bash
stryx scan http://target.com --threads 50
```

### --timeout

Set HTTP request timeout in seconds (1-120).

```bash
stryx scan http://target.com --timeout 30
```

### --headers

Pass custom headers as JSON.

```bash
stryx scan http://target.com --headers '{"Authorization": "Bearer token123"}'
```

### --cookies

Pass authentication cookies.

```bash
stryx scan http://target.com --cookies "session=abc123; token=xyz"
```

### --proxy

Route requests through an HTTP proxy.

```bash
stryx scan http://target.com --proxy http://127.0.0.1:8080
```

### --wordlist

Use a custom wordlist for endpoint discovery.

```bash
stryx crawl http://target.com --wordlist /path/to/wordlist.txt
```

### --rate

Limit requests per second.

```bash
stryx scan http://target.com --rate 10
```

## 5. Authenticated Scanning

To scan behind authentication, pass cookies or headers:

```bash
# Using cookies
stryx scan http://target.com --cookies "session=your_session_cookie"

# Using Authorization header
stryx scan http://target.com --headers '{"Authorization": "Bearer your_jwt_token"}'

# Using multiple headers
stryx scan http://target.com --headers '{"Authorization": "Bearer token", "X-API-Key": "key123"}'
```

## 6. Proxy Configuration

```bash
# HTTP proxy
stryx scan http://target.com --proxy http://127.0.0.1:8080

# SOCKS5 proxy
stryx scan http://target.com --proxy socks5://127.0.0.1:1080
```

## 7. Interpreting Reports

### Severity Levels

- **CRITICAL**: Directly exploitable, immediate impact
- **HIGH**: Exploitable with moderate effort, significant impact
- **MEDIUM**: Requires specific conditions, moderate impact
- **LOW**: Limited impact or requires unlikely conditions
- **INFO**: Informational, no direct security impact

### Confidence Scores

- **90-100%**: Highly confident, evidence strongly supports the finding
- **70-89%**: Confident, evidence supports the finding
- **50-69%**: Moderate confidence, may need manual verification
- **Below 50%**: Low confidence, informational only

### Evidence Block

Every finding includes:
- HTTP request (method, URL, headers, body)
- HTTP response (status, headers, body snippet)
- Payload used
- Confidence score

## 8. CI/CD Usage

```yaml
# GitHub Actions example
- name: Run STRYX scan
  run: |
    pip install stryx
    stryx scan https://staging.example.com --json stryx-report.json

- name: Check findings
  run: |
    CRITICAL=$(python -c "import json; d=json.load(open('stryx-report.json')); print(d['summary']['critical'])")
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical findings detected"
      exit 1
    fi
```

## 9. Troubleshooting

### Target Unreachable

- Verify the target URL is correct and accessible
- Check if a proxy is needed
- Increase timeout: `--timeout 30`

### Rate Limited

- Reduce request rate: `--rate 5`
- Increase timeout between requests

### Playwright Browser Not Installed

```bash
playwright install chromium
```

### AI Provider Authentication Failure

- Verify your API key is set correctly
- Check environment variables: `GROQ_API_KEY`, `OPENAI_API_KEY`, etc.
- Run `stryx config` to verify provider settings
- AI attack planning will be skipped gracefully if no key is configured
