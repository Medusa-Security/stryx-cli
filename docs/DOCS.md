# STRYX Technical Documentation

Architecture reference and internal module documentation.

## 1. Architecture Overview

STRYX follows a pipeline architecture:

```
CLI (Click + Rich)
    |
Configuration (YAML + Pydantic)
    |
Attack Orchestrator
    |
    +-- Endpoint Discovery (crawler/)
    |       +-- OpenAPI/Swagger
    |       +-- Sitemap/robots.txt
    |       +-- JavaScript endpoints
    |       +-- GraphQL discovery
    |
    +-- Framework Fingerprinting
    |
    +-- Scanner Modules
    |       +-- Auth Scanner
    |       +-- Authorization Scanner
    |       +-- Injection Engine
    |       +-- API Fuzzer
    |       +-- CORS Scanner
    |       +-- GraphQL Scanner
    |
    +-- AI Attack Planner
    |
    +-- Report Generator
            +-- Terminal (Rich)
            +-- JSON
            +-- Markdown
            +-- HTML (Jinja2)
```

### ScanContext

The `ScanContext` dataclass is the shared state object passed by reference to all modules:

```python
@dataclass
class ScanContext:
    target_url: str
    endpoints: list[Endpoint]
    endpoint_urls: list[str]
    findings: list[Finding]
    graphql_endpoints: list[str]
    cookies: str
    headers: dict[str, str]
    framework: Optional[str]
    auth_tokens: dict[str, str]
```

### Core Pipeline

1. **Discover**: Crawl target, extract endpoints from OpenAPI, sitemaps, JS, GraphQL
2. **Fingerprint**: Identify target framework for payload adaptation
3. **Scan**: Run all enabled scanner modules against discovered endpoints
4. **Plan**: AI-assisted attack chain construction from findings
5. **Report**: Generate output in requested formats

## 2. Module Internals

### crawler/

- **discovery.py**: `DiscoveryAggregator` merges results from all sub-modules into deduplicated `Endpoint` list
- **openapi.py**: Probes common OpenAPI/Swagger paths, parses specs to extract endpoints with methods and parameters
- **sitemap.py**: Parses robots.txt and sitemap.xml for URL paths
- **js_endpoints.py**: Downloads JS files, regex-extracts API endpoint patterns
- **graphql_discovery.py**: Probes common GraphQL paths, tests introspection queries

### scanners/

- **auth.py**: `AuthScanner` tests unauthenticated access, JWT weaknesses, session fixation
- **authorization.py**: `AuthorizationScanner` tests IDOR, privilege escalation, admin panel access
- **injection.py**: `InjectionScanner` loads payloads per category, adapts to fingerprinted framework, tests query params and POST bodies
- **fuzz.py**: `FuzzScanner` mutates parameters with type confusion, boundary values, nested JSON
- **cors.py**: `CorsScanner` tests Origin reflection and wildcard CORS
- **graphql.py**: `GraphQLScanner` tests introspection and query depth

### attacks/

- **attack_chain.py**: `AttackChain` and `ChainBuilder` construct multi-step attack paths from findings
- **replay.py**: `ReplayEngine` replays requests with modified IDs for IDOR testing

### ai/

- **providers.py**: Unified abstraction over Groq, OpenAI, Anthropic, OpenRouter, Ollama, XAI, NVIDIA NIM
- **attack_planner.py**: `AttackPlanner` uses AI to construct attack chains; falls back to rule-based chains
- **prompts.py**: System and user prompt templates for AI attack planning

### reports/

- **json_report.py**: `JsonReport` produces MEDUSA-compatible JSON
- **markdown_report.py**: `MarkdownReport` for PR comments and CI logs
- **terminal_report.py**: `TerminalReport` uses Rich tables and panels
- **generator.py**: `ReportGenerator` orchestrates all format outputs
- **templates/report.html.j2**: Jinja2 HTML template with dark theme

### config/

- **schema.py**: `StryxConfig` Pydantic model with validation (threads 1-200, timeout 1-120)
- **loader.py**: Priority-based config loading: CLI > user file > local file > defaults
- **default_config.yaml**: Built-in defaults

### utils/

- **evidence.py**: `Evidence` and `Finding` dataclasses -- every finding requires Evidence
- **http_client.py**: `HttpClient` with rate limiting and evidence collection
- **logging.py**: Rich-based logging configuration
- **rate_limiter.py**: Async token-bucket rate limiter

### plugins/

- **base.py**: `BaseScanner` abstract class and `PluginMetadata` -- interface for v0.5 plugins

## 3. Data Models

### Evidence

Every finding MUST include populated Evidence:

```python
@dataclass
class Evidence:
    request_method: str          # HTTP method (GET, POST, etc.)
    request_url: str             # Full request URL
    request_headers: dict        # Request headers
    request_body: Optional[str]  # Request body
    response_status: int         # HTTP status code
    response_headers: dict       # Response headers
    response_body: str           # Full response body
    response_snippet: str        # First 500 chars of response
    payload: str                 # Attack payload used
    confidence: float            # 0.0 to 1.0
```

### Finding

```python
@dataclass
class Finding:
    title: str                   # Finding title
    severity: Severity           # critical/high/medium/low/info
    evidence: Evidence           # REQUIRED -- no finding without evidence
    description: str             # Detailed description
    remediation: str             # Fix recommendations
    cwe: str                     # CWE identifier
    owasp: str                   # OWASP category
    endpoint: str                # Affected endpoint
    scanner: str                 # Scanner that found it
    tags: list[str]              # Classification tags
```

## 4. Configuration Schema

| Field | Type | Default | Range |
|-------|------|---------|-------|
| provider | string | groq | - |
| model | string | openai/gpt-oss-120b | - |
| api_key | string | null | - |
| threads | int | 20 | 1-200 |
| timeout | int | 10 | 1-120 |
| crawl_depth | int | 5 | 1-50 |
| respect_robots | bool | false | - |
| ai_attack_planning | bool | true | - |
| modules.auth | bool | true | - |
| modules.authorization | bool | true | - |
| modules.injection | bool | true | - |
| modules.fuzzing | bool | true | - |

## 5. AI Provider Abstraction

`ai/providers.py` normalizes calls across providers:

| Provider | API Key Env Var | Default Model |
|----------|----------------|---------------|
| groq | GROQ_API_KEY | llama-3.3-70b-versatile |
| openai | OPENAI_API_KEY | gpt-4o |
| anthropic | ANTHROPIC_API_KEY | claude-3-5-sonnet-20241022 |
| openrouter | OPENROUTER_API_KEY | meta-llama/llama-3.3-70b-instruct:free |
| ollama | (none needed) | llama3.1 |
| xai | XAI_API_KEY | grok-2 |
| nvidia_nim | NVIDIA_NIM_API_KEY | meta/llama-3.1-8b-instruct |

AI attack planning degrades gracefully -- if no API key is configured, rule-based chains are used.

## 6. JSON Report Schema (MEDUSA Integration Contract)

```json
{
  "report": {
    "tool": "stryx",
    "version": "0.1.0",
    "generated_at": "ISO8601 timestamp",
    "target": "target URL"
  },
  "summary": {
    "total_findings": 10,
    "by_severity": {"critical": 1, "high": 3, "medium": 4, "low": 2},
    "critical": 1,
    "high": 3,
    "medium": 4,
    "low": 2,
    "info": 0
  },
  "findings": [
    {
      "title": "Finding title",
      "severity": "critical",
      "description": "Description",
      "remediation": "Fix",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "endpoint": "http://...",
      "scanner": "injection",
      "tags": ["sqli"],
      "evidence": {
        "request_method": "GET",
        "request_url": "http://...",
        "request_headers": {},
        "request_body": null,
        "response_status": 200,
        "response_headers": {},
        "response_body": "...",
        "response_snippet": "...",
        "payload": "test",
        "confidence": 0.85
      }
    }
  ],
  "attack_chains": [
    {
      "name": "Chain name",
      "steps": [...],
      "total_impact": "Impact description",
      "estimated_severity": "critical"
    }
  ],
  "metadata": {
    "scanners_used": ["auth", "injection"],
    "total_endpoints_tested": 50
  }
}
```

## 7. Plugin SDK (v0.5 Interface)

`plugins/base.py` defines the interface:

```python
class BaseScanner(ABC):
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata: ...

    @abstractmethod
    async def scan(self, target_url: str, endpoints: list[str], config: dict) -> list[Finding]: ...

    @abstractmethod
    def validate_config(self, config: dict) -> bool: ...
```

The plugin loader (v0.5) will discover classes extending `BaseScanner` and register them automatically.

## 8. Extending Payloads and Framework Signatures

### Payloads

- Files in `stryx/payloads/*.txt`, one payload per line
- Named by category: `sqli.txt`, `nosqli.txt`, `cmdi.txt`, etc.
- Loaded by `InjectionScanner` via `_load_payloads(category)`

### Framework Signatures

- `stryx/signatures/framework_fingerprints.yaml`
- Keyed by framework slug (e.g., `python_flask`, `node_express`)
- Each entry has `headers`, `cookies`, `body_patterns`, `sql_dialect`, `injection_modifiers`
- Used by `InjectionScanner.fingerprint_framework()` for payload adaptation
