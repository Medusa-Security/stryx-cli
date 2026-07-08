# Changelog

All notable changes to STRYX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-07-08

### Added

- Initial release
- HTTP crawler with endpoint discovery
- OpenAPI/Swagger endpoint extraction
- Sitemap and robots.txt parsing
- JavaScript endpoint extraction
- GraphQL endpoint discovery
- Authentication vulnerability scanner (missing auth, weak JWT, session fixation)
- Authorization scanner (IDOR, privilege escalation, admin access)
- Injection engine (SQL, NoSQL, command, path traversal, SSTI, XXE, SSRF)
- API fuzzer (parameter mutation, boundary values, nested JSON)
- CORS misconfiguration scanner
- GraphQL security scanner (introspection, query depth)
- AI attack planner with support for Groq, OpenAI, Anthropic, OpenRouter, Ollama, XAI, NVIDIA NIM
- Report generation: terminal (Rich), JSON, Markdown, HTML (Jinja2)
- CLI with Click and Rich
- Configuration system with YAML files and interactive setup
- Evidence-based findings (every finding requires supporting evidence)
- Framework fingerprinting for payload adaptation
- Rate limiting and async HTTP client
- Comprehensive test suite
- Mock vulnerable application for testing
