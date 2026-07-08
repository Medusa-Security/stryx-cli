"""STRYX - AI-Powered Dynamic Application Security Testing (DAST).

Part of the MEDUSA security platform:
  - Remy (SAST) + STRYX (DAST) + MEDUSA (Aggregator)

Features:
  - 16 scanner modules (injection, auth, authorization, fuzz, CORS, GraphQL,
    blind, disclosure, race, cloud SSRF, dependencies, and more)
  - AI-powered attack chain planning and payload generation
  - Recursive HTML crawler with depth limiting
  - Session state machine for authenticated scanning
  - SARIF 2.1.0 output for CI/CD integration
  - Policy engine for security quality gates
  - Baseline comparison for regression tracking
  - Multi-format reports (Terminal, JSON, HTML, Markdown, SARIF)

Usage:
    stryx scan https://target.com
    stryx scan https://target.com --deep --sarif results.sarif
    stryx scan https://target.com --policy policy.yaml
"""

__version__ = "0.1.0"
__author__ = "Akhilesh Varma"
__license__ = "Apache-2.0"
__description__ = "AI-Powered Dynamic Application Security Testing (DAST)"
__url__ = "https://github.com/medusa-Security/stryx"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "__description__",
    "__url__",
]
