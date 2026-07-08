# Contributing to STRYX

Thank you for your interest in contributing to STRYX. This document covers how to contribute effectively.

## Ways to Contribute

- **Bug reports**: Found a bug? Open an issue with reproduction steps.
- **Feature requests**: Have an idea? Open an issue describing the use case.
- **Payload additions**: Add new payloads to the `stryx/payloads/` directory.
- **Scanner modules**: Build new scanner modules following the plugin interface.
- **Documentation**: Improve docs, fix typos, add examples.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/medusa-Security/stryx.git
cd stryx

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Install Playwright browsers (for browser automation, v0.5+)
playwright install chromium

# Run tests
pytest

# Run linters
ruff check stryx/
black --check stryx/
```

## Branching Model

- `main` is protected and requires PR approval
- Create feature branches from `main` with descriptive names: `feat/add-xss-scanner`, `fix/cors-detection`
- All changes must go through Pull Requests

## Code Style

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type hints**: Required on all public functions
- **Docstrings**: Required on all scanner/module entry points

```python
async def scan(self, endpoints: list[str], base_url: str) -> list[Finding]:
    """Run injection tests against endpoints.

    Args:
        endpoints: List of endpoint URLs to test.
        base_url: Base URL of the target application.

    Returns:
        List of Finding objects with full Evidence.
    """
```

## Adding a New Scanner Module

1. Create the file in `stryx/scanners/your_scanner.py`
2. Implement the scanner class:

```python
from stryx.utils.evidence import Finding
from stryx.utils.http_client import HttpClient

class YourScanner:
    def __init__(self, client: HttpClient):
        self.client = client

    async def scan(self, endpoints: list[str], base_url: str) -> list[Finding]:
        """Run your scanner tests."""
        findings = []
        # Your scanning logic here
        return findings
```

3. Register it in `stryx/orchestrator.py` (add to `_stage_scan`)
4. Add config toggle in `stryx/config/schema.py` (ModuleConfig)
5. Every Finding MUST include populated Evidence (enforced at data-model level)
6. Add tests in `tests/test_your_scanner.py`

## Adding New Payloads

- Place payload files in `stryx/payloads/`
- One payload per line
- Use descriptive filenames: `your_category.txt`
- Minimum 15 payloads per category
- No destructive or live-malware payloads
- Source from well-known public payload lists

## Commit Message Convention

We recommend [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add XXE scanner module
fix: correct JWT validation bypass detection
docs: update USAGE.md with proxy examples
test: add unit tests for CORS scanner
```

## PR Checklist

Before submitting a PR:

- [ ] Tests pass (`pytest`)
- [ ] Lint passes (`ruff check`)
- [ ] Format passes (`black --check`)
- [ ] Docs updated (if CLI/config surface changed)
- [ ] Every finding includes full Evidence
- [ ] No emojis in code or documentation

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
