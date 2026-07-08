"""STRYX CLI -- command-line interface for Dynamic Application Security Testing."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.panel import Panel

from stryx.config.loader import get_effective_config, load_config, save_config
from stryx.config.schema import StryxConfig
from stryx.orchestrator import Orchestrator
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import setup_logging

console = Console()


def _first_run_check() -> bool:
    """Check if this is the first run (no config exists)."""
    config_path = Path.home() / ".stryx" / "config.yaml"
    return not config_path.exists()


def _interactive_config() -> StryxConfig:
    """Interactive configuration wizard for first-time setup."""
    console.print(Panel(
        "[bold cyan]Welcome to STRYX![/]\n\n"
        "This appears to be your first run. Let's configure your AI provider.\n"
        "You can change these settings later with [bold]stryx config[/].",
        title="First-Time Setup",
        border_style="cyan",
    ))

    providers = {
        "1": ("groq", "Groq (free tier available, fast)"),
        "2": ("openai", "OpenAI (GPT-4, GPT-4o)"),
        "3": ("anthropic", "Anthropic (Claude)"),
        "4": ("openrouter", "OpenRouter (multi-model access)"),
        "5": ("ollama", "Ollama (local models, no API key)"),
        "6": ("xai", "XAI / Grok"),
        "7": ("nvidia_nim", "NVIDIA NIM"),
    }

    console.print("\n[bold]Select your AI provider:[/]\n")
    for key, (name, desc) in providers.items():
        console.print(f"  {key}. {name} - {desc}")

    choice = click.prompt("\nChoice", type=str, default="1")
    provider_name = providers.get(choice, ("groq",))[0]

    api_key = None
    model = None
    if provider_name != "ollama":
        env_key_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "groq": "GROQ_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "nvidia_nim": "NVIDIA_NIM_API_KEY",
            "xai": "XAI_API_KEY",
        }
        env_var = env_key_map.get(provider_name, "")
        existing_key = os.environ.get(env_var) if env_var else None

        if existing_key:
            console.print(f"[green]Found {env_var} in environment.[/]")
            use_existing = click.confirm("Use this existing API key?", default=True)
            if use_existing:
                api_key = existing_key

        if not api_key:
            console.print(
                f"\n[dim]You can paste your API key below (Ctrl+V / right-click).[/]\n"
                f"[dim]Or press Enter to skip and set {env_var} later.[/]"
            )
            api_key = click.prompt(
                f"API key for {provider_name}",
                type=str,
                default="",
            )
            if not api_key:
                api_key = None
                console.print(
                    f"[yellow]No key provided. Set {env_var} env var before scanning.[/]"
                )

    model_defaults = {
        "groq": "llama-3.3-70b-versatile",
        "openai": "gpt-4o",
        "anthropic": "claude-3-5-sonnet-20241022",
        "openrouter": "meta-llama/llama-3.3-70b-instruct:free",
        "ollama": "llama3.1",
        "xai": "grok-2",
        "nvidia_nim": "meta/llama-3.1-8b-instruct",
    }

    default_model = model_defaults.get(provider_name, "")
    model = click.prompt(
        "Model to use",
        type=str,
        default=default_model,
    )

    config = StryxConfig(
        provider=provider_name,
        model=model,
        api_key=api_key,
    )

    path = save_config(config)
    console.print(f"\n[green]Configuration saved to {path}[/]")

    return config


@click.group()
@click.option("--config", "config_path", type=click.Path(), help="Path to config file")
@click.pass_context
def main(ctx: click.Context, config_path: str | None = None) -> None:
    """STRYX - AI-Powered Dynamic Application Security Testing (DAST)."""
    setup_logging()

    if _first_run_check() and ctx.invoked_subcommand != "config":
        config = _interactive_config()
        ctx.ensure_object(dict)
        ctx.obj["config"] = config
        return

    ctx.ensure_object(dict)


@main.command()
@click.argument("target_url")
@click.option("--deep", is_flag=True, help="Enable deep scanning (more thorough, slower)")
@click.option("--json", "json_output", type=click.Path(), help="Output JSON report to file")
@click.option("--html", "html_output", type=click.Path(), help="Output HTML report to file")
@click.option("--markdown", "markdown_output", type=click.Path(), help="Output Markdown report to file")
@click.option("--sarif", "sarif_output", type=click.Path(), help="Output SARIF report for CI/CD")
@click.option("--threads", type=int, help="Number of concurrent threads (1-200)")
@click.option("--timeout", type=int, help="HTTP request timeout in seconds (1-120)")
@click.option("--headers", type=str, help="Custom headers (JSON format)")
@click.option("--cookies", type=str, help="Cookies string")
@click.option("--proxy", type=str, help="HTTP proxy URL")
@click.option("--wordlist", type=click.Path(), help="Custom wordlist for discovery")
@click.option("--rate", type=int, help="Requests per second rate limit")
@click.option("--verbose", is_flag=True, help="Enable verbose output")
@click.option("--policy", "policy_file", type=click.Path(), help="Security policy file (YAML)")
@click.option("--baseline", "baseline_file", type=click.Path(), help="Previous scan JSON for comparison")
@click.option("--username", type=str, help="Login username for authenticated scanning")
@click.option("--password", type=str, help="Login password for authenticated scanning")
@click.option("--login-url", type=str, help="Login URL for authentication")
@click.pass_context
def scan(
    ctx: click.Context,
    target_url: str,
    deep: bool,
    json_output: str | None,
    html_output: str | None,
    markdown_output: str | None,
    sarif_output: str | None,
    threads: int | None,
    timeout: int | None,
    headers: str | None,
    cookies: str | None,
    proxy: str | None,
    wordlist: str | None,
    rate: int | None,
    verbose: bool,
    policy_file: str | None,
    baseline_file: str | None,
    username: str | None,
    password: str | None,
    login_url: str | None,
) -> None:
    """Run a full security scan against a target URL."""
    console.print(Panel(
        f"[bold]STRYX Scan[/]\nTarget: {target_url}",
        border_style="cyan",
    ))

    overrides = {
        "target_url": target_url,
        "deep": deep,
        "json_output": json_output,
        "html_output": html_output,
        "markdown_output": markdown_output,
        "sarif_output": sarif_output,
        "threads": threads,
        "timeout": timeout,
        "proxy": proxy,
        "wordlist": wordlist,
        "rate": rate,
        "policy_file": policy_file,
        "baseline_file": baseline_file,
    }
    if headers:
        try:
            overrides["headers"] = json.loads(headers)
        except json.JSONDecodeError:
            console.print("[red]Invalid headers JSON format[/]")
            return
    if cookies:
        overrides["cookies"] = cookies

    # Session config
    if username or password:
        overrides["session"] = {
            "username": username,
            "password": password,
            "login_url": login_url,
        }

    config = load_config(overrides)

    if deep:
        if not threads:
            config.threads = 50
        console.print("[cyan]Deep mode enabled -- more thorough scanning[/]")

    orchestrator = Orchestrator(config)
    findings = asyncio.run(orchestrator.run())

    # Print scan summary
    console.print()
    severity_counts = {}
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if findings:
        console.print(Panel(
            f"[bold]Scan Complete[/]\n"
            f"Total findings: {len(findings)}\n"
            f"Critical: {severity_counts.get('critical', 0)} | "
            f"High: {severity_counts.get('high', 0)} | "
            f"Medium: {severity_counts.get('medium', 0)} | "
            f"Low: {severity_counts.get('low', 0)} | "
            f"Info: {severity_counts.get('info', 0)}",
            title="Results Summary",
            border_style="green" if not severity_counts.get("critical") else "red",
        ))
    else:
        console.print("[green]No findings -- target appears secure[/]")

    # Print output file paths
    if json_output:
        console.print(f"[dim]JSON report: {json_output}[/]")
    if html_output:
        console.print(f"[dim]HTML report: {html_output}[/]")
    if markdown_output:
        console.print(f"[dim]Markdown report: {markdown_output}[/]")
    if sarif_output:
        console.print(f"[dim]SARIF report: {sarif_output}[/]")

    # Policy result
    if hasattr(orchestrator, '_policy_failed') and orchestrator._policy_failed:
        console.print("[red]❌ Policy check FAILED[/]")
        sys.exit(1)


@main.command()
@click.argument("target_url")
@click.option("--depth", type=int, default=5, help="Crawl depth")
@click.option("--json", "json_output", type=click.Path(), help="Output JSON report")
@click.option("--wordlist", type=click.Path(), help="Custom wordlist for discovery")
def crawl(target_url: str, depth: int, json_output: str | None, wordlist: str | None) -> None:
    """Crawl a target and discover endpoints."""
    console.print(Panel(f"[bold]STRYX Crawl[/]\nTarget: {target_url}", border_style="cyan"))

    from stryx.crawler.discovery import DiscoveryAggregator

    async def _crawl():
        aggregator = DiscoveryAggregator(target_url, depth, wordlist=wordlist)
        endpoints = await aggregator.discover()
        console.print(f"\n[green]Found {len(endpoints)} endpoints[/]")
        for ep in endpoints:
            console.print(f"  {ep.method:6s} {ep.path} (source: {ep.source})")

        if json_output and endpoints:
            data = [{"method": ep.method, "path": ep.path, "source": ep.source} for ep in endpoints]
            Path(json_output).write_text(json.dumps(data, indent=2), encoding="utf-8")
            console.print(f"[dim]Saved to {json_output}[/]")

    asyncio.run(_crawl())


@main.command()
@click.argument("target_url")
@click.option("--cookies", type=str, help="Authentication cookies")
@click.option("--headers", type=str, help="Custom headers (JSON format)")
def auth(target_url: str, cookies: str | None, headers: str | None) -> None:
    """Run authentication vulnerability tests."""
    console.print(Panel(f"[bold]STRYX Auth Scan[/]\nTarget: {target_url}", border_style="cyan"))

    from stryx.scanners.auth import AuthScanner

    async def _auth():
        parsed_headers = {}
        if headers:
            try:
                parsed_headers = json.loads(headers)
            except json.JSONDecodeError:
                console.print("[red]Invalid headers JSON[/]")
                return

        client = HttpClient(timeout=10, headers=parsed_headers, cookies=cookies)
        scanner = AuthScanner(client)
        findings = await scanner.scan([target_url], target_url)

        if findings:
            for f in findings:
                console.print(f"[red]{f.severity.value.upper()}[/] {f.title}")
        else:
            console.print("[green]No authentication issues found[/]")

    asyncio.run(_auth())


@main.command()
@click.argument("target_url")
@click.option("--cookies", type=str, help="Authentication cookies")
@click.option("--headers", type=str, help="Custom headers (JSON format)")
def fuzz(target_url: str, cookies: str | None, headers: str | None) -> None:
    """Run API fuzzing tests."""
    console.print(Panel(f"[bold]STRYX Fuzz[/]\nTarget: {target_url}", border_style="cyan"))

    from stryx.scanners.fuzz import FuzzScanner

    async def _fuzz():
        parsed_headers = {}
        if headers:
            try:
                parsed_headers = json.loads(headers)
            except json.JSONDecodeError:
                console.print("[red]Invalid headers JSON[/]")
                return

        client = HttpClient(timeout=10, headers=parsed_headers, cookies=cookies)
        scanner = FuzzScanner(client)
        findings = await scanner.scan([target_url], target_url)

        if findings:
            for f in findings:
                console.print(f"[yellow]{f.severity.value.upper()}[/] {f.title}")
        else:
            console.print("[green]No fuzzing issues found[/]")

    asyncio.run(_fuzz())


@main.command()
@click.argument("target_url")
@click.option("--cookies", type=str, help="Authentication cookies")
@click.option("--headers", type=str, help="Custom headers (JSON format)")
def disclosure(target_url: str, cookies: str | None, headers: str | None) -> None:
    """Run information disclosure tests."""
    console.print(Panel(f"[bold]STRYX Disclosure Scan[/]\nTarget: {target_url}", border_style="cyan"))

    from stryx.scanners.disclosure import DisclosureScanner

    async def _disclosure():
        parsed_headers = {}
        if headers:
            try:
                parsed_headers = json.loads(headers)
            except json.JSONDecodeError:
                console.print("[red]Invalid headers JSON[/]")
                return

        client = HttpClient(timeout=10, headers=parsed_headers, cookies=cookies)
        scanner = DisclosureScanner(client)
        findings = await scanner.scan([target_url], target_url)

        if findings:
            for f in findings:
                sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(f.severity.value, "white")
                console.print(f"[{sev_color}]{f.severity.value.upper()}[/] {f.title}")
        else:
            console.print("[green]No disclosure issues found[/]")

    asyncio.run(_disclosure())


@main.command()
@click.argument("target_url")
def blind(target_url: str) -> None:
    """Run blind injection tests (timing-based)."""
    console.print(Panel(f"[bold]STRYX Blind Injection Scan[/]\nTarget: {target_url}", border_style="cyan"))

    from stryx.scanners.blind import BlindScanner

    async def _blind():
        client = HttpClient(timeout=10)
        scanner = BlindScanner(client)
        findings = await scanner.scan([target_url], target_url)

        if findings:
            for f in findings:
                console.print(f"[red]{f.severity.value.upper()}[/] {f.title}")
        else:
            console.print("[green]No blind injection issues found[/]")

    asyncio.run(_blind())


@main.command()
@click.argument("json_input", type=click.Path(exists=True))
@click.option("--html", "html_output", type=click.Path(), help="Output HTML report")
@click.option("--markdown", "markdown_output", type=click.Path(), help="Output Markdown report")
@click.option("--sarif", "sarif_output", type=click.Path(), help="Output SARIF report")
@click.option("--target", "target_url", type=str, default="", help="Target URL for report header")
def report(
    json_input: str,
    html_output: str | None,
    markdown_output: str | None,
    sarif_output: str | None,
    target_url: str,
) -> None:
    """Regenerate reports from a JSON scan file."""
    console.print(Panel("[bold]STRYX Report Generator[/]", border_style="cyan"))

    from stryx.reports.generator import ReportGenerator
    from stryx.utils.evidence import Evidence, Finding, Severity

    try:
        with open(json_input, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        console.print(f"[red]Failed to load JSON report: {e}[/]")
        return

    findings = []
    target = target_url or data.get("target", "")

    for rf in data.get("findings", []):
        try:
            evidence_data = rf.get("evidence", {})
            evidence = Evidence(
                request_method=evidence_data.get("request_method", "GET"),
                request_url=evidence_data.get("request_url", ""),
                request_headers=evidence_data.get("request_headers", {}),
                request_body=evidence_data.get("request_body"),
                response_status=evidence_data.get("response_status", 0),
                response_headers=evidence_data.get("response_headers", {}),
                response_body=evidence_data.get("response_body", ""),
                response_snippet=evidence_data.get("response_snippet", ""),
                payload=evidence_data.get("payload", ""),
                confidence=evidence_data.get("confidence", 0.5),
            )
            finding = Finding(
                title=rf.get("title", "Unknown"),
                severity=Severity(rf.get("severity", "info")),
                evidence=evidence,
                description=rf.get("description", ""),
                remediation=rf.get("remediation", ""),
                cwe=rf.get("cwe", ""),
                owasp=rf.get("owasp", ""),
                endpoint=rf.get("endpoint", ""),
                scanner=rf.get("scanner", ""),
            )
            findings.append(finding)
        except Exception as e:
            console.print(f"[yellow]Skipping malformed finding: {e}[/]")

    if not findings:
        console.print("[yellow]No findings found in JSON file[/]")
        return

    console.print(f"[green]Loaded {len(findings)} findings from {json_input}[/]")

    generator = ReportGenerator(target, findings)

    if html_output:
        generator.generate_html(html_output)
        console.print(f"[green]HTML report saved to {html_output}[/]")

    if markdown_output:
        generator.generate_markdown(markdown_output)
        console.print(f"[green]Markdown report saved to {markdown_output}[/]")

    if sarif_output:
        from stryx.reports.sarif_report import SarifReport
        sarif = SarifReport(target, findings)
        sarif.save(sarif_output)
        console.print(f"[green]SARIF report saved to {sarif_output}[/]")

    if not html_output and not markdown_output and not sarif_output:
        base = Path(json_input).stem
        out_dir = Path(json_input).parent
        html_path = str(out_dir / f"{base}.html")
        md_path = str(out_dir / f"{base}.md")
        sarif_path = str(out_dir / f"{base}.sarif")
        generator.generate_html(html_path)
        generator.generate_markdown(md_path)
        sarif = SarifReport(target, findings)
        sarif.save(sarif_path)
        console.print(f"[green]Generated {html_path}, {md_path}, and {sarif_path}[/]")


@main.command()
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("current_file", type=click.Path(exists=True))
def compare(baseline_file: str, current_file: str) -> None:
    """Compare two scan results to detect regressions."""
    console.print(Panel("[bold]STRYX Scan Comparison[/]", border_style="cyan"))

    from stryx.comparison.differ import ScanDiffer

    differ = ScanDiffer(baseline_file, current_file)
    diff = differ.compare()

    console.print(diff.summary())

    if diff.has_regressions:
        console.print("\n[red]⚠️  REGRESSION DETECTED! New critical/high findings found.[/]")
        sys.exit(1)


@main.group()
def config() -> None:
    """View or update STRYX configuration."""
    pass


@config.command("show")
def config_show() -> None:
    """Show current configuration."""
    console.print(Panel("[bold]STRYX Configuration[/]", border_style="cyan"))

    current_config = load_config()
    effective = get_effective_config(current_config)

    console.print("\n[bold]Current configuration:[/]\n")
    console.print(json.dumps(effective, indent=2))

    from stryx.config.loader import _USER_CONFIG_PATH, _LOCAL_CONFIG_PATH
    console.print(f"\n[dim]User config: {_USER_CONFIG_PATH}[/]")
    console.print(f"[dim]Project config: {_LOCAL_CONFIG_PATH}[/]")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value.

    Examples:
        stryx config set provider openai
        stryx config set model gpt-4o
        stryx config set threads 50
    """
    from stryx.config.loader import _USER_CONFIG_PATH

    user_config = {}
    if _USER_CONFIG_PATH.exists():
        try:
            with open(_USER_CONFIG_PATH) as f:
                data = yaml.safe_load(f)
                user_config = data if isinstance(data, dict) else {}
        except Exception:
            pass

    keys = key.split(".")
    target = user_config
    for k in keys[:-1]:
        if k not in target:
            target[k] = {}
        target = target[k]

    try:
        parsed_value = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        parsed_value = value

    target[keys[-1]] = parsed_value

    _USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_USER_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(user_config, f, default_flow_style=False, sort_keys=False)

    console.print(f"[green]Set {key} = {parsed_value}[/]")
    console.print(f"[dim]Saved to {_USER_CONFIG_PATH}[/]")


@config.command("get")
@click.argument("key")
def config_get(key: str) -> None:
    """Get a configuration value."""
    current_config = load_config()
    effective = get_effective_config(current_config)

    keys = key.split(".")
    value = effective
    for k in keys:
        if isinstance(value, dict) and k in value:
            value = value[k]
        else:
            console.print(f"[yellow]Key '{key}' not found in configuration[/]")
            return

    console.print(f"[bold]{key}[/] = {json.dumps(value, indent=2) if isinstance(value, (dict, list)) else value}")


@config.command("reset")
@click.confirmation_option(prompt="This will reset all configuration to defaults. Continue?")
def config_reset() -> None:
    """Reset configuration to defaults."""
    from stryx.config.loader import _USER_CONFIG_PATH

    if _USER_CONFIG_PATH.exists():
        _USER_CONFIG_PATH.unlink()
        console.print(f"[green]Removed {_USER_CONFIG_PATH}[/]")

    console.print("[green]Configuration reset to defaults.[/]")
    console.print("[dim]Run 'stryx scan' to trigger the setup wizard.[/]")


@main.command()
def policy() -> None:
    """Generate a default security policy file."""
    console.print(Panel("[bold]STRYX Policy Generator[/]", border_style="cyan"))

    from stryx.policy.engine import save_default_policy

    path = click.prompt("Output path", type=str, default="stryx-policy.yaml")
    save_default_policy(path)
    console.print(f"[green]Default policy saved to {path}[/]")
    console.print("[dim]Edit the file to customize your security policy.[/]")


@main.command()
def providers() -> None:
    """List supported AI providers."""
    console.print(Panel("[bold]Supported AI Providers[/]", border_style="cyan"))

    providers_list = [
        ("groq", "Groq (free tier, fast inference)", "GROQ_API_KEY"),
        ("openai", "OpenAI (GPT-4, GPT-4o)", "OPENAI_API_KEY"),
        ("anthropic", "Anthropic (Claude)", "ANTHROPIC_API_KEY"),
        ("openrouter", "OpenRouter (multi-model)", "OPENROUTER_API_KEY"),
        ("ollama", "Ollama (local, no key needed)", "N/A"),
        ("xai", "XAI / Grok", "XAI_API_KEY"),
        ("nvidia_nim", "NVIDIA NIM", "NVIDIA_NIM_API_KEY"),
    ]

    for name, desc, env_var in providers_list:
        console.print(f"  [bold]{name}[/] - {desc}")
        console.print(f"    Env var: {env_var}")
        console.print()


@main.command()
def update() -> None:
    """Update STRYX to the latest version."""
    console.print(Panel("[bold]STRYX Update[/]", border_style="cyan"))
    console.print("To update STRYX, run:")
    console.print("  pip install --upgrade stryx")


@main.command()
def version() -> None:
    """Show STRYX version."""
    from stryx import __version__
    console.print(f"STRYX v{__version__}")


if __name__ == "__main__":
    main()
