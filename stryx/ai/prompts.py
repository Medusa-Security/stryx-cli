"""Prompt templates for the AI attack planner."""

SYSTEM_PROMPT = """You are an expert application security analyst specializing in
Dynamic Application Security Testing (DAST). Your role is to analyze scan findings
and construct realistic attack chains that demonstrate how individual vulnerabilities
can be combined to achieve significant impact.

Rules:
1. Only propose attack chains that are supported by the actual findings provided.
2. Each chain must have a clear sequence of steps.
3. Estimate the realistic impact of each chain.
4. Return your response as strict JSON matching the schema provided.
5. Do not fabricate vulnerabilities not present in the findings.
6. Prioritize chains with highest real-world impact.
7. Consider the relationships between findings (e.g., auth bypass enables IDOR)."""

ATTACK_CHAIN_PROMPT = """Analyze the following security scan findings and construct
realistic attack chains. Each chain should show how individual vulnerabilities can
be combined for greater impact.

Findings:
{findings_json}

Return a JSON array of attack chains with this exact schema:
[
  {{
    "name": "Chain name describing the attack path",
    "steps": [
      {{
        "title": "Step title",
        "description": "What this step achieves",
        "severity": "critical|high|medium|low",
        "endpoint": "affected endpoint"
      }}
    ],
    "total_impact": "Description of the overall impact",
    "estimated_severity": "critical|high|medium|low",
    "rationale": "Why this chain is realistic and actionable"
  }}
]

Focus on chains that:
1. Combine authentication/authorization issues with injection or data exposure
2. Demonstrate privilege escalation paths
3. Show data exfiltration scenarios
4. Reveal denial-of-service opportunities

Return ONLY the JSON array, no other text."""

REMEDIATION_PROMPT = """Based on the following finding, provide a detailed
remediation recommendation:

Title: {title}
Severity: {severity}
CWE: {cwe}
Endpoint: {endpoint}
Description: {description}

Provide:
1. A specific, actionable fix
2. Code example if applicable
3. Additional hardening recommendations
4. Testing steps to verify the fix

Return as JSON:
{{
  "fix": "Specific remediation steps",
  "code_example": "Code example if applicable",
  "hardening": ["Additional recommendations"],
  "testing": ["Steps to verify the fix"]
}}"""


def format_findings_for_prompt(findings: list[dict]) -> str:
    """Format findings list into a string for the AI prompt."""
    formatted = []
    for i, f in enumerate(findings, 1):
        formatted.append(
            f"{i}. [{f.get('severity', 'unknown').upper()}] {f.get('title', 'Unknown')}\n"
            f"   Endpoint: {f.get('endpoint', 'N/A')}\n"
            f"   Description: {f.get('description', 'N/A')}\n"
            f"   CWE: {f.get('cwe', 'N/A')}\n"
            f"   Tags: {', '.join(f.get('tags', []))}\n"
        )
    return "\n".join(formatted)
