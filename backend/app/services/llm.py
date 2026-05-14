"""Unified LLM client for OpenAI and Anthropic."""
import os
import json
import re
from typing import Optional, Dict, Any


class LLMClient:
    def __init__(self, provider: str = None, api_key: str = None, model: str = None):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.api_key = api_key or self._get_default_api_key()
        self.model = model or self._get_default_model()
        self.client = None
        self._init_client()

    def _get_default_api_key(self) -> str:
        if self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY", "")
        return os.getenv("OPENAI_API_KEY", "")

    def _get_default_model(self) -> str:
        if self.provider == "anthropic":
            return os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        return os.getenv("OPENAI_MODEL", "gpt-4o")

    def _init_client(self):
        if not self.api_key:
            raise ValueError(f"API key not provided for {self.provider}")
        if self.provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
        else:
            import openai
            self.client = openai.OpenAI(api_key=self.api_key)

    def _extract_json(self, text: str) -> Optional[Dict]:
        # Try direct parse first (clean LLM responses)
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass

        # Try code-fence patterns (non-greedy stops correctly at the } before the fence)
        for pattern in [r"```json\s*(\{.*?\})\s*```", r"```\s*(\{.*?\})\s*```"]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue

        # Balanced-brace extraction — handles trailing text/curly braces in string values
        # that fool the greedy (\{.*\}) approach.
        start = text.find('{')
        if start == -1:
            return None
        depth = 0
        in_string = False
        escape = False
        for i, c in enumerate(text[start:], start):
            if escape:
                escape = False
                continue
            if c == '\\' and in_string:
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        return None

    def analyze_file(self, file_path: str, language: str, content: str) -> Dict[str, Any]:
        system_prompt = """You are an expert code reviewer with 15 years of experience in software engineering, security, and performance optimization.

Analyze the provided code for the following categories:
1. **Bugs**: Logic errors, null pointer risks, race conditions, off-by-one errors, unhandled edge cases
2. **Security**: Injection vulnerabilities, XSS, CSRF, insecure cryptography, authentication flaws, secrets exposure, path traversal
3. **Performance**: Inefficient algorithms, memory leaks, unnecessary I/O, N+1 queries, resource exhaustion risks
4. **Refactoring**: DRY violations, dead code, high complexity, tight coupling, long functions/classes, poor naming
5. **HIPAA / PHI Compliance**: If this is a healthcare or medical application, flag ePHI exposure risks, missing encryption (§164.312(e)), weak authentication (§164.312(d)), absent audit logging (§164.312(b)), hardcoded credentials (§164.308(a)(1)), and unencrypted data in transit or at rest. Include the applicable HIPAA Security Rule section in the description.

For each issue found, return:
- category: exactly one of "bug", "security", "performance", "refactoring"
- severity: exactly one of "critical", "high", "medium", "low"
- line: the approximate line number where the issue occurs (integer), or null if not applicable
- description: a clear, specific explanation of the problem (2-3 sentences)
- recommendation: a concrete fix or improvement suggestion with code example if relevant

Return ONLY a JSON object in this exact format (no markdown, no explanations outside JSON):
{
  "issues": [
    {
      "category": "security",
      "severity": "high",
      "line": 15,
      "description": "User input is passed directly to exec() without sanitization, allowing arbitrary code execution.",
      "recommendation": "Use ast.literal_eval() for safe evaluation, or implement a strict whitelist parser."
    }
  ],
  "summary": "Brief 1-2 sentence summary of the file's overall quality and main concerns."
}

If no issues are found, return {"issues": [], "summary": "No significant issues found. Code appears well-structured and secure."}"""

        user_prompt = f"File: {file_path}\nLanguage: {language}\n\n```\n{content}\n```"
        response_text = self._call_llm(system_prompt, user_prompt)
        parsed = self._extract_json(response_text)
        if parsed is None:
            return {
                "issues": [],
                "summary": f"[Parse Error] LLM response could not be parsed.",
                "_raw": response_text[:200]
            }
        return parsed

    def synthesize_project(self, file_summaries: list, all_issues: list) -> Dict[str, Any]:
        system_prompt = """You are a principal engineer conducting an architecture and deployment readiness review.

Given summaries and issues from individual files, identify cross-cutting concerns that span multiple files or represent systemic problems.

Focus on:
1. **Architecture**: Monolith vs microservices concerns, coupling, cohesion, API design, data flow issues
2. **Deployment Risks**: Missing health checks, hardcoded config, missing containerization, state management issues
3. **Security Posture**: Missing auth, inconsistent security practices, secrets management, input validation gaps
4. **Operational Concerns**: Logging, monitoring, error handling, scalability bottlenecks
5. **HIPAA Compliance Posture**: If this appears to be a healthcare application, assess systemic compliance gaps across HIPAA Administrative Safeguards (§164.308), Physical Safeguards (§164.310), and Technical Safeguards (§164.312). Flag missing audit trails, unencrypted ePHI, inadequate access controls, and any patterns suggesting PHI is handled without proper safeguards. Use category "security" and include the HIPAA section reference in the description.

For each project-level issue:
- category: one of "bug", "security", "performance", "refactoring", "deployment"
- severity: "critical", "high", "medium", "low"
- file: relevant file path or "project-wide"
- line: null
- description: detailed explanation
- recommendation: actionable remediation

Return ONLY JSON:
{
  "project_level_issues": [
    {
      "category": "deployment",
      "severity": "high",
      "file": "project-wide",
      "line": null,
      "description": "...",
      "recommendation": "..."
    }
  ],
  "overall_assessment": "2-3 paragraph executive summary of project readiness, key risks, and priority actions.",
  "overall_risk_score": 75
}

Risk score: 0-100 where 0 = pristine, 100 = critical issues blocking deployment."""

        context = "## File Summaries\n\n"
        for fs in file_summaries[:30]:
            context += f"### {fs['file_path']} ({fs['language']})\n"
            context += f"Summary: {fs['summary']}\n"
            context += f"Issues found: {len(fs.get('issues', []))}\n\n"

        if all_issues:
            context += "\n## Notable Issues\n\n"
            for issue in all_issues[:20]:
                context += f"- [{issue.severity.value.upper()}] {issue.category.value}: {issue.description[:100]}\n"

        user_prompt = context + "\n\nProvide your project-level assessment."
        response_text = self._call_llm(system_prompt, user_prompt)
        parsed = self._extract_json(response_text)
        if parsed is None:
            return {
                "project_level_issues": [],
                "overall_assessment": "Failed to generate project-level assessment due to response parsing error.",
                "overall_risk_score": 50,
                "_raw": response_text
            }
        return parsed

    def analyze_bundle(self, files: list) -> dict:
        """Analyze multiple files in one LLM call. Returns flat issue list + project summary."""
        system_prompt = """You are an expert code reviewer specializing in security, bugs, and software architecture.

You will receive multiple source files from a codebase, each preceded by a header showing its path and language, with line numbers. Analyze all files together, catching both per-file issues and cross-cutting concerns.

For each issue found:
- file: exact file path from the === FILE: ... === header
- category: exactly one of "bug", "security", "performance", "refactoring", "deployment"
- severity: exactly one of "critical", "high", "medium", "low"
- line: line number (integer) where the issue occurs, or null
- description: clear explanation of the problem (2-3 sentences)
- recommendation: concrete fix or improvement, with a short code example if helpful

Return ONLY a JSON object in this exact format (no markdown, no text outside the JSON):
{
  "issues": [
    {
      "file": "src/auth.py",
      "category": "security",
      "severity": "high",
      "line": 15,
      "description": "User input passed directly to exec() without sanitization.",
      "recommendation": "Use ast.literal_eval() or a strict whitelist parser instead."
    }
  ],
  "project_level_issues": [
    {
      "file": "project-wide",
      "category": "deployment",
      "severity": "medium",
      "line": null,
      "description": "No health-check endpoint found across the project.",
      "recommendation": "Add a /health route that returns 200 OK for load-balancer probes."
    }
  ],
  "overall_assessment": "2-3 paragraph executive summary of overall code quality, security posture, and the highest-priority actions the team should take.",
  "overall_risk_score": 65
}

Risk score: 0=pristine, 100=critical issues blocking deployment.
Focus on real, actionable issues. Do not pad with minor style nits."""

        bundle_text = ""
        for f in files:
            bundle_text += f"\n=== FILE: {f['path']} ({f['language']}) ===\n"
            for i, line in enumerate(f["content"].splitlines(), 1):
                bundle_text += f"{i:6d}: {line}\n"

        user_prompt = f"Analyze the following codebase:\n{bundle_text}"
        response_text = self._call_llm(system_prompt, user_prompt, max_tokens=16384)
        parsed = self._extract_json(response_text)
        if parsed is None:
            print(f"[analyze_bundle] parse failed. Raw response (first 1000 chars):\n{response_text[:1000]}", flush=True)
            return {
                "issues": [],
                "project_level_issues": [],
                "overall_assessment": "[Parse Error] Bundle analysis response could not be parsed.",
                "overall_risk_score": 50,
                "_raw": response_text[:1000],
            }
        return parsed

    def _call_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        if self.provider == "anthropic":
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            return message.content[0].text
        else:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
