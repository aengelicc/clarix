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
        patterns = [
            r"```json\s*(\{.*?\})\s*```",
            r"```\s*(\{.*?\})\s*```",
            r'(\{.*\})',  # greedy: first { to last } — catches any JSON object
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
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

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        if self.provider == "anthropic":
            message = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
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
                max_tokens=4096
            )
            return response.choices[0].message.content
