"""Main analysis orchestrator."""
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime

from app.core.models import Issue, FileAnalysis, ProjectReport, LanguageBreakdown, Severity, Category
from app.services.file_utils import read_file_content, count_lines, estimate_tokens
from app.services.llm import LLMClient
from app.services.security import scan_file, check_dependencies
from app.services.hipaa import scan_hipaa, build_hipaa_checklist
from app.services.pci_dss import scan_pci, build_pci_checklist
from app.services.gdpr import scan_gdpr, build_gdpr_checklist
from app.services.soc2 import scan_soc2, build_soc2_checklist

# Leave ~15k for system prompt and 16k for output; rest is code content
_BUNDLE_TOKEN_BUDGET = 150_000


class CodeAnalyzer:
    def __init__(self, llm_client: Optional[LLMClient] = None, max_file_tokens: int = 8000, cancel_event=None):
        self.llm = llm_client
        self.max_file_tokens = max_file_tokens
        self.cancel_event = cancel_event

    def _check_cancel(self):
        if self.cancel_event and self.cancel_event.is_set():
            from app.api.analysis import _AnalysisCancelled
            raise _AnalysisCancelled()

    def _run_static_scanners(self, abs_path, rel_path_str: str, language: str, content: str) -> List[Issue]:
        return (
            scan_file(abs_path, rel_path_str, language, content)
            + scan_hipaa(abs_path, rel_path_str, language, content)
            + scan_pci(abs_path, rel_path_str, language, content)
            + scan_gdpr(abs_path, rel_path_str, language, content)
            + scan_soc2(abs_path, rel_path_str, language, content)
        )

    def analyze_repo(
        self,
        repo_path: str,
        files: List[Tuple[Path, str, int]],
        repo_name: str,
        source_type: str,
        on_progress=None,
        mode: str = "per_file",
        # backward compat — callers that still pass static_only=True are handled in analysis.py
        static_only: bool = False,
    ) -> ProjectReport:
        if static_only:
            mode = "static"

        repo_path_obj = Path(repo_path)
        all_issues: List[Issue] = []
        language_stats: dict = {}
        total = len(files)

        if on_progress:
            on_progress("Checking dependencies...", 0, total)
        all_issues.extend(check_dependencies(repo_path))

        if mode == "bundle":
            file_analyses, synthesis = self._analyze_bundle(
                repo_path_obj, files, language_stats, all_issues, on_progress, total
            )
        else:
            file_analyses, synthesis = self._analyze_per_file(
                repo_path_obj, files, language_stats, all_issues, on_progress, total,
                static_only=(mode == "static")
            )

        languages = [
            LanguageBreakdown(language=lang, file_count=s["count"], line_count=s["lines"])
            for lang, s in language_stats.items()
        ]
        languages.sort(key=lambda x: x.file_count, reverse=True)

        risk_score = self._calculate_risk_score(all_issues, synthesis.get("overall_risk_score"))
        hipaa_checklist = build_hipaa_checklist(all_issues)
        pci_checklist = build_pci_checklist(all_issues)
        gdpr_checklist = build_gdpr_checklist(all_issues)
        soc2_checklist = build_soc2_checklist(all_issues)

        proj_issues = []
        for pi in synthesis.get("project_level_issues", []):
            try:
                proj_issues.append(Issue(
                    category=Category(pi.get("category", "deployment")),
                    severity=Severity(pi.get("severity", "medium")),
                    file=pi.get("file", "project-wide"),
                    line=pi.get("line"),
                    description=pi.get("description", ""),
                    recommendation=pi.get("recommendation", ""),
                    source="llm"
                ))
            except (ValueError, KeyError):
                continue

        assessment = synthesis.get("overall_assessment", "")
        if not assessment:
            n = len(all_issues)
            c = len([i for i in all_issues if i.severity == Severity.CRITICAL])
            h = len([i for i in all_issues if i.severity == Severity.HIGH])
            sev_parts = []
            if c:
                sev_parts.append(f"{c} critical")
            if h:
                sev_parts.append(f"{h} high severity")
            label = "Static analysis" if mode == "static" else "Analysis"
            assessment = f"{label} found {n} issue{'s' if n != 1 else ''}"
            if sev_parts:
                assessment += f", including {' and '.join(sev_parts)}"
            if mode == "static":
                assessment += ". No LLM-based code review was performed; results reflect regex and pattern-matching only."

        return ProjectReport(
            repo_name=repo_name,
            source_type=source_type,
            languages=languages,
            overall_risk_score=risk_score,
            overall_assessment=assessment,
            file_analyses=file_analyses,
            project_level_issues=proj_issues,
            security_findings=[i for i in all_issues if i.category == Category.SECURITY],
            hipaa_checklist=hipaa_checklist,
            pci_checklist=pci_checklist,
            gdpr_checklist=gdpr_checklist,
            soc2_checklist=soc2_checklist,
            metadata={
                "total_files_analyzed": len([f for f in file_analyses if f.analyzed]),
                "total_files_skipped": len([f for f in file_analyses if not f.analyzed]),
                "total_issues_found": len(all_issues),
                "llm_provider": self.llm.provider if self.llm else "none",
                "llm_model": self.llm.model if self.llm else "static-only",
                "analysis_mode": mode,
            },
            generated_at=datetime.now().isoformat()
        )

    # ------------------------------------------------------------------
    # Per-file mode (original behavior)
    # ------------------------------------------------------------------

    def _analyze_per_file(self, repo_path_obj, files, language_stats, all_issues, on_progress, total, static_only=False):
        file_analyses = []

        for i, (rel_path, language, size) in enumerate(files):
            self._check_cancel()
            if on_progress:
                on_progress(f"Analyzing {rel_path}", i + 1, total)

            abs_path = repo_path_obj / rel_path
            content = read_file_content(abs_path)

            if language not in language_stats:
                language_stats[language] = {"count": 0, "lines": 0}
            language_stats[language]["count"] += 1
            language_stats[language]["lines"] += count_lines(content)

            tokens = estimate_tokens(content)
            if tokens > self.max_file_tokens:
                file_analyses.append(FileAnalysis(
                    file_path=str(rel_path),
                    language=language,
                    size_bytes=size,
                    analyzed=False,
                    skip_reason=f"File too large ({tokens} estimated tokens > {self.max_file_tokens} limit)",
                    token_count=tokens
                ))
                continue

            static_issues = self._run_static_scanners(abs_path, str(rel_path), language, content)
            llm_result = self.llm.analyze_file(str(rel_path), language, content) if not static_only and self.llm else {}

            llm_issues = []
            for issue_data in llm_result.get("issues", []):
                try:
                    llm_issues.append(Issue(
                        category=Category(issue_data.get("category", "bug")),
                        severity=Severity(issue_data.get("severity", "medium")),
                        file=str(rel_path),
                        line=issue_data.get("line"),
                        description=issue_data.get("description", ""),
                        recommendation=issue_data.get("recommendation", ""),
                        source="llm"
                    ))
                except (ValueError, KeyError):
                    continue

            combined = static_issues + llm_issues
            all_issues.extend(combined)
            file_analyses.append(FileAnalysis(
                file_path=str(rel_path),
                language=language,
                size_bytes=size,
                issues=combined,
                summary=llm_result.get("summary", ""),
                token_count=tokens,
                analyzed=True
            ))

        synthesis: dict = {}
        if not static_only and self.llm:
            if on_progress:
                on_progress("Synthesizing project analysis...", total, total)
            file_summaries = [
                {
                    "file_path": fa.file_path,
                    "language": fa.language,
                    "summary": fa.summary,
                    "issues": [
                        {"severity": i.severity.value, "category": i.category.value, "description": i.description}
                        for i in fa.issues
                    ]
                }
                for fa in file_analyses if fa.analyzed
            ]
            representative = sorted(
                [i for i in all_issues if i.severity in (Severity.CRITICAL, Severity.HIGH)],
                key=lambda x: (x.severity.value, x.category.value)
            )[:25]
            synthesis = self.llm.synthesize_project(file_summaries, representative)

        return file_analyses, synthesis

    # ------------------------------------------------------------------
    # Bundle mode: one LLM call for the whole repo
    # ------------------------------------------------------------------

    def _analyze_bundle(self, repo_path_obj, files, language_stats, all_issues, on_progress, total):
        # Phase 1: static scanners + read content for all files
        file_data: dict = {}
        for i, (rel_path, language, size) in enumerate(files):
            self._check_cancel()
            if on_progress:
                on_progress(f"Static scan: {rel_path}", i + 1, total)

            abs_path = repo_path_obj / rel_path
            content = read_file_content(abs_path)

            if language not in language_stats:
                language_stats[language] = {"count": 0, "lines": 0}
            language_stats[language]["count"] += 1
            language_stats[language]["lines"] += count_lines(content)

            tokens = estimate_tokens(content)
            if tokens > self.max_file_tokens:
                file_data[str(rel_path)] = {
                    "content": None, "tokens": tokens, "size": size, "language": language,
                    "static_issues": [], "skip_reason": f"File too large ({tokens} tokens)"
                }
                continue

            static_issues = self._run_static_scanners(abs_path, str(rel_path), language, content)
            file_data[str(rel_path)] = {
                "content": content, "tokens": tokens, "size": size, "language": language,
                "static_issues": static_issues, "skip_reason": None
            }

        # Phase 2: pack files into budget, prioritising those with static hits
        eligible = [(p, d) for p, d in file_data.items() if d["content"] is not None]
        eligible.sort(key=lambda x: (0 if x[1]["static_issues"] else 1, x[1]["tokens"]))

        bundle_files = []
        budget = _BUNDLE_TOKEN_BUDGET
        excluded: set = set()
        for path, d in eligible:
            if d["tokens"] <= budget:
                bundle_files.append({"path": path, "language": d["language"], "content": d["content"]})
                budget -= d["tokens"]
            else:
                excluded.add(path)

        if on_progress:
            on_progress(f"Sending {len(bundle_files)} files to AI for review...", total, total)

        # Phase 3: single LLM call
        bundle_result = self.llm.analyze_bundle(bundle_files) if self.llm else {}

        # Index LLM issues by file path
        llm_by_file: dict = {}
        for issue_data in bundle_result.get("issues", []):
            try:
                issue = Issue(
                    category=Category(issue_data.get("category", "bug")),
                    severity=Severity(issue_data.get("severity", "medium")),
                    file=issue_data.get("file", "unknown"),
                    line=issue_data.get("line"),
                    description=issue_data.get("description", ""),
                    recommendation=issue_data.get("recommendation", ""),
                    source="llm"
                )
                llm_by_file.setdefault(issue.file, []).append(issue)
            except (ValueError, KeyError):
                continue

        # Phase 4: assemble FileAnalysis for every file
        file_analyses = []
        for path, d in file_data.items():
            if d["skip_reason"] and d["content"] is None:
                file_analyses.append(FileAnalysis(
                    file_path=path, language=d["language"], size_bytes=d["size"],
                    analyzed=False, skip_reason=d["skip_reason"], token_count=d["tokens"]
                ))
                continue

            static_issues = d["static_issues"]
            all_issues.extend(static_issues)

            if path in excluded:
                file_analyses.append(FileAnalysis(
                    file_path=path, language=d["language"], size_bytes=d["size"],
                    issues=static_issues, summary="", token_count=d["tokens"], analyzed=True,
                    skip_reason="Excluded from AI bundle (budget exceeded); static analysis ran."
                ))
                continue

            llm_issues = llm_by_file.get(path, [])
            all_issues.extend(llm_issues)
            combined = static_issues + llm_issues
            n_ai = len(llm_issues)
            summary = f"{n_ai} AI-detected issue{'s' if n_ai != 1 else ''}." if n_ai else "No AI-detected issues."
            file_analyses.append(FileAnalysis(
                file_path=path, language=d["language"], size_bytes=d["size"],
                issues=combined, summary=summary, token_count=d["tokens"], analyzed=True
            ))

        synthesis = {
            "project_level_issues": bundle_result.get("project_level_issues", []),
            "overall_assessment": bundle_result.get("overall_assessment", ""),
            "overall_risk_score": bundle_result.get("overall_risk_score"),
        }
        return file_analyses, synthesis

    # ------------------------------------------------------------------

    def _calculate_risk_score(self, all_issues: List[Issue], llm_suggested_score=None) -> int:
        base = int(llm_suggested_score) if isinstance(llm_suggested_score, (int, float)) else 0
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
        score = base + sum(weights.get(i.severity, 1) for i in all_issues)
        sec_count = sum(
            1 for i in all_issues
            if i.category == Category.SECURITY and i.severity in (Severity.CRITICAL, Severity.HIGH)
        )
        return min(100, max(0, score + sec_count * 5))
