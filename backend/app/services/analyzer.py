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


class CodeAnalyzer:
    def __init__(self, llm_client: Optional[LLMClient] = None, max_file_tokens: int = 8000):
        self.llm = llm_client
        self.max_file_tokens = max_file_tokens

    def analyze_repo(self, repo_path: str, files: List[Tuple[Path, str, int]], repo_name: str, source_type: str, on_progress=None, static_only: bool = False) -> ProjectReport:
        repo_path_obj = Path(repo_path)
        file_analyses = []
        all_issues = []
        language_stats = {}
        total = len(files)

        if on_progress:
            on_progress("Checking dependencies...", 0, total)
        dep_issues = check_dependencies(repo_path)
        all_issues.extend(dep_issues)

        for i, (rel_path, language, size) in enumerate(files):
            if on_progress:
                on_progress(f"Analyzing {rel_path}", i + 1, total)
            abs_path = repo_path_obj / rel_path
            content = read_file_content(abs_path)
            lines = count_lines(content)

            if language not in language_stats:
                language_stats[language] = {"count": 0, "lines": 0}
            language_stats[language]["count"] += 1
            language_stats[language]["lines"] += lines

            tokens = estimate_tokens(content)
            if tokens > self.max_file_tokens:
                fa = FileAnalysis(
                    file_path=str(rel_path),
                    language=language,
                    size_bytes=size,
                    analyzed=False,
                    skip_reason=f"File too large ({tokens} estimated tokens > {self.max_file_tokens} limit)",
                    token_count=tokens
                )
                file_analyses.append(fa)
                continue

            sec_issues = scan_file(abs_path, str(rel_path), language, content)
            hipaa_issues = scan_hipaa(abs_path, str(rel_path), language, content)
            pci_issues = scan_pci(abs_path, str(rel_path), language, content)
            gdpr_issues = scan_gdpr(abs_path, str(rel_path), language, content)
            soc2_issues = scan_soc2(abs_path, str(rel_path), language, content)
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

            combined_issues = sec_issues + hipaa_issues + pci_issues + gdpr_issues + soc2_issues + llm_issues
            all_issues.extend(combined_issues)

            fa = FileAnalysis(
                file_path=str(rel_path),
                language=language,
                size_bytes=size,
                issues=combined_issues,
                summary=llm_result.get("summary", ""),
                token_count=tokens,
                analyzed=True
            )
            file_analyses.append(fa)

        languages = [
            LanguageBreakdown(language=lang, file_count=stats["count"], line_count=stats["lines"])
            for lang, stats in language_stats.items()
        ]
        languages.sort(key=lambda x: x.file_count, reverse=True)

        file_summaries = [
            {
                "file_path": fa.file_path,
                "language": fa.language,
                "summary": fa.summary,
                "issues": [{"severity": i.severity.value, "category": i.category.value, "description": i.description} for i in fa.issues]
            }
            for fa in file_analyses if fa.analyzed
        ]

        representative_issues = sorted(
            [i for i in all_issues if i.severity in (Severity.CRITICAL, Severity.HIGH)],
            key=lambda x: (x.severity.value, x.category.value)
        )[:25]

        if on_progress:
            on_progress("Synthesizing project analysis...", total, total)
        if not static_only and self.llm:
            synthesis = self.llm.synthesize_project(file_summaries, representative_issues)
        else:
            synthesis = {}
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

        if static_only:
            n = len(all_issues)
            c = len([i for i in all_issues if i.severity == Severity.CRITICAL])
            h = len([i for i in all_issues if i.severity == Severity.HIGH])
            sev_parts = []
            if c:
                sev_parts.append(f"{c} critical")
            if h:
                sev_parts.append(f"{h} high severity")
            assessment = f"Static analysis found {n} issue{'s' if n != 1 else ''}"
            if sev_parts:
                assessment += f", including {' and '.join(sev_parts)}"
            assessment += ". No LLM-based code review was performed; results reflect regex and pattern-matching only."
        else:
            assessment = synthesis.get("overall_assessment", "")

        report = ProjectReport(
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
            },
            generated_at=datetime.now().isoformat()
        )
        return report

    def _calculate_risk_score(self, all_issues: List[Issue], llm_suggested_score=None) -> int:
        if llm_suggested_score is not None and isinstance(llm_suggested_score, (int, float)):
            base = int(llm_suggested_score)
        else:
            base = 0
        weights = {Severity.CRITICAL: 25, Severity.HIGH: 10, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
        score = base
        for issue in all_issues:
            score += weights.get(issue.severity, 1)
        sec_count = len([i for i in all_issues if i.category == Category.SECURITY and i.severity in (Severity.CRITICAL, Severity.HIGH)])
        score += sec_count * 5
        return min(100, max(0, score))
