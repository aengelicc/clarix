"""Verify the ProjectReport model exposes the new owasp_checklist and cis_checklist fields,
and that the analyzer populates them from a real scan.
"""
import os
import tempfile
from pathlib import Path

import pytest


def test_project_report_has_owasp_and_cis_checklist_fields():
    from app.core.models import ProjectReport
    report = ProjectReport(
        repo_name="x",
        source_type="local",
    )
    assert hasattr(report, "owasp_checklist")
    assert hasattr(report, "cis_checklist")
    assert report.owasp_checklist == []
    assert report.cis_checklist == []


def test_analyzer_populates_owasp_and_cis_checklists():
    """Run the analyzer on a tiny repo with one OWASP and one CIS hit; check both checklists are non-empty."""
    from app.services.analyzer import CodeAnalyzer

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # File with a deliberately vulnerable pickle.load (OWASP A08 / CIS 16.10).
        vuln = tmp_path / "app.py"
        vuln.write_text("import pickle\ndata = pickle.loads(request.body)\n", encoding="utf-8")

        files = [(vuln, "app.py", vuln.stat().st_size)]
        analyzer = CodeAnalyzer(llm_client=None)
        report = analyzer.analyze_repo(
            repo_path=str(tmp_path),
            files=files,
            repo_name="sample",
            source_type="local",
            mode="static",
        )

        # OWASP checklist should be populated and at least one section should be failing.
        assert any(c.status == "fail" for c in report.owasp_checklist), "Expected at least one OWASP failing section"
        # CIS checklist should be populated and at least one section should be failing.
        assert any(c.status == "fail" for c in report.cis_checklist), "Expected at least one CIS failing section"
        # The actual file analysis should have at least one issue.
        assert any(len(fa.issues) > 0 for fa in report.file_analyses)
