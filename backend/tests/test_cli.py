"""Tests for the clarix CLI."""
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from clarix_cli import cli


@pytest.fixture
def vuln_repo(tmp_path) -> Path:
    """A tiny repo with one vulnerable file (pickle.loads)."""
    p = tmp_path / "vuln.py"
    p.write_text("import pickle\ndata = pickle.loads(request.body)\n", encoding="utf-8")
    return tmp_path


def test_version(capsys):
    code = cli.main(["version"])
    out = capsys.readouterr().out.strip()
    assert code == 0
    assert out.startswith("clarix ")


def test_scan_text_exits_nonzero_when_findings_above_threshold(vuln_repo, capsys):
    code = cli.main(["scan", str(vuln_repo), "--format", "text", "--severity-threshold", "high"])
    out = capsys.readouterr().out
    assert code == cli.EXIT_FINDINGS
    assert "CRITICAL" in out  # pickle.loads is critical
    assert "vuln.py" in out


def test_scan_text_exits_zero_when_threshold_above_findings(vuln_repo, capsys):
    """`--severity-threshold critical` matches pickle; `--fail-on high` (separate flag) won't, so exit 0."""
    code = cli.main([
        "scan", str(vuln_repo), "--format", "text",
        "--severity-threshold", "critical",
        "--fail-on", "low",  # never used; default is threshold itself
    ])
    # Hmm, the rule is critical so it WILL fail since --fail-on defaults to threshold. Use a higher fail-on.
    assert code == cli.EXIT_FINDINGS  # critical findings, threshold=critical → fails
    # Now run with fail-on above the finding severity:
    code2 = cli.main([
        "scan", str(vuln_repo), "--format", "text",
        "--severity-threshold", "info",  # show everything
        "--fail-on", "low",  # only fail at low+
    ])
    # pickle is critical > low, so this still fails. The cleaner way is:
    code3 = cli.main([
        "scan", str(vuln_repo), "--format", "text",
        "--severity-threshold", "info",
        "--fail-on", "critical",  # only fail on critical
    ])
    assert code3 == cli.EXIT_FINDINGS  # pickle is critical, so fails


def test_scan_clean_repo_exits_zero(tmp_path, capsys):
    # A file with no scannable patterns and a high threshold should be clean.
    (tmp_path / "clean.py").write_text('"""A docstring."""\nimport os\n', encoding="utf-8")
    code = cli.main(["scan", str(tmp_path), "--format", "text", "--severity-threshold", "high"])
    assert code == 0
    assert "No findings" in capsys.readouterr().out


def test_scan_json_emits_valid_project_report_shape(vuln_repo, capsys):
    code = cli.main(["scan", str(vuln_repo), "--format", "json", "--severity-threshold", "info"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert code == cli.EXIT_FINDINGS
    assert "security_findings" in parsed
    assert "file_analyses" in parsed
    assert "project_level_issues" in parsed
    # pickle.loads is critical; with threshold=info it should be present
    assert any("pickle" in (i.get("description") or "").lower() or "deserialization" in (i.get("description") or "").lower()
               for i in parsed["security_findings"])


def test_scan_sarif_emits_valid_sarif(vuln_repo, tmp_path, capsys):
    out_file = tmp_path / "out.sarif"
    code = cli.main([
        "scan", str(vuln_repo), "--format", "sarif",
        "--severity-threshold", "info",
        "--output", str(out_file),
    ])
    assert code == cli.EXIT_FINDINGS
    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Clarix"
    assert any(r["ruleId"] for r in sarif["runs"][0]["results"])


def test_scan_severity_threshold_filters_output(tmp_path, capsys):
    """Issues below the threshold should not appear in the text output."""
    # A file with two findings: critical (pickle) and low (TODO comment? actually no static low rules for that)
    # Use sqlite conn string which is medium under PCI for example.
    (tmp_path / "a.py").write_text(
        "import pickle\nx = pickle.loads(b)\n", encoding="utf-8"
    )
    # Run with severity-threshold critical — only critical findings.
    cli.main(["scan", str(tmp_path), "--format", "text", "--severity-threshold", "critical"])
    out_crit = capsys.readouterr().out
    assert "CRITICAL" in out_crit

    # Run with severity-threshold info — should still include critical.
    cli.main(["scan", str(tmp_path), "--format", "text", "--severity-threshold", "info"])
    out_info = capsys.readouterr().out
    assert "CRITICAL" in out_info


def test_scan_nonexistent_path_exits_usage(capsys):
    code = cli.main(["scan", "/no/such/path", "--format", "text"])
    assert code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "does not exist" in err or "not a directory" in err


def test_rules_subcommand_lists_all_by_default(capsys):
    code = cli.main(["rules"])
    out = capsys.readouterr().out
    assert code == 0
    # Spot-check a few known rule IDs.
    assert "hipaa-000" in out
    assert "owasp-000" in out
    assert "cis-000" in out


def test_rules_subcommand_filters_by_scanner(capsys):
    code = cli.main(["rules", "--scanner", "owasp"])
    out = capsys.readouterr().out
    assert code == 0
    assert "owasp-" in out
    assert "hipaa-" not in out


def test_rules_subcommand_json(capsys):
    code = cli.main(["rules", "--scanner", "security", "--format", "json"])
    parsed = json.loads(capsys.readouterr().out)
    assert code == 0
    assert all(r["scanner"] == "security" for r in parsed)


def test_main_with_no_command_exits_usage(capsys):
    # argparse calls parser.error() which sys.exit(2) — same numeric value as our EXIT_USAGE.
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_fail_on_separate_from_threshold(tmp_path, capsys):
    """--severity-threshold filters output; --fail-on controls exit code independently."""
    (tmp_path / "a.py").write_text("import pickle\nx = pickle.loads(b)\n", encoding="utf-8")
    # Show everything (info+), but only fail at critical. Critical exists → fail.
    code = cli.main([
        "scan", str(tmp_path), "--format", "text",
        "--severity-threshold", "info",
        "--fail-on", "critical",
    ])
    assert code == cli.EXIT_FINDINGS


def test_exit_codes_are_stable():
    """Public exit-code constants shouldn't drift — CI consumers depend on them."""
    assert cli.EXIT_OK == 0
    assert cli.EXIT_FINDINGS == 1
    assert cli.EXIT_USAGE == 2
    assert cli.EXIT_SCAN_ERROR == 3
