"""Pydantic models for Clarix API."""
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Canonical severity ordering from least to most severe — single source of truth.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class Category(str, Enum):
    BUG = "bug"
    SECURITY = "security"
    PERFORMANCE = "performance"
    REFACTORING = "refactoring"
    DEPLOYMENT = "deployment"


class Issue(BaseModel):
    category: Category
    severity: Severity
    file: str
    line: int | None = None
    description: str
    recommendation: str
    code_snippet: str | None = None
    source: str = "llm"
    rule_id: str | None = None  # set by static scanners from rules.json; None for LLM-detected issues
    hipaa_reference: str | None = None
    compliance_ref: str | None = None


class HipaaChecklistItem(BaseModel):
    section: str
    title: str
    description: str
    findings_count: int
    status: str  # "pass" or "fail"
    worst_severity: str | None = None


class ComplianceChecklistItem(BaseModel):
    framework: str
    section: str
    title: str
    description: str
    findings_count: int = 0
    status: str = "pass"  # "pass" or "fail"
    worst_severity: str | None = None


class FileAnalysis(BaseModel):
    file_path: str
    language: str
    size_bytes: int
    issues: list[Issue] = Field(default_factory=list)
    summary: str = ""
    token_count: int = 0
    analyzed: bool = True
    skip_reason: str | None = None


class LanguageBreakdown(BaseModel):
    language: str
    file_count: int
    line_count: int


class ProjectReport(BaseModel):
    repo_name: str
    source_type: str
    languages: list[LanguageBreakdown] = Field(default_factory=list)
    overall_risk_score: int = Field(0, ge=0, le=100)
    overall_assessment: str = ""
    file_analyses: list[FileAnalysis] = Field(default_factory=list)
    project_level_issues: list[Issue] = Field(default_factory=list)
    security_findings: list[Issue] = Field(default_factory=list)
    hipaa_checklist: list[HipaaChecklistItem] = Field(default_factory=list)
    pci_checklist: list[ComplianceChecklistItem] = Field(default_factory=list)
    gdpr_checklist: list[ComplianceChecklistItem] = Field(default_factory=list)
    soc2_checklist: list[ComplianceChecklistItem] = Field(default_factory=list)
    owasp_checklist: list[ComplianceChecklistItem] = Field(default_factory=list)
    cis_checklist: list[ComplianceChecklistItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    generated_at: str = ""


class SecurityRule(BaseModel):
    id: str
    name: str
    pattern: str
    severity: Severity
    description: str
    recommendation: str
    language: str = "*"        # "*" = any; e.g. "Python", "JavaScript"
    scanner: str               # "security", "hipaa", "pci", "gdpr", "soc2"
    rule_type: str             # "secret", "dangerous", "compliance"
    compliance_ref: str | None = None
    enabled: bool = True
    builtin: bool = True


class SecurityRuleCreate(BaseModel):
    name: str
    pattern: str
    severity: Severity
    description: str
    recommendation: str
    language: str = "*"
    scanner: str = "security"
    rule_type: str = "dangerous"
    compliance_ref: str | None = None


class SecurityRuleUpdate(BaseModel):
    name: str | None = None
    pattern: str | None = None
    severity: Severity | None = None
    description: str | None = None
    recommendation: str | None = None
    language: str | None = None
    compliance_ref: str | None = None
    enabled: bool | None = None


class AnalyzeRequest(BaseModel):
    source: str
    source_type: str = "github"  # github or local
    github_pat: str | None = None
    llm_provider: str | None = None  # "openai" or "anthropic"
    api_key: str | None = None       # overrides server-side env var for this request
    max_files: int | None = None
    max_file_size_kb: int | None = None
    static_only: bool = False  # deprecated — use analysis_mode="static"
    analysis_mode: Literal["static", "per_file", "bundle"] = "per_file"


class AnalyzeResponse(BaseModel):
    success: bool
    report: ProjectReport | None = None
    error: str | None = None
