"""Pydantic models for Clarix API."""
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


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
    line: Optional[int] = None
    description: str
    recommendation: str
    code_snippet: Optional[str] = None
    source: str = "llm"
    rule_id: Optional[str] = None  # set by static scanners from rules.json; None for LLM-detected issues
    hipaa_reference: Optional[str] = None
    compliance_ref: Optional[str] = None


class HipaaChecklistItem(BaseModel):
    section: str
    title: str
    description: str
    findings_count: int
    status: str  # "pass" or "fail"
    worst_severity: Optional[str] = None


class ComplianceChecklistItem(BaseModel):
    framework: str
    section: str
    title: str
    description: str
    findings_count: int = 0
    status: str = "pass"  # "pass" or "fail"
    worst_severity: Optional[str] = None


class FileAnalysis(BaseModel):
    file_path: str
    language: str
    size_bytes: int
    issues: List[Issue] = Field(default_factory=list)
    summary: str = ""
    token_count: int = 0
    analyzed: bool = True
    skip_reason: Optional[str] = None


class LanguageBreakdown(BaseModel):
    language: str
    file_count: int
    line_count: int


class ProjectReport(BaseModel):
    repo_name: str
    source_type: str
    languages: List[LanguageBreakdown] = Field(default_factory=list)
    overall_risk_score: int = Field(0, ge=0, le=100)
    overall_assessment: str = ""
    file_analyses: List[FileAnalysis] = Field(default_factory=list)
    project_level_issues: List[Issue] = Field(default_factory=list)
    security_findings: List[Issue] = Field(default_factory=list)
    hipaa_checklist: List[HipaaChecklistItem] = Field(default_factory=list)
    pci_checklist: List[ComplianceChecklistItem] = Field(default_factory=list)
    gdpr_checklist: List[ComplianceChecklistItem] = Field(default_factory=list)
    soc2_checklist: List[ComplianceChecklistItem] = Field(default_factory=list)
    owasp_checklist: List[ComplianceChecklistItem] = Field(default_factory=list)
    cis_checklist: List[ComplianceChecklistItem] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
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
    compliance_ref: Optional[str] = None
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
    compliance_ref: Optional[str] = None


class SecurityRuleUpdate(BaseModel):
    name: Optional[str] = None
    pattern: Optional[str] = None
    severity: Optional[Severity] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    language: Optional[str] = None
    compliance_ref: Optional[str] = None
    enabled: Optional[bool] = None


class AnalyzeRequest(BaseModel):
    source: str
    source_type: str = "github"  # github or local
    github_pat: Optional[str] = None
    llm_provider: Optional[str] = None  # "openai" or "anthropic"
    api_key: Optional[str] = None       # overrides server-side env var for this request
    max_files: Optional[int] = None
    max_file_size_kb: Optional[int] = None
    static_only: bool = False  # deprecated — use analysis_mode="static"
    analysis_mode: Literal["static", "per_file", "bundle"] = "per_file"


class AnalyzeResponse(BaseModel):
    success: bool
    report: Optional[ProjectReport] = None
    error: Optional[str] = None
