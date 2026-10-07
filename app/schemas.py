from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool

Decision = Literal["ALLOW", "REVIEW", "BLOCK"]


class Schema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssessmentRequest(Schema):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=40)
    environment: str = Field(default="production", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class Vulnerability(Schema):
    cve_id: str = Field(min_length=13, max_length=40)
    description: str = Field(max_length=6000)
    cvss: float | None = Field(default=None, ge=0, le=10)
    attack_vector: str | None = None
    affected_products: list[str] = Field(default_factory=list, max_length=100)
    source: str = Field(max_length=500)


class Asset(Schema):
    asset_id: str = Field(min_length=1, max_length=200)
    environment: str = Field(min_length=1, max_length=80)
    internet_facing: StrictBool | None = None
    criticality: Literal["low", "medium", "high"] | None = None
    owner: str | None = Field(default=None, max_length=200)
    dependencies: list[str] = Field(default_factory=list, max_length=20)
    dependencies_truncated: StrictBool = False


class AssetContext(Schema):
    cve_id: str
    environment: str
    assets: list[Asset] = Field(max_length=100)
    complete: StrictBool = False
    source: str


class Proposal(Schema):
    decision: Decision
    summary: str = Field(min_length=1, max_length=1200)


class Evidence(Schema):
    reference: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=500)
    details: dict


class PolicyFinding(Schema):
    rule: str
    severity: Literal["BLOCK", "REVIEW"]
    message: str
    evidence_refs: list[str]


class PolicyResult(Schema):
    conforms: bool
    decision: Decision
    findings: list[PolicyFinding]


class RemediationAction(Schema):
    action: str
    rationale: str
    owner: str


class ToolTrace(Schema):
    step: int
    tool: str
    arguments: dict
    status: Literal["ok", "error"]
    observation: dict
    latency_ms: float


class SecurityDecision(Schema):
    run_id: str
    model: str
    goal: AssessmentRequest
    decision: Decision
    summary: str
    evidence: list[Evidence]
    policy_findings: list[PolicyFinding]
    remediation: list[RemediationAction]
    tool_trace: list[ToolTrace]
    proposed_decision: Proposal | None = None
    policy_validated: bool
