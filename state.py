from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


AlertType = Literal["brute_force", "suspicious_url", "network_reconnaissance", "external_reconnaissance", "internal_reconnaissance", "reconnaissance", "prompt_injection", "benign_url", "malformed_input", "unknown"]
SeverityLevel = Literal["low", "medium", "high", "critical"]


class Entities(BaseModel):
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    ports: list[str] = Field(default_factory=list)
    timestamps: list[str] = Field(default_factory=list)


class InvestigationPlan(BaseModel):
    alert_summary: str = ""
    hypotheses: list[str] = Field(default_factory=list)
    tools_to_use: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: str
    reputation: str = "unknown"
    confidence: float = 0.0
    sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    mocked: bool = False


class AttackMapping(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    rationale: str


class RiskAssessment(BaseModel):
    severity: SeverityLevel = "low"
    confidence: float = 0.0
    score: int = 0
    rationale: list[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    title: str = "SOC Investigation Report"
    executive_summary: str = ""
    likely_behavior: str = ""
    evidence: list[str] = Field(default_factory=list)
    attack_mapping: list[AttackMapping] = Field(default_factory=list)
    severity: SeverityLevel = "low"
    confidence: float = 0.0
    recommended_actions: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    source_attribution: list[dict[str, Any]] = Field(default_factory=list)


class CriticFeedback(BaseModel):
    unsupported_claims: list[str] = Field(default_factory=list)
    uncertainty_flags: list[str] = Field(default_factory=list)
    downgraded_conclusions: list[str] = Field(default_factory=list)
    verification_notes: list[str] = Field(default_factory=list)


class InvestigationState(BaseModel):
    raw_input: dict[str, Any] | list[dict[str, Any]] | list[Any] | str | None = None
    raw_alert: dict[str, Any] = Field(default_factory=dict)
    normalized_alert: dict[str, Any] = Field(default_factory=dict)
    raw_input_type: str = "unknown"
    agent_registry_version: str = "1.0"
    alert_type: AlertType = "unknown"
    entities: Entities = Field(default_factory=Entities)
    investigation_plan: InvestigationPlan | dict[str, Any] = Field(default_factory=InvestigationPlan)
    threat_intel_results: list[ThreatIntelResult] | list[dict[str, Any]] = Field(default_factory=list)
    attack_mapping: list[AttackMapping] = Field(default_factory=list)
    severity: SeverityLevel = "low"
    confidence: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    draft_report: InvestigationReport | dict[str, Any] = Field(default_factory=InvestigationReport)
    critic_feedback: CriticFeedback = Field(default_factory=CriticFeedback)
    final_report: InvestigationReport | dict[str, Any] = Field(default_factory=InvestigationReport)
    errors: list[str] = Field(default_factory=list)
    fallback_notes: list[str] = Field(default_factory=list)
    validation_results: list[dict[str, Any]] = Field(default_factory=list)
    audit_log: list[dict[str, Any]] = Field(default_factory=list)
    policy_violations: list[str] = Field(default_factory=list)
    source_attribution: list[dict[str, Any]] = Field(default_factory=list)
    route_decision: str = "planner"
    stop_reason: str = ""
    needs_revision: bool = False
    revision_count: int = 0
    max_revisions: int = 1
    revision_history: list[str] = Field(default_factory=list)
    planner_output: dict[str, Any] = Field(default_factory=dict)
    threat_intel_output: dict[str, Any] = Field(default_factory=dict)
    investigation_output: dict[str, Any] = Field(default_factory=dict)
