"""Schemas for the behavioral analysis system.

Maps static signals to MITRE ATT&CK behaviors without executing the file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
RiskLevel = Literal["low", "medium", "high"]


class BehaviorEvidence(BaseModel):
    type: str = Field(description="Evidence source: yara | string | api | network | metadata | signature")
    value: str = Field(description="Human-readable evidence snippet")
    confidence: float = Field(ge=0, le=1, description="Confidence of this single evidence")


class BehavioralFinding(BaseModel):
    id: str = Field(description="Stable behavior ID, e.g. B001")
    tactic: str = Field(description="ATT&CK tactic name, e.g. Execution")
    tactic_id: str = Field(description="ATT&CK tactic ID, e.g. TA0002")
    technique: str = Field(description="ATT&CK technique name")
    technique_id: str = Field(description="ATT&CK technique ID, e.g. T1059.001")
    name: str = Field(description="Short human-readable behavior name")
    description: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    observed: bool = Field(description="True if behavior was inferred from static signals")
    evidence: list[BehaviorEvidence] = Field(default_factory=list)
    mitre_url: str | None = None
    risk_contribution: int = Field(ge=0, le=30, description="Points contributed to behavioral risk score")


class TacticSummary(BaseModel):
    tactic: str
    tactic_id: str
    detected: int
    total: int
    max_severity: Severity | None = None


class BehavioralAnalysisResult(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    file_hash: str | None = None
    object_path: str | None = None
    risk_score: int = Field(ge=0, le=100, description="Aggregate behavioral risk 0-100")
    risk_level: RiskLevel
    confidence: float = Field(ge=0, le=1, description="Mean confidence across detected behaviors")
    behaviors_detected: int
    behaviors_total: int
    behaviors: list[BehavioralFinding]
    tactics_summary: list[TacticSummary]
    technique_coverage: list[str] = Field(description="Unique ATT&CK technique IDs observed")
    attack_chain: list[str] = Field(description="Ordered tactics that were hit (kill-chain order)")
    summary: str = Field(description="Human-readable summary")
    kill_chain_stage: str | None = Field(default=None, description="Furthest kill-chain stage reached")


class BehavioralAnalysisRequest(BaseModel):
    object_path: str = Field(description="Stored object path to re-analyse")
