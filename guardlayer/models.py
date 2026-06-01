"""
Shared data models for GuardLayer.
All threat scan results and session records are typed here.
"""

from __future__ import annotations
from enum import Enum
from datetime import datetime
from pydantic import BaseModel


class ThreatCategory(str, Enum):
    """The six attack types GuardLayer detects."""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    ROLE_HIJACKING = "ROLE_HIJACKING"
    PII_LEAKAGE = "PII_LEAKAGE"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"


class RiskLevel(str, Enum):
    """Human-readable risk band derived from the numeric score."""
    SAFE = "SAFE"           # 0–30
    SUSPICIOUS = "SUSPICIOUS"  # 31–60
    BLOCKED = "BLOCKED"     # 61–100


def risk_level_from_score(score: int) -> RiskLevel:
    """Map a 0–100 score to a RiskLevel enum value."""
    if score <= 30:
        return RiskLevel.SAFE
    if score <= 60:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.BLOCKED


class ThreatFinding(BaseModel):
    """A single threat detected in a prompt or response."""
    category: ThreatCategory
    risk_score: int                  # 0–100
    risk_level: RiskLevel
    explanation: str                 # plain English: what was found and why it matters
    recommendation: str              # what the developer should do about it


class ScanResult(BaseModel):
    """The full result of scanning one piece of text."""
    text_scanned: str
    findings: list[ThreatFinding] = []
    highest_score: int = 0
    overall_risk_level: RiskLevel = RiskLevel.SAFE
    blocked: bool = False            # True when highest_score > 60


class SessionRecord(BaseModel):
    """One request/response pair logged during a GuardLayer session."""
    record_id: str
    timestamp: datetime
    target_url: str                  # the LLM API endpoint being proxied
    request_scan: ScanResult
    response_scan: ScanResult | None = None
    was_blocked: bool = False
