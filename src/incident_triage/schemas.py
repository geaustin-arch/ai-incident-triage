from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field, field_validator


class IncidentRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=100)
    service: str = Field(min_length=1, max_length=120)
    severity: Literal["sev1", "sev2", "sev3", "sev4"]
    summary: str = Field(min_length=8, max_length=1500)
    log_lines: list[str] = Field(min_length=1, max_length=60)

    @field_validator("incident_id", "service", "summary")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value

    @field_validator("log_lines")
    @classmethod
    def bound_log_lines(cls, lines: list[str]) -> list[str]:
        if any(not line.strip() or len(line) > 1000 for line in lines):
            raise ValueError("each log line must contain 1 to 1000 characters")
        return lines


class Evidence(BaseModel):
    line_id: str = Field(pattern=r"^log-\d{2}$")
    quote: str = Field(min_length=1, max_length=500)


class IncidentAssessment(BaseModel):
    likely_cause: str = Field(min_length=8, max_length=600)
    confidence: float = Field(ge=0, le=1)
    evidence: list[Evidence] = Field(max_length=8)
    immediate_actions: list[str] = Field(min_length=1, max_length=5)
    escalation_required: bool
    uncertainty: str = Field(max_length=500)


class IncidentResponse(BaseModel):
    incident_id: str
    analysis_mode: Literal["google_cloud_gemini", "deterministic_fallback"]
    assessment: IncidentAssessment
    privacy_redactions: int
