"""
Investigation API Schemas

Pydantic models for investigation API requests and responses.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from spectre.plugins.base import EntityType
from spectre.services.models import InvestigationStatus


class InvestigationCreate(BaseModel):
    """Request to start a new investigation."""

    query: str = Field(..., description="Target to investigate (domain, IP, email, hash, or natural language query)")
    entity_type: EntityType | None = Field(default=None, description="Explicit entity type (auto-detected if not provided)")
    entity_value: str | None = Field(default=None, description="Explicit entity value")
    depth: str = Field(default="standard", description="Investigation depth: quick, standard, or full")


class TargetEntityResponse(BaseModel):
    """Target entity in response."""

    type: str
    value: str
    confidence: float = 1.0


class FindingResponse(BaseModel):
    """A finding from a plugin."""

    id: str
    type: str
    source: str
    data: dict[str, Any]
    confidence: float
    threat_level: str
    timestamp: str


class DiscoveredEntityResponse(BaseModel):
    """A discovered entity."""

    id: str
    type: str
    value: str
    source_plugin: str
    confidence: float
    properties: dict[str, Any]
    discovered_at: str


class ThreatAssessmentResponse(BaseModel):
    """Threat assessment summary."""

    threat_level: str
    confidence_score: float
    is_malicious: bool
    threat_types: list[str]
    indicators_of_compromise: int
    attributed_actors: list[str]
    mitre_techniques: list[str]
    summary: str


class InvestigationEventResponse(BaseModel):
    """An investigation event."""

    id: str
    type: str
    timestamp: str
    data: dict[str, Any]


class InvestigationResponse(BaseModel):
    """Full investigation details."""

    id: str
    query: str
    target: TargetEntityResponse
    status: str
    progress: float
    current_stage: str
    error: str | None = None

    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None

    plugins_total: int
    plugins_completed: int
    plugins_failed: int

    findings: list[FindingResponse]
    entities: list[DiscoveredEntityResponse]
    threat_assessment: ThreatAssessmentResponse | None = None

    events: list[InvestigationEventResponse]


class InvestigationSummary(BaseModel):
    """Summary for list views."""

    id: str
    query: str
    target: TargetEntityResponse
    status: str
    progress: float
    current_stage: str
    threat_level: str
    findings_count: int
    entities_count: int
    created_at: str
    completed_at: str | None = None
    duration_seconds: float | None = None


class InvestigationListResponse(BaseModel):
    """Paginated list of investigations."""

    items: list[InvestigationSummary]
    total: int
    limit: int
    offset: int


class InvestigationProgress(BaseModel):
    """Lightweight progress update."""

    id: str
    status: str
    progress: float
    current_stage: str
    plugins_completed: int
    plugins_total: int


class WebSocketMessage(BaseModel):
    """WebSocket message format."""

    type: str
    investigation_id: str
    timestamp: str
    data: dict[str, Any]
