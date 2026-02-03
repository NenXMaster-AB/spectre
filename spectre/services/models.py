"""
Investigation Models

Data models for tracking investigation state across all interfaces.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from spectre.plugins.base import EntityType, Finding, PluginResult


class InvestigationStatus(str, Enum):
    """Status of an investigation."""

    PENDING = "pending"  # Created but not started
    PLANNING = "planning"  # LLM is building the plan
    EXECUTING = "executing"  # Plugins are running
    CORRELATING = "correlating"  # Deduplicating and building relationships
    ENRICHING = "enriching"  # Adding threat intelligence
    COMPLETED = "completed"  # Successfully finished
    FAILED = "failed"  # Error occurred
    CANCELLED = "cancelled"  # User cancelled


class InvestigationEventType(str, Enum):
    """Types of investigation events for real-time updates."""

    # Lifecycle events
    INVESTIGATION_STARTED = "investigation.started"
    INVESTIGATION_COMPLETED = "investigation.completed"
    INVESTIGATION_FAILED = "investigation.failed"
    INVESTIGATION_CANCELLED = "investigation.cancelled"

    # Stage transitions
    STAGE_CHANGED = "stage.changed"
    PROGRESS_UPDATED = "progress.updated"

    # Plugin events
    PLUGIN_STARTED = "plugin.started"
    PLUGIN_COMPLETED = "plugin.completed"
    PLUGIN_FAILED = "plugin.failed"

    # Discovery events
    FINDING_DISCOVERED = "finding.discovered"
    ENTITY_DISCOVERED = "entity.discovered"
    THREAT_DETECTED = "threat.detected"

    # Planning events
    PLAN_CREATED = "plan.created"


class InvestigationEvent(BaseModel):
    """An event that occurred during an investigation."""

    id: UUID = Field(default_factory=uuid4)
    type: InvestigationEventType
    investigation_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)

    def to_ws_message(self) -> dict[str, Any]:
        """Convert to WebSocket message format."""
        return {
            "id": str(self.id),
            "type": self.type.value,
            "investigation_id": self.investigation_id,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class TargetEntity(BaseModel):
    """The target entity for an investigation."""

    type: EntityType
    value: str
    confidence: float = 1.0


class DiscoveredEntity(BaseModel):
    """An entity discovered during investigation."""

    id: UUID = Field(default_factory=uuid4)
    type: EntityType
    value: str
    source_plugin: str
    confidence: float = 1.0
    properties: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EntityRelationship(BaseModel):
    """A relationship between two entities."""

    id: UUID = Field(default_factory=uuid4)
    source_id: str
    target_id: str
    relationship_type: str  # e.g., "resolves_to", "registered_by", "hosts"
    confidence: float = 1.0
    source_plugin: str


class ThreatAssessment(BaseModel):
    """Threat assessment for an investigation."""

    threat_level: str = "unknown"  # critical, high, medium, low, info, clean, unknown
    confidence_score: float = 0.0
    is_malicious: bool = False
    threat_types: list[str] = Field(default_factory=list)
    indicators_of_compromise: int = 0
    attributed_actors: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str = ""


class InvestigationFinding(BaseModel):
    """A finding with additional investigation context."""

    id: UUID = Field(default_factory=uuid4)
    finding: Finding
    threat_level: str = "info"  # Derived threat level
    is_ioc: bool = False  # Is this an indicator of compromise


class Investigation(BaseModel):
    """
    Full investigation state.

    Tracks the complete lifecycle of an investigation from creation to completion.
    """

    # Identity
    id: str = Field(default_factory=lambda: str(uuid4()))
    query: str  # Original user query
    target: TargetEntity

    # Status
    status: InvestigationStatus = InvestigationStatus.PENDING
    progress: float = 0.0  # 0.0 to 1.0
    current_stage: str = "initializing"
    error: str | None = None

    # Timing
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    # Plan (from planner)
    plan_reasoning: str = ""
    planned_plugins: list[str] = Field(default_factory=list)

    # Results
    plugin_results: list[PluginResult] = Field(default_factory=list)
    findings: list[InvestigationFinding] = Field(default_factory=list)
    entities: list[DiscoveredEntity] = Field(default_factory=list)
    relationships: list[EntityRelationship] = Field(default_factory=list)

    # Threat Assessment
    threat_assessment: ThreatAssessment | None = None

    # Events log
    events: list[InvestigationEvent] = Field(default_factory=list)

    # Statistics
    plugins_completed: int = 0
    plugins_failed: int = 0
    plugins_total: int = 0

    def add_event(self, event_type: InvestigationEventType, data: dict[str, Any] | None = None) -> InvestigationEvent:
        """Add an event to the investigation log."""
        event = InvestigationEvent(
            type=event_type,
            investigation_id=self.id,
            data=data or {},
        )
        self.events.append(event)
        return event

    def update_progress(self, progress: float, stage: str | None = None) -> None:
        """Update investigation progress."""
        self.progress = min(max(progress, 0.0), 1.0)
        if stage:
            self.current_stage = stage

    def mark_started(self) -> None:
        """Mark investigation as started."""
        self.status = InvestigationStatus.PLANNING
        self.started_at = datetime.now(timezone.utc)
        self.current_stage = "planning"

    def mark_completed(self) -> None:
        """Mark investigation as completed."""
        self.status = InvestigationStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.progress = 1.0
        self.current_stage = "completed"

    def mark_failed(self, error: str) -> None:
        """Mark investigation as failed."""
        self.status = InvestigationStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.error = error
        self.current_stage = "failed"

    def mark_cancelled(self) -> None:
        """Mark investigation as cancelled."""
        self.status = InvestigationStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)
        self.current_stage = "cancelled"

    @property
    def duration_seconds(self) -> float | None:
        """Get investigation duration in seconds."""
        if self.started_at:
            end = self.completed_at or datetime.now(timezone.utc)
            return (end - self.started_at).total_seconds()
        return None

    @property
    def is_active(self) -> bool:
        """Check if investigation is still running."""
        return self.status in (
            InvestigationStatus.PENDING,
            InvestigationStatus.PLANNING,
            InvestigationStatus.EXECUTING,
            InvestigationStatus.CORRELATING,
            InvestigationStatus.ENRICHING,
        )

    def to_summary(self) -> dict[str, Any]:
        """Convert to summary format for list views."""
        return {
            "id": self.id,
            "query": self.query,
            "target": {
                "type": self.target.type.value,
                "value": self.target.value,
            },
            "status": self.status.value,
            "progress": self.progress,
            "current_stage": self.current_stage,
            "threat_level": self.threat_assessment.threat_level if self.threat_assessment else "unknown",
            "findings_count": len(self.findings),
            "entities_count": len(self.entities),
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
        }
