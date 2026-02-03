"""
SPECTRE Services Layer

Shared service layer used by CLI, Chat, and Web API interfaces.
Provides unified investigation orchestration with real-time event streaming.
"""

from spectre.services.investigation import InvestigationService, get_investigation_service
from spectre.services.models import (
    Investigation,
    InvestigationStatus,
    InvestigationEvent,
    InvestigationEventType,
    ThreatAssessment,
)
from spectre.services.event_bus import EventBus
from spectre.services.store import InvestigationStore

__all__ = [
    "InvestigationService",
    "get_investigation_service",
    "Investigation",
    "InvestigationStatus",
    "InvestigationEvent",
    "InvestigationEventType",
    "ThreatAssessment",
    "EventBus",
    "InvestigationStore",
]
