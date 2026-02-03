"""
Investigations Router

REST API endpoints and WebSocket for investigations.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Query, Request
from fastapi.responses import JSONResponse

from spectre.agent.planner import InvestigationDepth
from spectre.api.schemas.investigation import (
    InvestigationCreate,
    InvestigationResponse,
    InvestigationSummary,
    InvestigationListResponse,
    InvestigationProgress,
    FindingResponse,
    DiscoveredEntityResponse,
    ThreatAssessmentResponse,
    InvestigationEventResponse,
    TargetEntityResponse,
)
from spectre.api.schemas.finding import FindingDetail, FindingListResponse
from spectre.services import (
    InvestigationService,
    Investigation,
    InvestigationStatus,
    get_investigation_service,
)
from spectre.services.event_bus import get_event_bus

router = APIRouter(prefix="/investigations")


def _convert_investigation_to_response(inv: Investigation) -> InvestigationResponse:
    """Convert Investigation model to API response."""
    return InvestigationResponse(
        id=inv.id,
        query=inv.query,
        target=TargetEntityResponse(
            type=inv.target.type.value,
            value=inv.target.value,
            confidence=inv.target.confidence,
        ),
        status=inv.status.value,
        progress=inv.progress,
        current_stage=inv.current_stage,
        error=inv.error,
        created_at=inv.created_at.isoformat(),
        started_at=inv.started_at.isoformat() if inv.started_at else None,
        completed_at=inv.completed_at.isoformat() if inv.completed_at else None,
        duration_seconds=inv.duration_seconds,
        plugins_total=inv.plugins_total,
        plugins_completed=inv.plugins_completed,
        plugins_failed=inv.plugins_failed,
        findings=[
            FindingResponse(
                id=str(f.id),
                type=f.finding.type,
                source=f.finding.source,
                data=f.finding.data,
                confidence=f.finding.confidence,
                threat_level=f.threat_level,
                timestamp=f.finding.timestamp.isoformat(),
            )
            for f in inv.findings
        ],
        entities=[
            DiscoveredEntityResponse(
                id=str(e.id),
                type=e.type.value,
                value=e.value,
                source_plugin=e.source_plugin,
                confidence=e.confidence,
                properties=e.properties,
                discovered_at=e.discovered_at.isoformat(),
            )
            for e in inv.entities
        ],
        threat_assessment=ThreatAssessmentResponse(
            threat_level=inv.threat_assessment.threat_level,
            confidence_score=inv.threat_assessment.confidence_score,
            is_malicious=inv.threat_assessment.is_malicious,
            threat_types=inv.threat_assessment.threat_types,
            indicators_of_compromise=inv.threat_assessment.indicators_of_compromise,
            attributed_actors=inv.threat_assessment.attributed_actors,
            mitre_techniques=inv.threat_assessment.mitre_techniques,
            summary=inv.threat_assessment.summary,
        ) if inv.threat_assessment else None,
        events=[
            InvestigationEventResponse(
                id=str(e.id),
                type=e.type.value,
                timestamp=e.timestamp.isoformat(),
                data=e.data,
            )
            for e in inv.events[-50:]  # Last 50 events
        ],
    )


def _convert_investigation_to_summary(inv: Investigation) -> InvestigationSummary:
    """Convert Investigation model to summary response."""
    return InvestigationSummary(
        id=inv.id,
        query=inv.query,
        target=TargetEntityResponse(
            type=inv.target.type.value,
            value=inv.target.value,
            confidence=inv.target.confidence,
        ),
        status=inv.status.value,
        progress=inv.progress,
        current_stage=inv.current_stage,
        threat_level=inv.threat_assessment.threat_level if inv.threat_assessment else "unknown",
        findings_count=len(inv.findings),
        entities_count=len(inv.entities),
        created_at=inv.created_at.isoformat(),
        completed_at=inv.completed_at.isoformat() if inv.completed_at else None,
        duration_seconds=inv.duration_seconds,
    )


@router.post("", response_model=InvestigationResponse, status_code=201)
async def start_investigation(request: InvestigationCreate) -> InvestigationResponse:
    """
    Start a new investigation.

    The investigation runs asynchronously. Use the WebSocket endpoint
    or poll the GET endpoint to track progress.
    """
    service = get_investigation_service()

    # Map depth string to enum
    depth_map = {
        "quick": InvestigationDepth.QUICK,
        "standard": InvestigationDepth.STANDARD,
        "full": InvestigationDepth.FULL,
    }
    depth = depth_map.get(request.depth, InvestigationDepth.STANDARD)

    investigation = await service.start(
        query=request.query,
        depth=depth,
        entity_type=request.entity_type,
        entity_value=request.entity_value,
    )

    return _convert_investigation_to_response(investigation)


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    status: str | None = Query(default=None, description="Filter by status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> InvestigationListResponse:
    """
    List investigations with optional filtering and pagination.
    """
    service = get_investigation_service()

    # Convert status string to enum
    status_enum = None
    if status:
        try:
            status_enum = InvestigationStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    investigations = await service.list(status=status_enum, limit=limit, offset=offset)
    total = await service.store.count(status=status_enum)

    return InvestigationListResponse(
        items=[_convert_investigation_to_summary(inv) for inv in investigations],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(investigation_id: str) -> InvestigationResponse:
    """
    Get investigation details by ID.
    """
    service = get_investigation_service()
    investigation = await service.get(investigation_id)

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return _convert_investigation_to_response(investigation)


@router.get("/{investigation_id}/progress", response_model=InvestigationProgress)
async def get_investigation_progress(investigation_id: str) -> InvestigationProgress:
    """
    Get lightweight progress update for an investigation.
    Use this for polling when WebSocket is not available.
    """
    service = get_investigation_service()
    investigation = await service.get(investigation_id)

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    return InvestigationProgress(
        id=investigation.id,
        status=investigation.status.value,
        progress=investigation.progress,
        current_stage=investigation.current_stage,
        plugins_completed=investigation.plugins_completed,
        plugins_total=investigation.plugins_total,
    )


@router.delete("/{investigation_id}", status_code=204)
async def cancel_investigation(investigation_id: str) -> None:
    """
    Cancel a running investigation.
    """
    service = get_investigation_service()
    success = await service.cancel(investigation_id)

    if not success:
        investigation = await service.get(investigation_id)
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        raise HTTPException(status_code=400, detail="Investigation is not active")


@router.get("/{investigation_id}/findings", response_model=FindingListResponse)
async def get_investigation_findings(investigation_id: str) -> FindingListResponse:
    """
    Get all findings for an investigation.
    """
    service = get_investigation_service()
    investigation = await service.get(investigation_id)

    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    findings = [
        FindingDetail(
            id=str(f.id),
            type=f.finding.type,
            source=f.finding.source,
            data=f.finding.data,
            confidence=f.finding.confidence,
            threat_level=f.threat_level,
            is_ioc=f.is_ioc,
            timestamp=f.finding.timestamp.isoformat(),
            raw_response=f.finding.raw_response,
        )
        for f in investigation.findings
    ]

    # Count by source and threat level
    by_source: dict[str, int] = {}
    by_threat_level: dict[str, int] = {}
    for f in investigation.findings:
        source = f.finding.source
        by_source[source] = by_source.get(source, 0) + 1
        level = f.threat_level
        by_threat_level[level] = by_threat_level.get(level, 0) + 1

    return FindingListResponse(
        investigation_id=investigation_id,
        findings=findings,
        total=len(findings),
        by_source=by_source,
        by_threat_level=by_threat_level,
    )


@router.websocket("/ws/{investigation_id}")
async def investigation_websocket(websocket: WebSocket, investigation_id: str) -> None:
    """
    WebSocket endpoint for real-time investigation updates.

    Connect to receive events as they happen during an investigation.
    """
    await websocket.accept()

    service = get_investigation_service()
    event_bus = get_event_bus()

    # Verify investigation exists
    investigation = await service.get(investigation_id)
    if not investigation:
        await websocket.close(code=4004, reason="Investigation not found")
        return

    # Send initial state
    await websocket.send_json({
        "type": "connection.established",
        "investigation_id": investigation_id,
        "data": {
            "status": investigation.status.value,
            "progress": investigation.progress,
        },
    })

    try:
        # Subscribe to investigation events
        async for event in event_bus.subscribe(investigation_id):
            if event is None:  # End of stream
                break

            await websocket.send_json(event.to_ws_message())

            # Close on completion
            if event.type.value in (
                "investigation.completed",
                "investigation.failed",
                "investigation.cancelled",
            ):
                await websocket.close(code=1000)
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.close(code=1011, reason=str(e))
