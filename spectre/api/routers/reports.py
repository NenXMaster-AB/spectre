"""
Reports Router

REST API endpoints for intelligence report generation and retrieval.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from spectre.services import get_investigation_service, InvestigationStatus

router = APIRouter(prefix="/reports")


class ReportSummary(BaseModel):
    """Brief report info for list views."""
    id: str
    investigation_id: str
    title: str
    target: str
    target_type: str
    threat_level: str = "unknown"
    format: str = "markdown"
    created_at: str
    findings_count: int = 0
    entities_count: int = 0


class ReportDetail(BaseModel):
    """Full report with content."""
    id: str
    investigation_id: str
    title: str
    target: str
    target_type: str
    threat_level: str = "unknown"
    format: str = "markdown"
    content: str
    created_at: str
    findings_count: int = 0
    entities_count: int = 0
    executive_summary: str = ""
    sections: list[dict[str, Any]] = Field(default_factory=list)


class ReportListResponse(BaseModel):
    """List response."""
    reports: list[ReportSummary]
    total: int


@router.get("", response_model=ReportListResponse)
async def list_reports(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> ReportListResponse:
    """List available reports from completed investigations."""
    service = get_investigation_service()
    store = service._store

    investigations = await store.list(limit=100)

    reports = []
    for inv in investigations:
        if inv.status != InvestigationStatus.COMPLETED:
            continue

        threat_level = "unknown"
        if inv.threat_assessment:
            threat_level = inv.threat_assessment.get("threat_level", "unknown")

        reports.append(ReportSummary(
            id=f"report-{inv.id}",
            investigation_id=inv.id,
            title=f"Investigation: {inv.query}",
            target=inv.target.value,
            target_type=inv.target.type.value,
            threat_level=threat_level,
            format="markdown",
            created_at=inv.completed_at.isoformat() if inv.completed_at else inv.created_at.isoformat(),
            findings_count=len(inv.findings),
            entities_count=len(inv.entities),
        ))

    # Sort by creation time (newest first)
    reports.sort(key=lambda r: r.created_at, reverse=True)

    total = len(reports)
    paginated = reports[offset:offset + limit]

    return ReportListResponse(
        reports=paginated,
        total=total,
    )


@router.get("/{report_id}", response_model=ReportDetail)
async def get_report(
    report_id: str,
    format: str = Query("markdown", description="Report format: markdown, json, text"),
) -> ReportDetail:
    """Get a specific report."""
    # Extract investigation ID from report ID
    inv_id = report_id.replace("report-", "")

    service = get_investigation_service()
    store = service._store
    inv = await store.get(inv_id)

    if not inv:
        raise HTTPException(status_code=404, detail=f"Report not found: {report_id}")

    if inv.status != InvestigationStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Investigation not yet completed")

    threat_level = "unknown"
    if inv.threat_assessment:
        threat_level = inv.threat_assessment.get("threat_level", "unknown")

    # Generate report content
    content = _generate_report_content(inv, format)
    summary = _generate_executive_summary(inv)

    sections = [
        {"title": "Executive Summary", "type": "text", "content": summary},
        {"title": "Target Information", "type": "target", "content": {
            "type": inv.target.type.value,
            "value": inv.target.value,
        }},
        {"title": "Findings", "type": "findings", "content": {
            "total": len(inv.findings),
            "items": inv.findings[:20],
        }},
        {"title": "Discovered Entities", "type": "entities", "content": {
            "total": len(inv.entities),
            "items": inv.entities[:20],
        }},
    ]

    if inv.threat_assessment:
        sections.insert(1, {
            "title": "Threat Assessment",
            "type": "assessment",
            "content": inv.threat_assessment,
        })

    return ReportDetail(
        id=report_id,
        investigation_id=inv.id,
        title=f"Investigation: {inv.query}",
        target=inv.target.value,
        target_type=inv.target.type.value,
        threat_level=threat_level,
        format=format,
        content=content,
        created_at=inv.completed_at.isoformat() if inv.completed_at else inv.created_at.isoformat(),
        findings_count=len(inv.findings),
        entities_count=len(inv.entities),
        executive_summary=summary,
        sections=sections,
    )


def _generate_report_content(inv: Any, format: str) -> str:
    """Generate report content in the specified format."""
    lines = [
        f"# Intelligence Report: {inv.query}",
        f"",
        f"**Target:** {inv.target.value} ({inv.target.type.value})",
        f"**Status:** {inv.status.value}",
        f"**Created:** {inv.created_at.isoformat()}",
        f"",
    ]

    if inv.threat_assessment:
        ta = inv.threat_assessment
        lines.extend([
            "## Threat Assessment",
            f"",
            f"- **Threat Level:** {ta.get('threat_level', 'unknown')}",
            f"- **Confidence:** {ta.get('confidence_score', 0):.0%}",
            f"- **Malicious:** {'Yes' if ta.get('is_malicious') else 'No'}",
            f"",
        ])
        if ta.get("summary"):
            lines.append(ta["summary"])
            lines.append("")

    if inv.findings:
        lines.extend([
            "## Findings",
            f"",
            f"Total findings: {len(inv.findings)}",
            f"",
        ])
        for finding in inv.findings[:10]:
            source = finding.get("source", "unknown")
            ftype = finding.get("type", "unknown")
            level = finding.get("threat_level", "info")
            lines.append(f"- **[{level.upper()}]** {ftype} (source: {source})")
        if len(inv.findings) > 10:
            lines.append(f"- ... and {len(inv.findings) - 10} more findings")
        lines.append("")

    if inv.entities:
        lines.extend([
            "## Discovered Entities",
            f"",
            f"Total entities: {len(inv.entities)}",
            f"",
        ])
        for entity in inv.entities[:10]:
            etype = entity.get("type", "unknown")
            evalue = entity.get("value", "")
            lines.append(f"- **{etype}:** {evalue}")
        if len(inv.entities) > 10:
            lines.append(f"- ... and {len(inv.entities) - 10} more entities")

    return "\n".join(lines)


def _generate_executive_summary(inv: Any) -> str:
    """Generate executive summary for the report."""
    parts = [
        f"Investigation of {inv.target.value} ({inv.target.type.value}) "
        f"discovered {len(inv.findings)} finding(s) and {len(inv.entities)} related entity(s)."
    ]

    if inv.threat_assessment:
        ta = inv.threat_assessment
        level = ta.get("threat_level", "unknown")
        parts.append(f"Overall threat level: {level.upper()}.")

        if ta.get("attributed_actors"):
            actors = ", ".join(ta["attributed_actors"])
            parts.append(f"Potential attribution: {actors}.")

        if ta.get("summary"):
            parts.append(ta["summary"])

    return " ".join(parts)
