"""
Finding API Schemas

Pydantic models for finding-related API responses.
"""

from typing import Any

from pydantic import BaseModel, Field


class FindingDetail(BaseModel):
    """Detailed finding information."""

    id: str
    type: str = Field(..., description="Type of finding (e.g., dns_record, whois_data)")
    source: str = Field(..., description="Plugin that produced this finding")
    data: dict[str, Any] = Field(default_factory=dict, description="Finding data")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    threat_level: str = Field(default="info", description="Threat level: critical, high, medium, low, info")
    is_ioc: bool = Field(default=False, description="Is this an indicator of compromise")
    timestamp: str
    raw_response: dict[str, Any] | None = Field(default=None, description="Raw API response for debugging")


class FindingListResponse(BaseModel):
    """List of findings for an investigation."""

    investigation_id: str
    findings: list[FindingDetail]
    total: int
    by_source: dict[str, int] = Field(default_factory=dict, description="Count of findings by source")
    by_threat_level: dict[str, int] = Field(default_factory=dict, description="Count by threat level")
