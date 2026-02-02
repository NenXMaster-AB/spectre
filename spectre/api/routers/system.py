"""System router - health checks and system info."""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from spectre.api.config import settings


router = APIRouter()


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: str


class SystemInfo(BaseModel):
    """System information response."""

    name: str
    version: str
    description: str
    status: str
    uptime_started: str


# Track when the API started
_startup_time = datetime.now(timezone.utc)


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="operational",
        version=settings.version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/system", response_model=SystemInfo)
async def system_info() -> SystemInfo:
    """Get system information."""
    return SystemInfo(
        name=settings.title,
        version=settings.version,
        description=settings.description,
        status="operational",
        uptime_started=_startup_time.isoformat(),
    )
