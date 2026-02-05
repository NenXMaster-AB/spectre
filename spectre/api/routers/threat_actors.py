"""
Threat Actors Router

REST API endpoints for threat actor profiles and MITRE ATT&CK data.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from spectre.intel.attribution import AttributionPipeline, ThreatActor

router = APIRouter(prefix="/threat-actors")

# Shared pipeline instance
_pipeline: AttributionPipeline | None = None


def _get_pipeline() -> AttributionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = AttributionPipeline()
    return _pipeline


class TTPResponse(BaseModel):
    """A MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str = ""
    tactic: str = ""


class ThreatActorSummary(BaseModel):
    """Brief threat actor info for list views."""
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    country: str = ""
    active: bool = True
    ttp_count: int = 0
    tool_count: int = 0
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    description: str = ""


class ThreatActorProfile(BaseModel):
    """Full threat actor profile."""
    id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    country: str = ""
    active: bool = True

    # TTPs
    techniques: list[str] = Field(default_factory=list)

    # Arsenal
    tools: list[str] = Field(default_factory=list)
    infrastructure: list[str] = Field(default_factory=list)

    # Targeting
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)

    # External references
    references: list[str] = Field(default_factory=list)


class ThreatActorListResponse(BaseModel):
    """List response."""
    actors: list[ThreatActorSummary]
    total: int


class ActorComparisonResponse(BaseModel):
    """Comparison between two actors."""
    actor_a: ThreatActorSummary
    actor_b: ThreatActorSummary
    shared_techniques: list[str] = Field(default_factory=list)
    unique_to_a: list[str] = Field(default_factory=list)
    unique_to_b: list[str] = Field(default_factory=list)
    shared_tools: list[str] = Field(default_factory=list)
    shared_sectors: list[str] = Field(default_factory=list)
    similarity_score: float = 0.0


def _actor_to_summary(actor: ThreatActor) -> ThreatActorSummary:
    """Convert ThreatActor dataclass to summary."""
    return ThreatActorSummary(
        id=actor.name.lower().replace(" ", "-"),
        name=actor.name,
        aliases=actor.aliases,
        country=actor.attribution_country or "",
        active=True,
        ttp_count=len(actor.known_ttps),
        tool_count=len(actor.known_tools),
        target_sectors=actor.target_sectors,
        target_countries=actor.target_countries,
        description=actor.description,
    )


def _actor_to_profile(actor: ThreatActor) -> ThreatActorProfile:
    """Convert ThreatActor dataclass to full profile."""
    return ThreatActorProfile(
        id=actor.name.lower().replace(" ", "-"),
        name=actor.name,
        aliases=actor.aliases,
        description=actor.description,
        country=actor.attribution_country or "",
        active=True,
        techniques=actor.known_ttps,
        tools=actor.known_tools,
        infrastructure=actor.known_infrastructure,
        target_sectors=actor.target_sectors,
        target_countries=actor.target_countries,
        references=actor.references,
    )


def _find_actor(actor_id: str) -> ThreatActor | None:
    """Find an actor by slug ID or name."""
    pipeline = _get_pipeline()

    # Try direct name lookup
    actor = pipeline.get_actor(actor_id.replace("-", " "))
    if actor:
        return actor

    # Try matching by slug
    for a in pipeline.list_actors():
        if a.name.lower().replace(" ", "-") == actor_id.lower():
            return a

    return None


@router.get("", response_model=ThreatActorListResponse)
async def list_threat_actors(
    sector: str | None = Query(None, description="Filter by target sector"),
    country: str | None = Query(None, description="Filter by attribution country"),
    q: str | None = Query(None, description="Search by name or alias"),
) -> ThreatActorListResponse:
    """List known threat actors with optional filtering."""
    pipeline = _get_pipeline()
    actors = pipeline.list_actors()

    summaries = []
    for actor in actors:
        if sector:
            if sector.lower() not in [s.lower() for s in actor.target_sectors]:
                continue

        if country:
            if (actor.attribution_country or "").lower() != country.lower():
                continue

        if q:
            q_lower = q.lower()
            name_match = q_lower in actor.name.lower()
            alias_match = any(q_lower in a.lower() for a in actor.aliases)
            if not name_match and not alias_match:
                continue

        summaries.append(_actor_to_summary(actor))

    return ThreatActorListResponse(
        actors=summaries,
        total=len(summaries),
    )


@router.get("/{actor_id}", response_model=ThreatActorProfile)
async def get_threat_actor(actor_id: str) -> ThreatActorProfile:
    """Get full threat actor profile."""
    actor = _find_actor(actor_id)

    if not actor:
        raise HTTPException(status_code=404, detail=f"Threat actor not found: {actor_id}")

    return _actor_to_profile(actor)


@router.get("/{actor_id}/techniques")
async def get_actor_techniques(actor_id: str) -> list[str]:
    """Get MITRE ATT&CK technique IDs used by an actor."""
    actor = _find_actor(actor_id)

    if not actor:
        raise HTTPException(status_code=404, detail=f"Threat actor not found: {actor_id}")

    return actor.known_ttps


@router.get("/compare/{actor_a_id}/{actor_b_id}", response_model=ActorComparisonResponse)
async def compare_actors(actor_a_id: str, actor_b_id: str) -> ActorComparisonResponse:
    """Compare two threat actors."""
    actor_a = _find_actor(actor_a_id)
    actor_b = _find_actor(actor_b_id)

    if not actor_a:
        raise HTTPException(status_code=404, detail=f"Actor not found: {actor_a_id}")
    if not actor_b:
        raise HTTPException(status_code=404, detail=f"Actor not found: {actor_b_id}")

    techs_a = set(actor_a.known_ttps)
    techs_b = set(actor_b.known_ttps)

    shared_techniques = list(techs_a & techs_b)
    unique_a = list(techs_a - techs_b)
    unique_b = list(techs_b - techs_a)

    tools_a = set(actor_a.known_tools)
    tools_b = set(actor_b.known_tools)
    shared_tools = list(tools_a & tools_b)

    sectors_a = set(actor_a.target_sectors)
    sectors_b = set(actor_b.target_sectors)
    shared_sectors = list(sectors_a & sectors_b)

    union = techs_a | techs_b
    similarity = len(shared_techniques) / len(union) if union else 0.0

    return ActorComparisonResponse(
        actor_a=_actor_to_summary(actor_a),
        actor_b=_actor_to_summary(actor_b),
        shared_techniques=shared_techniques,
        unique_to_a=unique_a,
        unique_to_b=unique_b,
        shared_tools=shared_tools,
        shared_sectors=shared_sectors,
        similarity_score=similarity,
    )
