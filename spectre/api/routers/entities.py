"""
Entities Router

REST API endpoints for entity graph data and search.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from spectre.services import get_investigation_service, InvestigationStatus

router = APIRouter(prefix="/entities")


class GraphNode(BaseModel):
    """A node in the entity graph."""
    id: str
    label: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source_plugins: list[str] = Field(default_factory=list)
    threat_level: str = "unknown"
    investigation_ids: list[str] = Field(default_factory=list)


class GraphLink(BaseModel):
    """A link between two nodes."""
    source: str
    target: str
    relationship: str
    confidence: float = 1.0
    source_plugin: str = ""


class GraphData(BaseModel):
    """D3-compatible graph data."""
    nodes: list[GraphNode]
    links: list[GraphLink]
    total_nodes: int = 0
    total_links: int = 0


class EntitySearchResult(BaseModel):
    """Entity search result."""
    id: str
    type: str
    value: str
    sources: list[str] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)
    investigation_ids: list[str] = Field(default_factory=list)


class EntitySearchResponse(BaseModel):
    """Search response."""
    results: list[EntitySearchResult]
    total: int
    query: str


@router.get("/graph", response_model=GraphData)
async def get_entity_graph(
    investigation_id: str | None = Query(None, description="Filter by investigation ID"),
    entity_type: str | None = Query(None, description="Filter by entity type"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum nodes"),
) -> GraphData:
    """
    Get entity graph data in D3-compatible format.

    Returns nodes and links from completed investigations.
    """
    service = get_investigation_service()
    store = service._store

    # Collect entities and relationships from investigations
    nodes_map: dict[str, GraphNode] = {}
    links: list[GraphLink] = []

    investigations = await store.list(limit=50)

    if investigation_id:
        inv = await store.get(investigation_id)
        investigations = [inv] if inv else []

    for inv in investigations:
        if inv.status not in (InvestigationStatus.COMPLETED, InvestigationStatus.EXECUTING):
            continue

        # Add target entity as a node
        target_key = f"{inv.target.type.value}:{inv.target.value}".lower()
        if target_key not in nodes_map:
            nodes_map[target_key] = GraphNode(
                id=target_key,
                label=inv.target.value,
                type=inv.target.type.value,
                properties={"confidence": inv.target.confidence},
                investigation_ids=[inv.id],
            )
        elif inv.id not in nodes_map[target_key].investigation_ids:
            nodes_map[target_key].investigation_ids.append(inv.id)

        # Set threat level from assessment
        if inv.threat_assessment:
            nodes_map[target_key].threat_level = inv.threat_assessment.get("threat_level", "unknown")

        # Add discovered entities as nodes
        for entity in inv.entities:
            etype = entity.get("type", "unknown")
            evalue = entity.get("value", "")
            if not evalue:
                continue

            if entity_type and etype != entity_type:
                continue

            key = f"{etype}:{evalue}".lower()
            if key not in nodes_map:
                nodes_map[key] = GraphNode(
                    id=key,
                    label=evalue,
                    type=etype,
                    properties={
                        k: v for k, v in entity.items()
                        if k not in ("type", "value", "source_plugin", "id")
                    },
                    source_plugins=[entity.get("source_plugin", "")],
                    investigation_ids=[inv.id],
                )
            else:
                source = entity.get("source_plugin", "")
                if source and source not in nodes_map[key].source_plugins:
                    nodes_map[key].source_plugins.append(source)
                if inv.id not in nodes_map[key].investigation_ids:
                    nodes_map[key].investigation_ids.append(inv.id)

            # Create link from target to discovered entity
            rel = entity.get("relationship", "related_to")
            links.append(GraphLink(
                source=target_key,
                target=key,
                relationship=rel,
                confidence=entity.get("confidence", 1.0),
                source_plugin=entity.get("source_plugin", ""),
            ))

    # Apply entity type filter to nodes
    if entity_type:
        # Keep target nodes and filtered type nodes
        filtered = {
            k: v for k, v in nodes_map.items()
            if v.type == entity_type or any(
                link.source == k or link.target == k
                for link in links
            )
        }
        nodes_map = filtered

    # Limit nodes
    nodes = list(nodes_map.values())[:limit]
    node_ids = {n.id for n in nodes}

    # Filter links to only include links between existing nodes
    valid_links = [
        link for link in links
        if link.source in node_ids and link.target in node_ids
    ]

    # Deduplicate links
    seen_links: set[tuple[str, str, str]] = set()
    unique_links: list[GraphLink] = []
    for link in valid_links:
        key = (link.source, link.target, link.relationship)
        if key not in seen_links:
            seen_links.add(key)
            unique_links.append(link)

    return GraphData(
        nodes=nodes,
        links=unique_links,
        total_nodes=len(nodes),
        total_links=len(unique_links),
    )


@router.get("/search", response_model=EntitySearchResponse)
async def search_entities(
    q: str = Query(..., min_length=1, description="Search query"),
    entity_type: str | None = Query(None, description="Filter by entity type"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
) -> EntitySearchResponse:
    """Search entities across all investigations."""
    service = get_investigation_service()
    store = service._store
    query_lower = q.lower()

    results: dict[str, EntitySearchResult] = {}

    investigations = await store.list(limit=100)

    for inv in investigations:
        # Search target
        if query_lower in inv.target.value.lower():
            key = f"{inv.target.type.value}:{inv.target.value}".lower()
            if key not in results:
                results[key] = EntitySearchResult(
                    id=key,
                    type=inv.target.type.value,
                    value=inv.target.value,
                    investigation_ids=[inv.id],
                )

        # Search discovered entities
        for entity in inv.entities:
            evalue = entity.get("value", "")
            etype = entity.get("type", "unknown")

            if entity_type and etype != entity_type:
                continue

            if query_lower in evalue.lower():
                key = f"{etype}:{evalue}".lower()
                if key not in results:
                    results[key] = EntitySearchResult(
                        id=key,
                        type=etype,
                        value=evalue,
                        sources=[entity.get("source_plugin", "")],
                        properties={
                            k: v for k, v in entity.items()
                            if k not in ("type", "value", "source_plugin", "id")
                        },
                        investigation_ids=[inv.id],
                    )
                elif inv.id not in results[key].investigation_ids:
                    results[key].investigation_ids.append(inv.id)

    result_list = list(results.values())[:limit]

    return EntitySearchResponse(
        results=result_list,
        total=len(result_list),
        query=q,
    )


@router.get("/types")
async def get_entity_types() -> dict[str, Any]:
    """Get available entity types with counts."""
    service = get_investigation_service()
    store = service._store

    type_counts: dict[str, int] = {}

    investigations = await store.list(limit=100)
    for inv in investigations:
        for entity in inv.entities:
            etype = entity.get("type", "unknown")
            type_counts[etype] = type_counts.get(etype, 0) + 1

    return {
        "types": type_counts,
        "total_entities": sum(type_counts.values()),
    }
