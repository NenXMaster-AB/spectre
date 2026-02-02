"""
Cross-Source Correlator

Correlates findings across plugin outputs, resolves duplicate entities,
and detects relationships to build an entity graph.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import structlog

from spectre.agent.executor import ExecutionResult
from spectre.plugins.base import EntityType, Finding, PluginResult

logger = structlog.get_logger(__name__)


@dataclass
class CorrelatedEntity:
    """An entity with correlated data from multiple sources."""

    id: str
    type: EntityType
    value: str
    sources: list[str] = field(default_factory=list)
    confidence: float = 1.0
    attributes: dict[str, Any] = field(default_factory=dict)
    relationships: list["EntityRelationship"] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def merge(self, other: "CorrelatedEntity") -> None:
        """Merge another entity's data into this one."""
        # Combine sources
        for source in other.sources:
            if source not in self.sources:
                self.sources.append(source)

        # Update confidence (take max)
        self.confidence = max(self.confidence, other.confidence)

        # Merge attributes (other's values take precedence for conflicts)
        self.attributes.update(other.attributes)

        # Combine relationships
        existing_rels = {(r.target_value, r.relationship_type) for r in self.relationships}
        for rel in other.relationships:
            if (rel.target_value, rel.relationship_type) not in existing_rels:
                self.relationships.append(rel)

        # Combine findings
        self.findings.extend(other.findings)

        # Combine tags
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "sources": self.sources,
            "confidence": self.confidence,
            "attributes": self.attributes,
            "relationships": [r.to_dict() for r in self.relationships],
            "tags": self.tags,
            "finding_count": len(self.findings),
        }


@dataclass
class EntityRelationship:
    """A relationship between two entities."""

    source_value: str
    target_value: str
    target_type: EntityType
    relationship_type: str  # e.g., "resolves_to", "registered_by", "hosts"
    confidence: float = 1.0
    source_plugin: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_value": self.target_value,
            "target_type": self.target_type.value,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "source_plugin": self.source_plugin,
        }


@dataclass
class CorrelationResult:
    """Result of correlating investigation findings."""

    entities: list[CorrelatedEntity]
    relationships: list[EntityRelationship]
    total_findings: int = 0
    total_sources: int = 0
    duplicate_entities_merged: int = 0

    def get_entity(self, value: str) -> CorrelatedEntity | None:
        """Get entity by value."""
        for entity in self.entities:
            if entity.value.lower() == value.lower():
                return entity
        return None

    def get_entities_by_type(self, entity_type: EntityType) -> list[CorrelatedEntity]:
        """Get all entities of a specific type."""
        return [e for e in self.entities if e.type == entity_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "summary": {
                "total_entities": len(self.entities),
                "total_relationships": len(self.relationships),
                "total_findings": self.total_findings,
                "total_sources": self.total_sources,
                "duplicates_merged": self.duplicate_entities_merged,
                "entities_by_type": {
                    t.value: len(self.get_entities_by_type(t))
                    for t in EntityType
                    if self.get_entities_by_type(t)
                },
            },
        }


class Correlator:
    """
    Correlates findings across multiple plugin outputs.

    Performs:
    - Entity deduplication and merging
    - Relationship detection
    - Confidence aggregation
    - Cross-source validation
    """

    def __init__(self) -> None:
        """Initialize the correlator."""
        self._entity_map: dict[str, CorrelatedEntity] = {}
        self._relationships: list[EntityRelationship] = []

    def correlate(self, execution_result: ExecutionResult) -> CorrelationResult:
        """
        Correlate findings from an execution result.

        Args:
            execution_result: Result from executing an investigation plan

        Returns:
            CorrelationResult with correlated entities and relationships
        """
        logger.info(
            "Starting correlation",
            result_count=len(execution_result.all_results),
        )

        self._entity_map.clear()
        self._relationships.clear()

        total_findings = 0
        sources: set[str] = set()
        duplicates_merged = 0

        # Process each plugin result
        for result in execution_result.all_results:
            if not result.success:
                continue

            sources.add(result.plugin_name)
            total_findings += len(result.findings)

            # Process findings
            for finding in result.findings:
                self._process_finding(finding, result.plugin_name, result.input_entity)

            # Process discovered entities
            for entity_data in result.entities_discovered:
                merged = self._add_entity(
                    entity_type=EntityType(entity_data.get("type", "domain")),
                    value=entity_data.get("value", ""),
                    source=result.plugin_name,
                    attributes=entity_data,
                )
                if merged:
                    duplicates_merged += 1

                # Create relationship if specified
                rel_type = entity_data.get("relationship")
                if rel_type and result.input_entity.get("value"):
                    self._relationships.append(
                        EntityRelationship(
                            source_value=result.input_entity["value"],
                            target_value=entity_data["value"],
                            target_type=EntityType(entity_data["type"]),
                            relationship_type=rel_type,
                            source_plugin=result.plugin_name,
                        )
                    )

        # Attach findings to entities
        self._attach_findings_to_entities(execution_result.all_results)

        # Deduplicate relationships
        unique_relationships = self._deduplicate_relationships()

        result = CorrelationResult(
            entities=list(self._entity_map.values()),
            relationships=unique_relationships,
            total_findings=total_findings,
            total_sources=len(sources),
            duplicate_entities_merged=duplicates_merged,
        )

        logger.info(
            "Correlation complete",
            entities=len(result.entities),
            relationships=len(result.relationships),
            duplicates_merged=duplicates_merged,
        )

        return result

    def _process_finding(
        self,
        finding: Finding,
        plugin_name: str,
        input_entity: dict[str, Any],
    ) -> None:
        """Process a finding and extract entities/relationships."""
        finding_type = finding.type
        data = finding.data

        # Handle DNS findings
        if finding_type.startswith("dns_"):
            self._process_dns_finding(finding, plugin_name, input_entity)

        # Handle WHOIS findings
        elif finding_type == "whois_data":
            self._process_whois_finding(finding, plugin_name, input_entity)

        elif finding_type == "whois_registrant":
            self._process_registrant_finding(finding, plugin_name, input_entity)

    def _process_dns_finding(
        self,
        finding: Finding,
        plugin_name: str,
        input_entity: dict[str, Any],
    ) -> None:
        """Process DNS-related findings."""
        data = finding.data
        record_type = data.get("type", "")
        value = data.get("value", "")
        domain = input_entity.get("value", "")

        if not value:
            return

        if record_type in ("A", "AAAA"):
            # Add IP entity
            self._add_entity(
                entity_type=EntityType.IP_ADDRESS,
                value=value,
                source=plugin_name,
                attributes={"ip_version": data.get("ip_version")},
            )
            # Add resolves_to relationship
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=value,
                    target_type=EntityType.IP_ADDRESS,
                    relationship_type="resolves_to",
                    source_plugin=plugin_name,
                )
            )

        elif record_type == "MX":
            # Add mail server domain
            self._add_entity(
                entity_type=EntityType.DOMAIN,
                value=value,
                source=plugin_name,
                attributes={"is_mail_server": True, "priority": data.get("priority")},
            )
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=value,
                    target_type=EntityType.DOMAIN,
                    relationship_type="mail_handled_by",
                    source_plugin=plugin_name,
                )
            )

        elif record_type == "NS":
            # Add nameserver domain
            self._add_entity(
                entity_type=EntityType.DOMAIN,
                value=value,
                source=plugin_name,
                attributes={"is_nameserver": True},
            )
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=value,
                    target_type=EntityType.DOMAIN,
                    relationship_type="nameserver",
                    source_plugin=plugin_name,
                )
            )

        elif record_type == "CNAME":
            # Add alias domain
            self._add_entity(
                entity_type=EntityType.DOMAIN,
                value=value,
                source=plugin_name,
                attributes={"is_alias_target": True},
            )
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=value,
                    target_type=EntityType.DOMAIN,
                    relationship_type="alias_of",
                    source_plugin=plugin_name,
                )
            )

    def _process_whois_finding(
        self,
        finding: Finding,
        plugin_name: str,
        input_entity: dict[str, Any],
    ) -> None:
        """Process WHOIS data finding."""
        data = finding.data
        domain = input_entity.get("value", "")

        # Update domain entity with WHOIS data
        if domain in self._entity_map:
            entity = self._entity_map[domain]
            entity.attributes.update({
                "registrar": data.get("registrar"),
                "creation_date": data.get("creation_date"),
                "expiration_date": data.get("expiration_date"),
                "nameservers": data.get("nameservers", []),
            })
        else:
            self._add_entity(
                entity_type=EntityType.DOMAIN,
                value=domain,
                source=plugin_name,
                attributes=data,
            )

    def _process_registrant_finding(
        self,
        finding: Finding,
        plugin_name: str,
        input_entity: dict[str, Any],
    ) -> None:
        """Process registrant information finding."""
        data = finding.data
        domain = input_entity.get("value", "")

        # Add email if present
        email = data.get("email")
        if email and "@" in email:
            self._add_entity(
                entity_type=EntityType.EMAIL,
                value=email,
                source=plugin_name,
                attributes={"role": "registrant"},
            )
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=email,
                    target_type=EntityType.EMAIL,
                    relationship_type="registered_by_email",
                    source_plugin=plugin_name,
                )
            )

        # Add organization if present
        org = data.get("organization")
        if org and org.lower() not in ("redacted", "n/a", "none", "private"):
            self._add_entity(
                entity_type=EntityType.ORGANIZATION,
                value=org,
                source=plugin_name,
                attributes={
                    "country": data.get("country"),
                    "role": "registrant",
                },
            )
            self._relationships.append(
                EntityRelationship(
                    source_value=domain,
                    target_value=org,
                    target_type=EntityType.ORGANIZATION,
                    relationship_type="registered_by_org",
                    source_plugin=plugin_name,
                )
            )

    def _add_entity(
        self,
        entity_type: EntityType,
        value: str,
        source: str,
        attributes: dict[str, Any] | None = None,
    ) -> bool:
        """
        Add or merge an entity.

        Returns True if entity was merged with existing.
        """
        if not value:
            return False

        # Normalize key
        key = value.lower().strip()

        if key in self._entity_map:
            # Merge with existing
            existing = self._entity_map[key]
            if source not in existing.sources:
                existing.sources.append(source)
            if attributes:
                # Merge attributes (new values don't overwrite existing non-None values)
                for k, v in attributes.items():
                    if v is not None and (k not in existing.attributes or existing.attributes[k] is None):
                        existing.attributes[k] = v
            return True
        else:
            # Create new entity
            self._entity_map[key] = CorrelatedEntity(
                id=str(uuid4()),
                type=entity_type,
                value=value,
                sources=[source],
                attributes=attributes or {},
            )
            return False

    def _attach_findings_to_entities(self, results: list[PluginResult]) -> None:
        """Attach relevant findings to their entities."""
        for result in results:
            input_value = result.input_entity.get("value", "").lower()
            if input_value in self._entity_map:
                entity = self._entity_map[input_value]
                for finding in result.findings:
                    entity.findings.append(finding)

    def _deduplicate_relationships(self) -> list[EntityRelationship]:
        """Remove duplicate relationships."""
        seen: set[tuple[str, str, str]] = set()
        unique: list[EntityRelationship] = []

        for rel in self._relationships:
            key = (rel.source_value.lower(), rel.target_value.lower(), rel.relationship_type)
            if key not in seen:
                seen.add(key)
                unique.append(rel)

        return unique


def correlate_results(execution_result: ExecutionResult) -> CorrelationResult:
    """
    Convenience function to correlate execution results.

    Args:
        execution_result: Result from executing an investigation plan

    Returns:
        CorrelationResult with correlated entities
    """
    correlator = Correlator()
    return correlator.correlate(execution_result)
