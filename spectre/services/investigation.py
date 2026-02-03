"""
Investigation Service

Main orchestrator for investigations. Provides a unified interface
for CLI, Chat, and Web API to run investigations with the full pipeline:
Plan → Execute → Correlate → Enrich → Report
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Any

import structlog

from spectre.agent.planner import (
    InvestigationPlanner,
    InvestigationPlan,
    InvestigationDepth,
    ExtractedEntity,
)
from spectre.agent.executor import InvestigationExecutor, ExecutionResult
from spectre.agent.correlator import Correlator
from spectre.agent.llm import create_llm_client, BaseLLMClient
from spectre.intel.enrichment import EnrichmentPipeline, EnrichmentConfig
from spectre.plugins.base import EntityType, PluginConfig, PluginResult, Finding
from spectre.plugins.registry import PluginRegistry, get_registry
from spectre.services.models import (
    Investigation,
    InvestigationStatus,
    InvestigationEvent,
    InvestigationEventType,
    TargetEntity,
    DiscoveredEntity,
    InvestigationFinding,
    ThreatAssessment,
)
from spectre.services.event_bus import EventBus, get_event_bus
from spectre.services.store import InvestigationStore, get_investigation_store

logger = structlog.get_logger(__name__)


class InvestigationServiceConfig:
    """Configuration for the investigation service."""

    def __init__(
        self,
        llm_provider: str = "claude",
        llm_model: str | None = None,
        use_llm_planning: bool = True,
        max_concurrent_plugins: int = 5,
        plugin_timeout_seconds: float = 30.0,
        api_keys: dict[str, str] | None = None,
    ) -> None:
        self.llm_provider = llm_provider
        self.llm_model = llm_model
        self.use_llm_planning = use_llm_planning
        self.max_concurrent_plugins = max_concurrent_plugins
        self.plugin_timeout_seconds = plugin_timeout_seconds
        self.api_keys = api_keys or {}


class InvestigationService:
    """
    Unified investigation orchestration service.

    Provides the full investigation pipeline:
    1. Planning - LLM analyzes query and builds execution plan
    2. Execution - Run plugins in parallel with dependency resolution
    3. Correlation - Deduplicate entities and build relationships
    4. Enrichment - Add threat intelligence from feeds
    5. Assessment - Generate threat assessment and report

    All interfaces (CLI, Chat, Web API) use this service for consistency.
    """

    def __init__(
        self,
        config: InvestigationServiceConfig | None = None,
        registry: PluginRegistry | None = None,
        store: InvestigationStore | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        """
        Initialize the investigation service.

        Args:
            config: Service configuration
            registry: Plugin registry (uses global if not provided)
            store: Investigation store (uses global if not provided)
            event_bus: Event bus for real-time updates (uses global if not provided)
        """
        self.config = config or InvestigationServiceConfig()
        self.registry = registry or get_registry()
        self.store = store or get_investigation_store()
        self.event_bus = event_bus or get_event_bus()

        # Lazily initialized components
        self._llm: BaseLLMClient | None = None
        self._planner: InvestigationPlanner | None = None
        self._executor: InvestigationExecutor | None = None
        self._correlator: Correlator | None = None
        self._enrichment: EnrichmentPipeline | None = None

    def _get_llm(self) -> BaseLLMClient:
        """Get or create LLM client."""
        if self._llm is None:
            self._llm = create_llm_client(
                self.config.llm_provider,
                model=self.config.llm_model,
            )
        return self._llm

    def _get_planner(self) -> InvestigationPlanner:
        """Get or create investigation planner."""
        if self._planner is None:
            self._planner = InvestigationPlanner(
                llm=self._get_llm(),
                registry=self.registry,
            )
        return self._planner

    def _get_executor(self) -> InvestigationExecutor:
        """Get or create investigation executor."""
        if self._executor is None:
            self._executor = InvestigationExecutor(
                registry=self.registry,
                max_concurrent=self.config.max_concurrent_plugins,
            )
        return self._executor

    def _get_enrichment(self) -> EnrichmentPipeline:
        """Get or create enrichment pipeline."""
        if self._enrichment is None:
            self._enrichment = EnrichmentPipeline(
                registry=self.registry,
                config=EnrichmentConfig(
                    max_concurrent=self.config.max_concurrent_plugins,
                    timeout_seconds=self.config.plugin_timeout_seconds,
                    api_keys=self.config.api_keys,
                ),
            )
        return self._enrichment

    async def start(
        self,
        query: str,
        depth: InvestigationDepth = InvestigationDepth.STANDARD,
        entity_type: EntityType | None = None,
        entity_value: str | None = None,
    ) -> Investigation:
        """
        Start a new investigation.

        Args:
            query: User query or target to investigate
            depth: Investigation depth (quick, standard, full)
            entity_type: Optional explicit entity type
            entity_value: Optional explicit entity value

        Returns:
            The created investigation (may still be running)
        """
        # Determine target entity
        if entity_type and entity_value:
            target = TargetEntity(type=entity_type, value=entity_value)
        else:
            # Auto-detect from query
            target = self._detect_entity(query)

        # Create investigation
        investigation = Investigation(
            query=query,
            target=target,
        )

        # Save and emit creation event
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.INVESTIGATION_STARTED,
            {"query": query, "target": target.model_dump()},
        )

        # Start the investigation pipeline in the background
        asyncio.create_task(self._run_pipeline(investigation, depth))

        return investigation

    async def get(self, investigation_id: str) -> Investigation | None:
        """
        Get an investigation by ID.

        Args:
            investigation_id: The investigation ID

        Returns:
            The investigation or None if not found
        """
        return await self.store.get(investigation_id)

    async def list(
        self,
        status: InvestigationStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Investigation]:
        """
        List investigations with optional filtering.

        Args:
            status: Filter by status
            limit: Maximum number to return
            offset: Number to skip

        Returns:
            List of investigations
        """
        return await self.store.list(status=status, limit=limit, offset=offset)

    async def cancel(self, investigation_id: str) -> bool:
        """
        Cancel a running investigation.

        Args:
            investigation_id: The investigation ID

        Returns:
            True if cancelled, False if not found or already completed
        """
        investigation = await self.store.get(investigation_id)
        if not investigation:
            return False

        if not investigation.is_active:
            return False

        investigation.mark_cancelled()
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.INVESTIGATION_CANCELLED,
        )
        await self.event_bus.cleanup_investigation(investigation_id)

        return True

    async def subscribe(
        self,
        investigation_id: str,
    ) -> AsyncIterator[InvestigationEvent]:
        """
        Subscribe to real-time events for an investigation.

        Args:
            investigation_id: The investigation ID

        Yields:
            Investigation events as they occur
        """
        async for event in self.event_bus.subscribe(investigation_id):
            if event is None:  # Sentinel for end of stream
                break
            yield event

    def _detect_entity(self, query: str) -> TargetEntity:
        """
        Auto-detect entity type from query.

        Simple heuristic detection - the LLM planner will do more sophisticated
        analysis if enabled.
        """
        query = query.strip().lower()

        # IP address pattern
        if self._looks_like_ip(query):
            return TargetEntity(type=EntityType.IP_ADDRESS, value=query)

        # Email pattern
        if "@" in query and "." in query.split("@")[-1]:
            return TargetEntity(type=EntityType.EMAIL, value=query)

        # Hash patterns (MD5, SHA1, SHA256)
        if len(query) == 32 and all(c in "0123456789abcdef" for c in query):
            return TargetEntity(type=EntityType.HASH, value=query)
        if len(query) == 40 and all(c in "0123456789abcdef" for c in query):
            return TargetEntity(type=EntityType.HASH, value=query)
        if len(query) == 64 and all(c in "0123456789abcdef" for c in query):
            return TargetEntity(type=EntityType.HASH, value=query)

        # Default to domain
        return TargetEntity(type=EntityType.DOMAIN, value=query)

    def _looks_like_ip(self, value: str) -> bool:
        """Check if value looks like an IP address."""
        parts = value.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        return False

    async def _run_pipeline(
        self,
        investigation: Investigation,
        depth: InvestigationDepth,
    ) -> None:
        """
        Run the full investigation pipeline.

        This is the main orchestration method that runs:
        1. Planning
        2. Execution
        3. Correlation
        4. Enrichment
        5. Assessment
        """
        try:
            investigation.mark_started()
            await self.store.save(investigation)

            # Stage 1: Planning
            await self._stage_planning(investigation, depth)

            # Check for cancellation
            if investigation.status == InvestigationStatus.CANCELLED:
                return

            # Stage 2: Execution
            await self._stage_execution(investigation)

            if investigation.status == InvestigationStatus.CANCELLED:
                return

            # Stage 3: Correlation
            await self._stage_correlation(investigation)

            if investigation.status == InvestigationStatus.CANCELLED:
                return

            # Stage 4: Enrichment (threat intel)
            await self._stage_enrichment(investigation)

            if investigation.status == InvestigationStatus.CANCELLED:
                return

            # Stage 5: Assessment
            await self._stage_assessment(investigation)

            # Complete
            investigation.mark_completed()
            await self.store.save(investigation)
            await self._emit_event(
                investigation,
                InvestigationEventType.INVESTIGATION_COMPLETED,
                {"summary": investigation.to_summary()},
            )

        except Exception as e:
            logger.exception("Investigation failed", investigation_id=investigation.id)
            investigation.mark_failed(str(e))
            await self.store.save(investigation)
            await self._emit_event(
                investigation,
                InvestigationEventType.INVESTIGATION_FAILED,
                {"error": str(e)},
            )

        finally:
            # Clean up event subscriptions
            await self.event_bus.cleanup_investigation(investigation.id)

    async def _stage_planning(
        self,
        investigation: Investigation,
        depth: InvestigationDepth,
    ) -> None:
        """Stage 1: Build investigation plan."""
        investigation.status = InvestigationStatus.PLANNING
        investigation.current_stage = "planning"
        investigation.update_progress(0.1)
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.STAGE_CHANGED,
            {"stage": "planning"},
        )

        if self.config.use_llm_planning:
            # Use LLM to build plan
            try:
                planner = self._get_planner()
                plan = await planner.plan(investigation.query, depth)
                investigation.plan_reasoning = plan.reasoning
                investigation.planned_plugins = [t.plugin_name for t in plan.tasks]
                investigation.plugins_total = len(plan.tasks)
            except Exception as e:
                logger.warning("LLM planning failed, using fallback", error=str(e))
                # Fallback to simple plugin selection
                investigation.planned_plugins = self._get_plugins_for_entity(
                    investigation.target.type
                )
                investigation.plugins_total = len(investigation.planned_plugins)
        else:
            # Simple plugin selection based on entity type
            investigation.planned_plugins = self._get_plugins_for_entity(
                investigation.target.type
            )
            investigation.plugins_total = len(investigation.planned_plugins)

        await self._emit_event(
            investigation,
            InvestigationEventType.PLAN_CREATED,
            {"plugins": investigation.planned_plugins},
        )

    async def _stage_execution(self, investigation: Investigation) -> None:
        """Stage 2: Execute plugins."""
        investigation.status = InvestigationStatus.EXECUTING
        investigation.current_stage = "executing"
        investigation.update_progress(0.2)
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.STAGE_CHANGED,
            {"stage": "executing"},
        )

        # Build plugin config
        plugin_config = PluginConfig()
        for key, value in self.config.api_keys.items():
            setattr(plugin_config, f"{key}_api_key", value)

        # Execute each plugin
        total_plugins = len(investigation.planned_plugins)
        for idx, plugin_name in enumerate(investigation.planned_plugins):
            if investigation.status == InvestigationStatus.CANCELLED:
                break

            await self._emit_event(
                investigation,
                InvestigationEventType.PLUGIN_STARTED,
                {"plugin": plugin_name},
            )

            try:
                if not self.registry.has_plugin(plugin_name):
                    logger.warning("Plugin not found", plugin=plugin_name)
                    investigation.plugins_failed += 1
                    continue

                plugin = self.registry.get_plugin(plugin_name)
                result = await plugin.execute(
                    {"type": investigation.target.type.value, "value": investigation.target.value},
                    plugin_config,
                )

                investigation.plugin_results.append(result)
                investigation.plugins_completed += 1

                # Process findings
                for finding in result.findings:
                    inv_finding = InvestigationFinding(
                        finding=finding,
                        threat_level=self._assess_finding_threat(finding),
                    )
                    investigation.findings.append(inv_finding)

                    await self._emit_event(
                        investigation,
                        InvestigationEventType.FINDING_DISCOVERED,
                        {"finding": finding.model_dump()},
                    )

                # Process discovered entities
                for entity_data in result.entities_discovered:
                    entity = DiscoveredEntity(
                        type=EntityType(entity_data.get("type", "domain")),
                        value=entity_data.get("value", ""),
                        source_plugin=plugin_name,
                        properties=entity_data,
                    )
                    investigation.entities.append(entity)

                    await self._emit_event(
                        investigation,
                        InvestigationEventType.ENTITY_DISCOVERED,
                        {"entity": entity.model_dump()},
                    )

                await self._emit_event(
                    investigation,
                    InvestigationEventType.PLUGIN_COMPLETED,
                    {"plugin": plugin_name, "findings_count": len(result.findings)},
                )

            except Exception as e:
                logger.error("Plugin execution failed", plugin=plugin_name, error=str(e))
                investigation.plugins_failed += 1
                await self._emit_event(
                    investigation,
                    InvestigationEventType.PLUGIN_FAILED,
                    {"plugin": plugin_name, "error": str(e)},
                )

            # Update progress
            progress = 0.2 + (0.5 * (idx + 1) / total_plugins)
            investigation.update_progress(progress)
            await self.store.save(investigation)
            await self._emit_event(
                investigation,
                InvestigationEventType.PROGRESS_UPDATED,
                {"progress": progress, "stage": "executing"},
            )

    async def _stage_correlation(self, investigation: Investigation) -> None:
        """Stage 3: Correlate and deduplicate results."""
        investigation.status = InvestigationStatus.CORRELATING
        investigation.current_stage = "correlating"
        investigation.update_progress(0.75)
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.STAGE_CHANGED,
            {"stage": "correlating"},
        )

        # Deduplicate entities
        seen_values: set[str] = set()
        unique_entities: list[DiscoveredEntity] = []
        for entity in investigation.entities:
            key = f"{entity.type.value}:{entity.value}"
            if key not in seen_values:
                seen_values.add(key)
                unique_entities.append(entity)

        investigation.entities = unique_entities

    async def _stage_enrichment(self, investigation: Investigation) -> None:
        """Stage 4: Enrich with threat intelligence."""
        investigation.status = InvestigationStatus.ENRICHING
        investigation.current_stage = "enriching"
        investigation.update_progress(0.85)
        await self.store.save(investigation)
        await self._emit_event(
            investigation,
            InvestigationEventType.STAGE_CHANGED,
            {"stage": "enriching"},
        )

        # Threat intelligence enrichment is already done via plugins
        # This stage can be extended for additional threat feed checks

    async def _stage_assessment(self, investigation: Investigation) -> None:
        """Stage 5: Generate threat assessment."""
        investigation.current_stage = "assessing"
        investigation.update_progress(0.95)
        await self.store.save(investigation)

        # Analyze findings for threat assessment
        threat_types: set[str] = set()
        ioc_count = 0
        is_malicious = False
        max_threat_level = "info"

        threat_level_order = ["clean", "info", "low", "medium", "high", "critical"]

        for inv_finding in investigation.findings:
            finding = inv_finding.finding
            data = finding.data

            # Check for malicious indicators
            if data.get("is_malicious"):
                is_malicious = True
            if data.get("threat_types"):
                threat_types.update(data["threat_types"])
            if inv_finding.is_ioc:
                ioc_count += 1

            # Track max threat level
            level = inv_finding.threat_level
            if level in threat_level_order:
                if threat_level_order.index(level) > threat_level_order.index(max_threat_level):
                    max_threat_level = level

        investigation.threat_assessment = ThreatAssessment(
            threat_level=max_threat_level,
            confidence_score=0.7 if investigation.plugins_completed > 0 else 0.0,
            is_malicious=is_malicious,
            threat_types=list(threat_types),
            indicators_of_compromise=ioc_count,
            summary=self._generate_threat_summary(investigation, max_threat_level, is_malicious),
        )

        if is_malicious or max_threat_level in ("high", "critical"):
            await self._emit_event(
                investigation,
                InvestigationEventType.THREAT_DETECTED,
                {"threat_level": max_threat_level, "is_malicious": is_malicious},
            )

    def _get_plugins_for_entity(self, entity_type: EntityType) -> list[str]:
        """Get applicable plugins for an entity type."""
        applicable_plugins = self.registry.get_plugins_for_entity(entity_type)
        return [p.name for p in applicable_plugins]

    def _assess_finding_threat(self, finding: Finding) -> str:
        """Assess threat level of a finding."""
        data = finding.data

        # Check for explicit malicious indicators
        if data.get("is_malicious"):
            return "critical" if data.get("detection_ratio", "0/0").startswith(("5", "6", "7", "8", "9")) else "high"

        if data.get("threat_types"):
            return "medium"

        if data.get("risk_score", 0) > 70:
            return "high"
        if data.get("risk_score", 0) > 40:
            return "medium"

        return "info"

    def _generate_threat_summary(
        self,
        investigation: Investigation,
        threat_level: str,
        is_malicious: bool,
    ) -> str:
        """Generate a human-readable threat summary."""
        target = investigation.target.value
        findings_count = len(investigation.findings)
        entities_count = len(investigation.entities)

        if is_malicious:
            return (
                f"Investigation of {target} detected malicious indicators. "
                f"Found {findings_count} findings across {investigation.plugins_completed} sources. "
                f"Threat level: {threat_level.upper()}"
            )
        elif threat_level in ("medium", "high", "critical"):
            return (
                f"Investigation of {target} found {findings_count} findings with elevated risk. "
                f"Discovered {entities_count} related entities. "
                f"Recommend further analysis."
            )
        else:
            return (
                f"Investigation of {target} completed. "
                f"Found {findings_count} findings and {entities_count} related entities. "
                f"No significant threats detected."
            )

    async def _emit_event(
        self,
        investigation: Investigation,
        event_type: InvestigationEventType,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Emit an investigation event."""
        event = investigation.add_event(event_type, data)
        await self.event_bus.publish(event)


# Global service instance
_service: InvestigationService | None = None


def get_investigation_service(
    config: InvestigationServiceConfig | None = None,
) -> InvestigationService:
    """Get the global investigation service instance."""
    global _service
    if _service is None:
        _service = InvestigationService(config=config)
    return _service
