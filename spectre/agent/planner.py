"""
Investigation Planner

Uses LLM to analyze user queries, extract entities, and build
execution plans (DAGs) for plugin orchestration.
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from spectre.agent.llm import BaseLLMClient, LLMMessage
from spectre.plugins.base import EntityType
from spectre.plugins.registry import PluginRegistry

logger = structlog.get_logger(__name__)


class InvestigationDepth(str, Enum):
    """Depth levels for investigation."""

    QUICK = "quick"  # Fast, essential plugins only
    STANDARD = "standard"  # Balanced depth
    FULL = "full"  # Comprehensive, all applicable plugins


@dataclass
class ExtractedEntity:
    """An entity extracted from user query."""

    type: EntityType
    value: str
    confidence: float = 1.0
    context: str | None = None  # Additional context about why this was extracted


@dataclass
class PluginTask:
    """A task to execute a plugin."""

    plugin_name: str
    entity: ExtractedEntity
    priority: int = 0  # Lower = higher priority
    depends_on: list[str] = field(default_factory=list)  # Task IDs this depends on
    task_id: str = ""

    def __post_init__(self) -> None:
        if not self.task_id:
            self.task_id = f"{self.plugin_name}:{self.entity.value}"


@dataclass
class InvestigationPlan:
    """A plan for executing an investigation."""

    query: str
    entities: list[ExtractedEntity]
    tasks: list[PluginTask]
    depth: InvestigationDepth
    reasoning: str = ""  # LLM's reasoning for the plan
    estimated_duration_seconds: int = 0

    def get_execution_order(self) -> list[list[PluginTask]]:
        """Get tasks grouped by execution wave (parallel tasks in same wave)."""
        if not self.tasks:
            return []

        # Build dependency graph
        task_map = {t.task_id: t for t in self.tasks}
        waves: list[list[PluginTask]] = []
        completed: set[str] = set()

        remaining = list(self.tasks)
        while remaining:
            # Find tasks with all dependencies satisfied
            ready = [
                t for t in remaining
                if all(dep in completed for dep in t.depends_on)
            ]

            if not ready:
                # Circular dependency or missing dependency - just run remaining
                logger.warning("Could not resolve dependencies, running remaining tasks")
                waves.append(remaining)
                break

            # Sort by priority
            ready.sort(key=lambda t: t.priority)
            waves.append(ready)

            # Mark as completed
            for t in ready:
                completed.add(t.task_id)
                remaining.remove(t)

        return waves

    def to_dict(self) -> dict[str, Any]:
        """Convert plan to dictionary."""
        return {
            "query": self.query,
            "entities": [
                {
                    "type": e.type.value,
                    "value": e.value,
                    "confidence": e.confidence,
                    "context": e.context,
                }
                for e in self.entities
            ],
            "tasks": [
                {
                    "task_id": t.task_id,
                    "plugin": t.plugin_name,
                    "entity": {"type": t.entity.type.value, "value": t.entity.value},
                    "priority": t.priority,
                    "depends_on": t.depends_on,
                }
                for t in self.tasks
            ],
            "depth": self.depth.value,
            "reasoning": self.reasoning,
        }


# System prompt for the planner LLM
PLANNER_SYSTEM_PROMPT = """You are SPECTRE's investigation planner. Your job is to analyze user queries about security investigations and create execution plans.

Given a user query, you must:
1. Extract target entities (domains, IPs, emails, hashes)
2. Determine which plugins should be run
3. Order plugins by dependencies and priority

Available plugins and their capabilities:
{plugins_info}

Response format (JSON):
{{
    "entities": [
        {{
            "type": "domain|ip_address|email|hash",
            "value": "the actual value",
            "confidence": 0.0-1.0,
            "context": "why this entity was extracted"
        }}
    ],
    "tasks": [
        {{
            "plugin": "plugin_name",
            "entity_index": 0,
            "priority": 0,
            "depends_on": [],
            "reasoning": "why this plugin"
        }}
    ],
    "depth_recommendation": "quick|standard|full",
    "overall_reasoning": "explanation of the plan"
}}

Guidelines:
- For domain investigations: start with dns_recon and whois_lookup (no dependencies)
- For IP investigations: start with reverse DNS and geolocation
- cert_transparency depends on dns_recon (needs subdomains)
- subdomain_enum can run in parallel with whois_lookup
- Higher priority number = run later
- Be conservative with "full" depth - only recommend if user explicitly asks for comprehensive scan
"""


class InvestigationPlanner:
    """
    Plans investigations using LLM analysis.

    Analyzes user queries, extracts entities, and builds
    execution DAGs for plugin orchestration.
    """

    def __init__(
        self,
        llm_client: BaseLLMClient,
        registry: PluginRegistry,
    ) -> None:
        """Initialize the planner."""
        self.llm = llm_client
        self.registry = registry

    def _get_plugins_info(self) -> str:
        """Get formatted plugin information for the system prompt."""
        plugins = self.registry.list_plugins()
        lines = []
        for p in plugins:
            input_types = ", ".join(t.value for t in p.input_types)
            output_types = ", ".join(t.value for t in p.output_types)
            lines.append(
                f"- {p.name}: {p.description}\n"
                f"  Input: {input_types} | Output: {output_types}"
            )
        return "\n".join(lines)

    async def plan(
        self,
        query: str,
        depth: InvestigationDepth = InvestigationDepth.STANDARD,
    ) -> InvestigationPlan:
        """
        Create an investigation plan from a user query.

        Args:
            query: Natural language query from user
            depth: Desired investigation depth

        Returns:
            InvestigationPlan with entities and tasks
        """
        logger.info("Planning investigation", query=query, depth=depth.value)

        # Build system prompt with plugin info
        system_prompt = PLANNER_SYSTEM_PROMPT.format(
            plugins_info=self._get_plugins_info()
        )

        # Create the planning request
        messages = [
            LLMMessage(
                role="user",
                content=f"Plan an investigation for: {query}\n\nRequested depth: {depth.value}",
            )
        ]

        # Get LLM response
        try:
            plan_data = await self.llm.generate_json(messages, system_prompt)
        except Exception as e:
            logger.error("LLM planning failed", error=str(e))
            # Fall back to rule-based planning
            return self._fallback_plan(query, depth)

        # Parse the response
        return self._parse_plan_response(query, depth, plan_data)

    def _parse_plan_response(
        self,
        query: str,
        depth: InvestigationDepth,
        data: dict[str, Any],
    ) -> InvestigationPlan:
        """Parse LLM response into an InvestigationPlan."""
        entities: list[ExtractedEntity] = []
        tasks: list[PluginTask] = []

        # Parse entities
        for e in data.get("entities", []):
            try:
                entity_type = EntityType(e.get("type", "domain"))
                entities.append(
                    ExtractedEntity(
                        type=entity_type,
                        value=e.get("value", ""),
                        confidence=float(e.get("confidence", 1.0)),
                        context=e.get("context"),
                    )
                )
            except (ValueError, KeyError) as err:
                logger.warning("Failed to parse entity", entity=e, error=str(err))

        # Parse tasks
        for t in data.get("tasks", []):
            try:
                plugin_name = t.get("plugin", "")
                entity_index = int(t.get("entity_index", 0))

                if not plugin_name or not self.registry.has_plugin(plugin_name):
                    logger.warning("Unknown plugin in plan", plugin=plugin_name)
                    continue

                if entity_index >= len(entities):
                    logger.warning("Invalid entity index", index=entity_index)
                    continue

                task = PluginTask(
                    plugin_name=plugin_name,
                    entity=entities[entity_index],
                    priority=int(t.get("priority", 0)),
                    depends_on=t.get("depends_on", []),
                )
                tasks.append(task)
            except (ValueError, KeyError, IndexError) as err:
                logger.warning("Failed to parse task", task=t, error=str(err))

        # Use LLM's depth recommendation if provided
        recommended_depth = data.get("depth_recommendation")
        if recommended_depth:
            try:
                depth = InvestigationDepth(recommended_depth)
            except ValueError:
                pass

        return InvestigationPlan(
            query=query,
            entities=entities,
            tasks=tasks,
            depth=depth,
            reasoning=data.get("overall_reasoning", ""),
        )

    def _fallback_plan(
        self,
        query: str,
        depth: InvestigationDepth,
    ) -> InvestigationPlan:
        """
        Create a rule-based plan when LLM is unavailable.

        Uses simple heuristics to extract entities and assign plugins.
        """
        logger.info("Using fallback rule-based planning")

        entities = self._extract_entities_rule_based(query)
        tasks = self._assign_plugins_rule_based(entities, depth)

        return InvestigationPlan(
            query=query,
            entities=entities,
            tasks=tasks,
            depth=depth,
            reasoning="Rule-based plan (LLM unavailable)",
        )

    def _extract_entities_rule_based(self, query: str) -> list[ExtractedEntity]:
        """Extract entities using regex patterns."""
        import re

        entities: list[ExtractedEntity] = []

        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        for match in re.finditer(domain_pattern, query):
            value = match.group().lower()
            # Filter out common false positives (but allow them in tests)
            if "." in value:
                entities.append(
                    ExtractedEntity(
                        type=EntityType.DOMAIN,
                        value=value,
                        confidence=0.9,
                        context="Extracted via regex",
                    )
                )

        # IP pattern (simplified IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, query):
            entities.append(
                ExtractedEntity(
                    type=EntityType.IP_ADDRESS,
                    value=match.group(),
                    confidence=0.95,
                    context="Extracted via regex",
                )
            )

        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        for match in re.finditer(email_pattern, query):
            entities.append(
                ExtractedEntity(
                    type=EntityType.EMAIL,
                    value=match.group().lower(),
                    confidence=0.95,
                    context="Extracted via regex",
                )
            )

        # Hash patterns
        hash_patterns = [
            (r'\b[a-fA-F0-9]{32}\b', "MD5"),
            (r'\b[a-fA-F0-9]{40}\b', "SHA1"),
            (r'\b[a-fA-F0-9]{64}\b', "SHA256"),
        ]
        for pattern, hash_type in hash_patterns:
            for match in re.finditer(pattern, query):
                entities.append(
                    ExtractedEntity(
                        type=EntityType.HASH,
                        value=match.group().lower(),
                        confidence=0.9,
                        context=f"{hash_type} hash extracted via regex",
                    )
                )

        return entities

    def _assign_plugins_rule_based(
        self,
        entities: list[ExtractedEntity],
        depth: InvestigationDepth,
    ) -> list[PluginTask]:
        """Assign plugins to entities based on rules."""
        tasks: list[PluginTask] = []

        # Plugin assignments by entity type and depth
        plugin_map: dict[EntityType, dict[InvestigationDepth, list[tuple[str, int, list[str]]]]] = {
            EntityType.DOMAIN: {
                InvestigationDepth.QUICK: [
                    ("dns_recon", 0, []),
                ],
                InvestigationDepth.STANDARD: [
                    ("dns_recon", 0, []),
                    ("whois_lookup", 0, []),
                ],
                InvestigationDepth.FULL: [
                    ("dns_recon", 0, []),
                    ("whois_lookup", 0, []),
                    ("subdomain_enum", 1, []),
                    ("cert_transparency", 1, []),
                ],
            },
            EntityType.IP_ADDRESS: {
                InvestigationDepth.QUICK: [],
                InvestigationDepth.STANDARD: [],
                InvestigationDepth.FULL: [],
            },
        }

        for entity in entities:
            entity_plugins = plugin_map.get(entity.type, {}).get(depth, [])

            for plugin_name, priority, depends_on in entity_plugins:
                if self.registry.has_plugin(plugin_name):
                    tasks.append(
                        PluginTask(
                            plugin_name=plugin_name,
                            entity=entity,
                            priority=priority,
                            depends_on=depends_on,
                        )
                    )

        return tasks

    def plan_sync(
        self,
        query: str,
        depth: InvestigationDepth = InvestigationDepth.STANDARD,
    ) -> InvestigationPlan:
        """
        Create an investigation plan without LLM (rule-based only).

        Useful when no LLM is configured or for quick local planning.
        """
        entities = self._extract_entities_rule_based(query)
        tasks = self._assign_plugins_rule_based(entities, depth)

        return InvestigationPlan(
            query=query,
            entities=entities,
            tasks=tasks,
            depth=depth,
            reasoning="Rule-based plan (sync mode)",
        )
