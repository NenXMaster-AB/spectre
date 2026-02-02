"""
Auto-Enrichment Pipeline

Automatically enriches entities with threat intelligence from multiple sources.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import structlog

from spectre.plugins.base import EntityType, PluginConfig, PluginResult
from spectre.plugins.registry import PluginRegistry

logger = structlog.get_logger(__name__)


@dataclass
class EnrichmentConfig:
    """Configuration for the enrichment pipeline."""

    # Maximum concurrent enrichment tasks
    max_concurrent: int = 5

    # Timeout per plugin (seconds)
    timeout_seconds: float = 30.0

    # Plugins to use for each entity type
    plugins_by_type: dict[str, list[str]] = field(default_factory=dict)

    # API keys for plugins that require them
    api_keys: dict[str, str] = field(default_factory=dict)

    # Skip plugins that require API keys if not configured
    skip_unconfigured: bool = True


@dataclass
class EnrichmentResult:
    """Result of enriching an entity."""

    entity: dict[str, Any]
    results: list[PluginResult]
    success: bool = True
    error: str | None = None
    confidence_score: float = 0.0
    is_malicious: bool = False
    threat_level: str = "unknown"

    @property
    def all_findings(self) -> list[dict[str, Any]]:
        """Get all findings from all results."""
        findings = []
        for result in self.results:
            findings.extend(result.findings)
        return findings

    @property
    def all_entities(self) -> list[dict[str, Any]]:
        """Get all discovered entities from all results."""
        entities = []
        for result in self.results:
            entities.extend(result.discovered_entities)
        return entities


class EnrichmentPipeline:
    """
    Auto-enrichment pipeline for entities.

    Takes an entity and automatically enriches it using relevant plugins
    based on entity type.
    """

    # Default plugins for each entity type
    DEFAULT_PLUGINS: dict[str, list[str]] = {
        "domain": ["dns_recon", "whois_lookup", "subdomain_enum", "cert_transparency",
                   "abuse_ch", "virustotal", "alienvault_otx"],
        "ip_address": ["abuse_ch", "virustotal", "shodan_lookup", "alienvault_otx"],
        "hash": ["abuse_ch", "virustotal", "alienvault_otx"],
        "url": ["abuse_ch", "virustotal", "alienvault_otx"],
    }

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        config: EnrichmentConfig | None = None,
    ) -> None:
        """Initialize the enrichment pipeline."""
        self.registry = registry or PluginRegistry()
        self.config = config or EnrichmentConfig()
        self._semaphore: asyncio.Semaphore | None = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Get or create the concurrency semaphore."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        return self._semaphore

    def _get_plugins_for_type(self, entity_type: str) -> list[str]:
        """Get plugins to use for an entity type."""
        # Check custom config first
        if entity_type in self.config.plugins_by_type:
            return self.config.plugins_by_type[entity_type]
        # Fall back to defaults
        return self.DEFAULT_PLUGINS.get(entity_type, [])

    def _create_plugin_config(self, plugin_name: str) -> PluginConfig | None:
        """Create plugin config with API key if available."""
        api_key = self.config.api_keys.get(plugin_name)

        # Check if plugin requires API key
        try:
            plugin = self.registry.get_plugin(plugin_name)
        except Exception:
            plugin = None
        if plugin and "api_key" in plugin.required_config:
            if not api_key and self.config.skip_unconfigured:
                logger.debug(
                    "Skipping plugin - API key not configured",
                    plugin=plugin_name,
                )
                return None

        return PluginConfig(
            api_key=api_key,
            timeout_seconds=self.config.timeout_seconds,
        )

    async def _run_plugin(
        self,
        plugin_name: str,
        entity: dict[str, Any],
    ) -> PluginResult | None:
        """Run a single plugin with concurrency control."""
        try:
            plugin = self.registry.get_plugin(plugin_name)
        except Exception:
            plugin = None
        if not plugin:
            logger.warning("Plugin not found", plugin=plugin_name)
            return None

        config = self._create_plugin_config(plugin_name)
        if config is None:
            return None

        semaphore = self._get_semaphore()
        async with semaphore:
            try:
                logger.debug(
                    "Running enrichment plugin",
                    plugin=plugin_name,
                    entity_type=entity.get("type"),
                )
                result = await asyncio.wait_for(
                    plugin.execute(entity, config),
                    timeout=self.config.timeout_seconds,
                )
                return result
            except asyncio.TimeoutError:
                logger.warning(
                    "Plugin timeout",
                    plugin=plugin_name,
                    timeout=self.config.timeout_seconds,
                )
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    input_entity=entity,
                    error="Plugin execution timed out",
                )
            except Exception as e:
                logger.error(
                    "Plugin execution error",
                    plugin=plugin_name,
                    error=str(e),
                )
                return PluginResult(
                    success=False,
                    plugin_name=plugin_name,
                    input_entity=entity,
                    error=str(e),
                )

    def _calculate_threat_assessment(
        self,
        results: list[PluginResult],
    ) -> tuple[float, bool, str]:
        """
        Calculate overall threat assessment from results.

        Returns:
            Tuple of (confidence_score, is_malicious, threat_level)
        """
        malicious_indicators = 0
        suspicious_indicators = 0
        total_sources = 0
        confidence_sum = 0.0

        for result in results:
            if not result.success:
                continue

            for finding in result.findings:
                total_sources += 1
                confidence = finding.get("confidence", 0.5)
                confidence_sum += confidence

                data = finding.get("data", {})

                # Check for malicious indicators
                if data.get("is_malicious"):
                    malicious_indicators += 1
                elif data.get("verdict") == "malicious":
                    malicious_indicators += 1
                elif data.get("pulse_count", 0) >= 3:
                    malicious_indicators += 1

                # Check for suspicious indicators
                if data.get("is_suspicious"):
                    suspicious_indicators += 1
                elif data.get("verdict") == "suspicious":
                    suspicious_indicators += 1
                elif data.get("pulse_count", 0) >= 1:
                    suspicious_indicators += 1

        if total_sources == 0:
            return 0.0, False, "unknown"

        # Calculate average confidence
        avg_confidence = confidence_sum / total_sources

        # Determine if malicious based on multiple sources agreeing
        is_malicious = malicious_indicators >= 2 or (
            malicious_indicators >= 1 and suspicious_indicators >= 2
        )

        # Determine threat level
        if malicious_indicators >= 3:
            threat_level = "critical"
        elif malicious_indicators >= 2:
            threat_level = "high"
        elif malicious_indicators >= 1 or suspicious_indicators >= 3:
            threat_level = "medium"
        elif suspicious_indicators >= 1:
            threat_level = "low"
        else:
            threat_level = "clean"

        # Adjust confidence based on source agreement
        if is_malicious and malicious_indicators >= 3:
            avg_confidence = min(avg_confidence + 0.2, 1.0)
        elif not is_malicious and threat_level == "clean":
            avg_confidence = min(avg_confidence + 0.1, 0.95)

        return avg_confidence, is_malicious, threat_level

    async def enrich(
        self,
        entity: dict[str, Any],
        plugins: list[str] | None = None,
    ) -> EnrichmentResult:
        """
        Enrich an entity with threat intelligence.

        Args:
            entity: Entity dict with 'type' and 'value' keys
            plugins: Optional list of specific plugins to use

        Returns:
            EnrichmentResult with findings from all sources
        """
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")

        if not entity_value:
            return EnrichmentResult(
                entity=entity,
                results=[],
                success=False,
                error="No value provided in entity",
            )

        logger.info(
            "Starting enrichment",
            entity_type=entity_type,
            entity_value=entity_value[:50],
        )

        # Get plugins to use
        plugin_names = plugins or self._get_plugins_for_type(entity_type)

        if not plugin_names:
            return EnrichmentResult(
                entity=entity,
                results=[],
                success=False,
                error=f"No plugins available for entity type: {entity_type}",
            )

        # Run all plugins concurrently
        tasks = [
            self._run_plugin(plugin_name, entity)
            for plugin_name in plugin_names
        ]
        plugin_results = await asyncio.gather(*tasks)

        # Filter out None results
        results = [r for r in plugin_results if r is not None]

        # Calculate threat assessment
        confidence, is_malicious, threat_level = self._calculate_threat_assessment(results)

        logger.info(
            "Enrichment complete",
            entity=entity_value[:50],
            plugins_run=len(results),
            findings=sum(len(r.findings) for r in results),
            is_malicious=is_malicious,
            threat_level=threat_level,
        )

        return EnrichmentResult(
            entity=entity,
            results=results,
            success=True,
            confidence_score=confidence,
            is_malicious=is_malicious,
            threat_level=threat_level,
        )

    async def enrich_batch(
        self,
        entities: list[dict[str, Any]],
    ) -> list[EnrichmentResult]:
        """
        Enrich multiple entities.

        Args:
            entities: List of entity dicts

        Returns:
            List of EnrichmentResults
        """
        tasks = [self.enrich(entity) for entity in entities]
        return await asyncio.gather(*tasks)
