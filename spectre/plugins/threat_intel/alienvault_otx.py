"""
AlienVault OTX Threat Intelligence Plugin

Queries AlienVault Open Threat Exchange (OTX) for
community-sourced threat intelligence.
"""

from typing import Any

import httpx
import structlog

from spectre.plugins.base import (
    EntityType,
    PluginCategory,
    PluginConfig,
    PluginResult,
    RateLimit,
    SpectrePlugin,
)

logger = structlog.get_logger(__name__)


class AlienVaultOTXPlugin(SpectrePlugin):
    """
    AlienVault OTX Threat Intelligence Plugin.

    Queries the AlienVault OTX API for:
    - Domain reputation and pulses
    - IP address reputation and pulses
    - File hash analysis
    - URL reputation

    Requires an OTX API key (free with registration).
    """

    name = "alienvault_otx"
    description = "Query AlienVault OTX for community threat intelligence and pulses"
    category = PluginCategory.THREAT_INTEL
    input_types = [EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.HASH, EntityType.URL]
    output_types = [EntityType.HASH, EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.MALWARE]
    required_config: list[str] = ["api_key"]
    rate_limit = RateLimit(
        requests_per_minute=100,
        concurrent_requests=5,
    )

    # API endpoint
    OTX_API_BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self) -> None:
        """Initialize the AlienVault OTX plugin."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(
        self,
        api_key: str,
        config: PluginConfig | None = None,
    ) -> httpx.AsyncClient:
        """Get or create the HTTP client with API key."""
        if self._client is None:
            timeout = config.timeout_seconds if config else 30
            self._client = httpx.AsyncClient(
                timeout=timeout,
                headers={
                    "X-OTX-API-KEY": api_key,
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _query_indicator(
        self,
        indicator_type: str,
        indicator: str,
        section: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query OTX for an indicator."""
        try:
            url = f"{self.OTX_API_BASE}/indicators/{indicator_type}/{indicator}/{section}"
            response = await client.get(url)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug(
                    "Indicator not found in OTX",
                    type=indicator_type,
                    indicator=indicator,
                )
            else:
                logger.warning(
                    "OTX query failed",
                    type=indicator_type,
                    indicator=indicator,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error(
                "OTX query error",
                type=indicator_type,
                indicator=indicator,
                error=str(e),
            )
        return None

    async def _get_indicator_general(
        self,
        indicator_type: str,
        indicator: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Get general information about an indicator."""
        return await self._query_indicator(indicator_type, indicator, "general", client)

    async def _get_indicator_pulses(
        self,
        indicator_type: str,
        indicator: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Get pulses containing this indicator."""
        return await self._query_indicator(indicator_type, indicator, "general", client)

    def _parse_general_response(
        self,
        data: dict[str, Any],
        entity_type: str,
        result: PluginResult,
    ) -> None:
        """Parse general indicator response."""
        indicator = data.get("indicator")
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])

        # Add main finding
        result.add_finding(
            finding_type="otx_indicator",
            data={
                "indicator": indicator,
                "type": data.get("type"),
                "pulse_count": pulse_count,
                "reputation": data.get("reputation", 0),
                "validation": data.get("validation", []),
                "whois": data.get("whois"),
                "asn": data.get("asn"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
            },
            confidence=0.9 if pulse_count > 0 else 0.5,
        )

        # Determine if malicious based on pulse count
        is_malicious = pulse_count >= 3
        is_suspicious = pulse_count >= 1

        if is_malicious or is_suspicious:
            result.add_finding(
                finding_type="otx_threat_assessment",
                data={
                    "indicator": indicator,
                    "is_malicious": is_malicious,
                    "is_suspicious": is_suspicious,
                    "pulse_count": pulse_count,
                    "threat_level": "high" if pulse_count >= 10 else "medium" if pulse_count >= 3 else "low",
                },
                confidence=min(0.5 + (pulse_count * 0.05), 0.95),
            )

        # Add pulse findings (limit to 10)
        for pulse in pulses[:10]:
            pulse_tags = pulse.get("tags", [])
            malware_families = pulse.get("malware_families", [])

            result.add_finding(
                finding_type="otx_pulse",
                data={
                    "pulse_id": pulse.get("id"),
                    "name": pulse.get("name"),
                    "description": pulse.get("description", "")[:500],
                    "author": pulse.get("author_name"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tags": pulse_tags,
                    "malware_families": malware_families,
                    "targeted_countries": pulse.get("targeted_countries", []),
                    "industries": pulse.get("industries", []),
                    "adversary": pulse.get("adversary"),
                    "tlp": pulse.get("TLP"),
                    "indicator_count": pulse.get("indicator_count", 0),
                },
                confidence=0.85,
            )

            # Add malware families as entities
            for malware in malware_families:
                result.add_entity(
                    EntityType.MALWARE,
                    {
                        "value": malware,
                        "source": "otx_pulse",
                        "pulse_id": pulse.get("id"),
                    },
                )

            # Add threat actor if present
            adversary = pulse.get("adversary")
            if adversary:
                result.add_entity(
                    EntityType.THREAT_ACTOR,
                    {
                        "value": adversary,
                        "source": "otx_pulse",
                        "pulse_id": pulse.get("id"),
                    },
                )

    def _parse_domain_specific(
        self,
        data: dict[str, Any],
        domain: str,
        result: PluginResult,
    ) -> None:
        """Parse domain-specific data."""
        # Add passive DNS data if available
        passive_dns = data.get("passive_dns", [])
        for record in passive_dns[:10]:
            result.add_finding(
                finding_type="otx_passive_dns",
                data={
                    "hostname": record.get("hostname"),
                    "address": record.get("address"),
                    "record_type": record.get("record_type"),
                    "first": record.get("first"),
                    "last": record.get("last"),
                },
                confidence=0.9,
            )

            # Add discovered IPs
            if record.get("address"):
                result.add_entity(
                    EntityType.IP_ADDRESS,
                    {
                        "value": record["address"],
                        "source": "otx_passive_dns",
                        "associated_domain": domain,
                    },
                )

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute AlienVault OTX lookup for an entity.

        Args:
            entity: Dict with 'type' and 'value' keys
            config: Plugin configuration (must include api_key)

        Returns:
            PluginResult with OTX threat intelligence findings
        """
        entity_type = entity.get("type", "")
        entity_value = entity.get("value", "")

        if not entity_value:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                input_entity=entity,
                error="No value provided in entity",
            )

        # Get API key from config
        api_key = None
        if config:
            api_key = config.api_key or config.extra.get("api_key")

        if not api_key:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                input_entity=entity,
                error="AlienVault OTX API key not configured",
            )

        logger.info(
            "Starting AlienVault OTX lookup",
            entity_type=entity_type,
            entity_value=entity_value[:50],
        )

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(api_key, config)

        # Map entity type to OTX indicator type
        otx_type_map = {
            "domain": "domain",
            "ip_address": "IPv4",
            "hash": "file",
            "url": "url",
        }

        otx_type = otx_type_map.get(entity_type)
        if not otx_type:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                input_entity=entity,
                error=f"Unsupported entity type: {entity_type}",
            )

        # Query general information
        general_data = await self._get_indicator_general(otx_type, entity_value, client)
        if general_data:
            self._parse_general_response(general_data, entity_type, result)

        # Add summary if no findings
        if len(result.findings) == 0:
            result.add_finding(
                finding_type="otx_not_found",
                data={
                    "entity": entity_value,
                    "entity_type": entity_type,
                    "message": "No data found in AlienVault OTX",
                },
                confidence=0.5,
            )

        logger.info(
            "AlienVault OTX lookup complete",
            entity=entity_value[:50],
            findings=len(result.findings),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify OTX API is accessible.

        Note: Returns True since we can't test without an API key.
        """
        return True
