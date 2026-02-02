"""
Subdomain Enumeration Plugin

Discovers subdomains using Certificate Transparency logs (crt.sh)
and other passive sources.
"""

import asyncio
import re
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


class SubdomainEnumPlugin(SpectrePlugin):
    """
    Subdomain Enumeration Plugin.

    Discovers subdomains using:
    - Certificate Transparency logs (crt.sh)
    - Future: DNS brute forcing, passive DNS, etc.
    """

    name = "subdomain_enum"
    description = "Enumerate subdomains via Certificate Transparency logs and passive sources"
    category = PluginCategory.OSINT
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.DOMAIN]
    required_config: list[str] = []
    rate_limit = RateLimit(requests_per_minute=30, concurrent_requests=3)

    # crt.sh API endpoint
    CRT_SH_URL = "https://crt.sh/"

    def __init__(self) -> None:
        """Initialize the subdomain enumeration plugin."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, config: PluginConfig | None = None) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            timeout = config.timeout_seconds if config else 30
            self._client = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "SPECTRE-OSINT/0.1.0",
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _query_crt_sh(self, domain: str, client: httpx.AsyncClient) -> list[str]:
        """
        Query crt.sh Certificate Transparency logs.

        Returns list of discovered subdomains.
        """
        subdomains: set[str] = set()

        try:
            # Query crt.sh JSON API
            response = await client.get(
                self.CRT_SH_URL,
                params={
                    "q": f"%.{domain}",
                    "output": "json",
                },
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        # Split by newlines (crt.sh can return multiple names per cert)
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Filter wildcards and validate domain
                            if name and not name.startswith("*") and domain in name:
                                # Validate it's a proper subdomain
                                if self._is_valid_subdomain(name, domain):
                                    subdomains.add(name)
                except Exception as e:
                    logger.warning("Failed to parse crt.sh JSON", error=str(e))

            elif response.status_code == 429:
                logger.warning("crt.sh rate limited")

            else:
                logger.warning(
                    "crt.sh returned non-200",
                    status=response.status_code,
                )

        except httpx.TimeoutException:
            logger.warning("crt.sh request timed out")
        except Exception as e:
            logger.error("crt.sh query failed", error=str(e))

        return sorted(subdomains)

    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Validate that a string is a valid subdomain of the parent domain."""
        # Must end with parent domain
        if not subdomain.endswith(f".{parent_domain}") and subdomain != parent_domain:
            return False

        # Basic validation - alphanumeric, hyphens, dots
        pattern = r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$"
        if not re.match(pattern, subdomain):
            return False

        # No consecutive dots or hyphens
        if ".." in subdomain or "--" in subdomain:
            return False

        return True

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute subdomain enumeration for a domain.

        Args:
            entity: Dict with 'type' and 'value' keys (domain name)
            config: Optional plugin configuration

        Returns:
            PluginResult with discovered subdomains
        """
        domain = entity.get("value", "")
        if not domain:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                input_entity=entity,
                error="No domain provided in entity",
            )

        # Normalize domain
        domain = domain.lower().strip().rstrip(".")

        # Extract base domain (remove subdomain if present)
        parts = domain.split(".")
        if len(parts) > 2:
            # Simple extraction - take last two parts
            # Note: This doesn't handle TLDs like co.uk properly
            common_second_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
            if parts[-2] in common_second_level and len(parts) > 2:
                base_domain = ".".join(parts[-3:])
            else:
                base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        logger.info("Starting subdomain enumeration", domain=domain, base_domain=base_domain)

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(config)

        # Query Certificate Transparency
        ct_subdomains = await self._query_crt_sh(base_domain, client)

        # Combine all sources and deduplicate
        all_subdomains = set(ct_subdomains)

        # Remove the base domain itself from results
        all_subdomains.discard(base_domain)

        # Sort for consistent output
        sorted_subdomains = sorted(all_subdomains)

        # Add summary finding
        result.add_finding(
            finding_type="subdomain_summary",
            data={
                "domain": base_domain,
                "total_subdomains": len(sorted_subdomains),
                "sources": {
                    "certificate_transparency": len(ct_subdomains),
                },
            },
            confidence=1.0,
        )

        # Add individual subdomain findings
        for subdomain in sorted_subdomains:
            result.add_finding(
                finding_type="subdomain",
                data={
                    "subdomain": subdomain,
                    "parent_domain": base_domain,
                    "source": "certificate_transparency",
                },
                confidence=0.95,  # CT logs are highly reliable
            )

            # Add as discovered entity
            result.add_entity(
                EntityType.DOMAIN,
                {
                    "value": subdomain,
                    "source": f"subdomain_enum:{base_domain}",
                    "is_subdomain": True,
                    "parent_domain": base_domain,
                    "relationship": "subdomain_of",
                },
            )

        logger.info(
            "Subdomain enumeration complete",
            domain=base_domain,
            subdomains_found=len(sorted_subdomains),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify crt.sh is accessible.

        Tests by making a simple request to crt.sh.
        """
        try:
            client = await self._get_client()
            response = await client.get(
                self.CRT_SH_URL,
                params={"q": "example.com", "output": "json"},
            )
            return response.status_code == 200
        except Exception as e:
            logger.error("Subdomain enum health check failed", error=str(e))
            return False
