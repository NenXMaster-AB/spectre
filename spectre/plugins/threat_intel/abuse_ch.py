"""
Abuse.ch Threat Intelligence Plugin

Queries Abuse.ch APIs for threat intelligence:
- URLhaus: Malware URLs
- ThreatFox: IOCs (IPs, domains, hashes)
- MalwareBazaar: Malware samples
"""

from datetime import datetime
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


class AbuseChPlugin(SpectrePlugin):
    """
    Abuse.ch Threat Intelligence Plugin.

    Queries multiple Abuse.ch APIs:
    - URLhaus: Database of malware URLs
    - ThreatFox: IOC database (domains, IPs, hashes)
    - MalwareBazaar: Malware sample database

    All APIs are free and require no API key.
    """

    name = "abuse_ch"
    description = "Query Abuse.ch threat feeds (URLhaus, ThreatFox, MalwareBazaar)"
    category = PluginCategory.THREAT_INTEL
    input_types = [EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.HASH, EntityType.URL]
    output_types = [EntityType.HASH, EntityType.URL, EntityType.MALWARE]
    required_config: list[str] = []
    rate_limit = RateLimit(requests_per_minute=30, concurrent_requests=3)

    # API endpoints
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
    THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1"
    MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1"

    def __init__(self) -> None:
        """Initialize the Abuse.ch plugin."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, config: PluginConfig | None = None) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            timeout = config.timeout_seconds if config else 30
            self._client = httpx.AsyncClient(
                timeout=timeout,
                headers={
                    "User-Agent": "SPECTRE-OSINT/0.1.0",
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _query_urlhaus_host(
        self,
        host: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query URLhaus for a host (domain or IP)."""
        try:
            response = await client.post(
                f"{self.URLHAUS_API}/host/",
                data={"host": host},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data
        except Exception as e:
            logger.warning("URLhaus query failed", host=host, error=str(e))
        return None

    async def _query_urlhaus_url(
        self,
        url: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query URLhaus for a specific URL."""
        try:
            response = await client.post(
                f"{self.URLHAUS_API}/url/",
                data={"url": url},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data
        except Exception as e:
            logger.warning("URLhaus URL query failed", url=url, error=str(e))
        return None

    async def _query_threatfox(
        self,
        ioc: str,
        ioc_type: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query ThreatFox for an IOC."""
        try:
            response = await client.post(
                self.THREATFOX_API,
                json={
                    "query": "search_ioc",
                    "search_term": ioc,
                },
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data
        except Exception as e:
            logger.warning("ThreatFox query failed", ioc=ioc, error=str(e))
        return None

    async def _query_malwarebazaar(
        self,
        hash_value: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query MalwareBazaar for a hash."""
        try:
            response = await client.post(
                self.MALWAREBAZAAR_API,
                data={
                    "query": "get_info",
                    "hash": hash_value,
                },
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data
        except Exception as e:
            logger.warning("MalwareBazaar query failed", hash=hash_value, error=str(e))
        return None

    def _parse_urlhaus_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse URLhaus response and add findings."""
        urls = data.get("urls", [])

        if not urls:
            return

        # Add summary
        result.add_finding(
            finding_type="urlhaus_summary",
            data={
                "host": data.get("host"),
                "url_count": data.get("url_count", len(urls)),
                "first_seen": data.get("firstseen"),
                "blacklists": data.get("blacklists", {}),
            },
            confidence=1.0,
        )

        # Add individual malicious URLs (limit to 20)
        for url_entry in urls[:20]:
            result.add_finding(
                finding_type="malicious_url",
                data={
                    "url": url_entry.get("url"),
                    "url_status": url_entry.get("url_status"),
                    "threat": url_entry.get("threat"),
                    "tags": url_entry.get("tags", []),
                    "date_added": url_entry.get("date_added"),
                    "reporter": url_entry.get("reporter"),
                },
                confidence=0.95,
            )

            # Add URL as discovered entity
            if url_entry.get("url"):
                result.add_entity(
                    EntityType.URL,
                    {
                        "value": url_entry["url"],
                        "is_malicious": True,
                        "threat_type": url_entry.get("threat"),
                        "source": "urlhaus",
                    },
                )

    def _parse_threatfox_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse ThreatFox response and add findings."""
        iocs = data.get("data", [])

        if not iocs:
            return

        for ioc in iocs[:20]:
            result.add_finding(
                finding_type="threatfox_ioc",
                data={
                    "ioc": ioc.get("ioc"),
                    "ioc_type": ioc.get("ioc_type"),
                    "threat_type": ioc.get("threat_type"),
                    "malware": ioc.get("malware"),
                    "malware_alias": ioc.get("malware_alias"),
                    "malware_printable": ioc.get("malware_printable"),
                    "confidence_level": ioc.get("confidence_level"),
                    "first_seen": ioc.get("first_seen_utc"),
                    "last_seen": ioc.get("last_seen_utc"),
                    "tags": ioc.get("tags", []),
                    "reference": ioc.get("reference"),
                },
                confidence=ioc.get("confidence_level", 75) / 100,
            )

            # Add malware entity if identified
            malware_name = ioc.get("malware_printable") or ioc.get("malware")
            if malware_name:
                result.add_entity(
                    EntityType.MALWARE,
                    {
                        "value": malware_name,
                        "aliases": ioc.get("malware_alias", "").split(",") if ioc.get("malware_alias") else [],
                        "source": "threatfox",
                    },
                )

    def _parse_malwarebazaar_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse MalwareBazaar response and add findings."""
        samples = data.get("data", [])

        if not samples:
            return

        for sample in samples[:10]:
            result.add_finding(
                finding_type="malware_sample",
                data={
                    "sha256": sample.get("sha256_hash"),
                    "sha1": sample.get("sha1_hash"),
                    "md5": sample.get("md5_hash"),
                    "file_name": sample.get("file_name"),
                    "file_type": sample.get("file_type"),
                    "file_size": sample.get("file_size"),
                    "signature": sample.get("signature"),
                    "first_seen": sample.get("first_seen"),
                    "intelligence": sample.get("intelligence", {}),
                    "tags": sample.get("tags", []),
                    "delivery_method": sample.get("delivery_method"),
                },
                confidence=0.95,
            )

            # Add hash entities
            for hash_type in ["sha256_hash", "sha1_hash", "md5_hash"]:
                if sample.get(hash_type):
                    result.add_entity(
                        EntityType.HASH,
                        {
                            "value": sample[hash_type],
                            "hash_type": hash_type.replace("_hash", ""),
                            "is_malicious": True,
                            "malware_family": sample.get("signature"),
                            "source": "malwarebazaar",
                        },
                    )

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute Abuse.ch lookup for an entity.

        Args:
            entity: Dict with 'type' and 'value' keys
            config: Optional plugin configuration

        Returns:
            PluginResult with threat intelligence findings
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

        logger.info(
            "Starting Abuse.ch lookup",
            entity_type=entity_type,
            entity_value=entity_value,
        )

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(config)
        is_malicious = False

        # Query based on entity type
        if entity_type in ("domain", "ip_address"):
            # Query URLhaus for host
            urlhaus_data = await self._query_urlhaus_host(entity_value, client)
            if urlhaus_data:
                self._parse_urlhaus_response(urlhaus_data, result)
                is_malicious = True

            # Query ThreatFox
            threatfox_data = await self._query_threatfox(entity_value, entity_type, client)
            if threatfox_data and threatfox_data.get("data"):
                self._parse_threatfox_response(threatfox_data, result)
                is_malicious = True

        elif entity_type == "hash":
            # Query MalwareBazaar for hash
            malwarebazaar_data = await self._query_malwarebazaar(entity_value, client)
            if malwarebazaar_data and malwarebazaar_data.get("data"):
                self._parse_malwarebazaar_response(malwarebazaar_data, result)
                is_malicious = True

            # Also query ThreatFox
            threatfox_data = await self._query_threatfox(entity_value, "hash", client)
            if threatfox_data and threatfox_data.get("data"):
                self._parse_threatfox_response(threatfox_data, result)
                is_malicious = True

        elif entity_type == "url":
            # Query URLhaus for URL
            urlhaus_data = await self._query_urlhaus_url(entity_value, client)
            if urlhaus_data:
                result.add_finding(
                    finding_type="urlhaus_url",
                    data={
                        "url": entity_value,
                        "url_status": urlhaus_data.get("url_status"),
                        "threat": urlhaus_data.get("threat"),
                        "host": urlhaus_data.get("host"),
                        "date_added": urlhaus_data.get("date_added"),
                        "blacklists": urlhaus_data.get("blacklists", {}),
                        "payloads": urlhaus_data.get("payloads", [])[:5],
                    },
                    confidence=0.95,
                )
                is_malicious = True

        # Add overall threat assessment
        result.add_finding(
            finding_type="abuse_ch_assessment",
            data={
                "entity": entity_value,
                "entity_type": entity_type,
                "is_malicious": is_malicious,
                "sources_checked": ["urlhaus", "threatfox", "malwarebazaar"],
                "findings_count": len(result.findings) - 1,  # Exclude this finding
            },
            confidence=1.0 if is_malicious else 0.5,
        )

        logger.info(
            "Abuse.ch lookup complete",
            entity=entity_value,
            is_malicious=is_malicious,
            findings=len(result.findings),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify Abuse.ch APIs are accessible.
        """
        try:
            client = await self._get_client()
            # Test URLhaus API
            response = await client.post(
                f"{self.URLHAUS_API}/host/",
                data={"host": "example.com"},
            )
            return response.status_code == 200
        except Exception as e:
            logger.error("Abuse.ch health check failed", error=str(e))
            return False
