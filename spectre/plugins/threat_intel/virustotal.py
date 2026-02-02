"""
VirusTotal Threat Intelligence Plugin

Queries VirusTotal API for multi-engine scanning results
on domains, IPs, URLs, and file hashes.
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


class VirusTotalPlugin(SpectrePlugin):
    """
    VirusTotal Threat Intelligence Plugin.

    Queries the VirusTotal API v3 for:
    - Domain reputation and analysis
    - IP address reputation
    - URL scanning results
    - File hash analysis

    Requires a VirusTotal API key (free tier available).
    """

    name = "virustotal"
    description = "Query VirusTotal for multi-engine reputation and analysis"
    category = PluginCategory.THREAT_INTEL
    input_types = [EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.HASH, EntityType.URL]
    output_types = [EntityType.HASH, EntityType.DOMAIN, EntityType.IP_ADDRESS]
    required_config: list[str] = ["api_key"]
    rate_limit = RateLimit(
        requests_per_minute=4,  # Free tier: 4 requests/minute
        requests_per_day=500,   # Free tier: 500 requests/day
        concurrent_requests=1,
    )

    # API endpoint
    VT_API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        """Initialize the VirusTotal plugin."""
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
                    "x-apikey": api_key,
                    "Accept": "application/json",
                },
            )
        return self._client

    def _calculate_verdict(self, stats: dict[str, int]) -> tuple[str, float]:
        """
        Calculate verdict and confidence from analysis stats.

        Returns:
            Tuple of (verdict, confidence)
        """
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected
        if total == 0:
            return "unknown", 0.0

        # Calculate detection ratio
        detection_ratio = (malicious + suspicious) / total

        if malicious >= 5 or detection_ratio >= 0.1:
            verdict = "malicious"
            confidence = min(0.5 + (malicious / 20), 1.0)
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
            confidence = 0.6
        elif harmless > undetected:
            verdict = "clean"
            confidence = min(0.5 + (harmless / total), 0.95)
        else:
            verdict = "undetected"
            confidence = 0.5

        return verdict, confidence

    async def _query_domain(
        self,
        domain: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query VirusTotal for domain information."""
        try:
            response = await client.get(f"{self.VT_API_BASE}/domains/{domain}")
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug("Domain not found in VirusTotal", domain=domain)
            else:
                logger.warning(
                    "VirusTotal domain query failed",
                    domain=domain,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error("VirusTotal domain query error", domain=domain, error=str(e))
        return None

    async def _query_ip(
        self,
        ip: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query VirusTotal for IP information."""
        try:
            response = await client.get(f"{self.VT_API_BASE}/ip_addresses/{ip}")
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug("IP not found in VirusTotal", ip=ip)
            else:
                logger.warning(
                    "VirusTotal IP query failed",
                    ip=ip,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error("VirusTotal IP query error", ip=ip, error=str(e))
        return None

    async def _query_file(
        self,
        file_hash: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query VirusTotal for file hash information."""
        try:
            response = await client.get(f"{self.VT_API_BASE}/files/{file_hash}")
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug("Hash not found in VirusTotal", hash=file_hash)
            else:
                logger.warning(
                    "VirusTotal file query failed",
                    hash=file_hash,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error("VirusTotal file query error", hash=file_hash, error=str(e))
        return None

    def _parse_domain_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse domain response and add findings."""
        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        verdict, confidence = self._calculate_verdict(stats)

        result.add_finding(
            finding_type="virustotal_domain",
            data={
                "domain": data.get("data", {}).get("id"),
                "verdict": verdict,
                "analysis_stats": stats,
                "reputation": attributes.get("reputation", 0),
                "registrar": attributes.get("registrar"),
                "creation_date": attributes.get("creation_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "categories": attributes.get("categories", {}),
                "popularity_ranks": attributes.get("popularity_ranks", {}),
                "last_dns_records": attributes.get("last_dns_records", [])[:5],
            },
            confidence=confidence,
        )

        # Add detected URLs if malicious
        if verdict in ("malicious", "suspicious"):
            result.add_finding(
                finding_type="virustotal_threat_assessment",
                data={
                    "entity_type": "domain",
                    "is_malicious": verdict == "malicious",
                    "is_suspicious": verdict == "suspicious",
                    "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "reputation_score": attributes.get("reputation", 0),
                },
                confidence=confidence,
            )

    def _parse_ip_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse IP response and add findings."""
        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        verdict, confidence = self._calculate_verdict(stats)

        result.add_finding(
            finding_type="virustotal_ip",
            data={
                "ip": data.get("data", {}).get("id"),
                "verdict": verdict,
                "analysis_stats": stats,
                "reputation": attributes.get("reputation", 0),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "country": attributes.get("country"),
                "continent": attributes.get("continent"),
                "network": attributes.get("network"),
                "last_analysis_date": attributes.get("last_analysis_date"),
            },
            confidence=confidence,
        )

        if verdict in ("malicious", "suspicious"):
            result.add_finding(
                finding_type="virustotal_threat_assessment",
                data={
                    "entity_type": "ip_address",
                    "is_malicious": verdict == "malicious",
                    "is_suspicious": verdict == "suspicious",
                    "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "reputation_score": attributes.get("reputation", 0),
                },
                confidence=confidence,
            )

    def _parse_file_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse file hash response and add findings."""
        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        verdict, confidence = self._calculate_verdict(stats)

        # Get signature info
        signature_info = attributes.get("signature_info", {})
        names = attributes.get("names", [])

        result.add_finding(
            finding_type="virustotal_file",
            data={
                "sha256": attributes.get("sha256"),
                "sha1": attributes.get("sha1"),
                "md5": attributes.get("md5"),
                "verdict": verdict,
                "analysis_stats": stats,
                "file_type": attributes.get("type_description"),
                "file_size": attributes.get("size"),
                "names": names[:10],
                "meaningful_name": attributes.get("meaningful_name"),
                "signature": signature_info.get("product") or signature_info.get("description"),
                "magic": attributes.get("magic"),
                "first_submission_date": attributes.get("first_submission_date"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "times_submitted": attributes.get("times_submitted"),
                "popular_threat_classification": attributes.get("popular_threat_classification", {}),
                "tags": attributes.get("tags", []),
            },
            confidence=confidence,
        )

        # Add threat classification if available
        threat_class = attributes.get("popular_threat_classification", {})
        if threat_class:
            suggested_label = threat_class.get("suggested_threat_label")
            if suggested_label:
                result.add_entity(
                    EntityType.MALWARE,
                    {
                        "value": suggested_label,
                        "source": "virustotal",
                        "confidence": confidence,
                    },
                )

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute VirusTotal lookup for an entity.

        Args:
            entity: Dict with 'type' and 'value' keys
            config: Plugin configuration (must include api_key)

        Returns:
            PluginResult with VirusTotal analysis findings
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
                error="VirusTotal API key not configured",
            )

        logger.info(
            "Starting VirusTotal lookup",
            entity_type=entity_type,
            entity_value=entity_value[:50],
        )

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(api_key, config)

        # Query based on entity type
        if entity_type == "domain":
            vt_data = await self._query_domain(entity_value, client)
            if vt_data:
                self._parse_domain_response(vt_data, result)

        elif entity_type == "ip_address":
            vt_data = await self._query_ip(entity_value, client)
            if vt_data:
                self._parse_ip_response(vt_data, result)

        elif entity_type == "hash":
            vt_data = await self._query_file(entity_value, client)
            if vt_data:
                self._parse_file_response(vt_data, result)

        elif entity_type == "url":
            # For URLs, we'd need to submit for scanning or query by URL ID
            # This is more complex - for now, return not supported
            result.add_finding(
                finding_type="virustotal_notice",
                data={
                    "message": "URL scanning requires submission and waiting for results",
                    "entity": entity_value,
                },
                confidence=0.5,
            )

        # Add summary if no findings
        if len(result.findings) == 0:
            result.add_finding(
                finding_type="virustotal_not_found",
                data={
                    "entity": entity_value,
                    "entity_type": entity_type,
                    "message": "No data found in VirusTotal",
                },
                confidence=0.5,
            )

        logger.info(
            "VirusTotal lookup complete",
            entity=entity_value[:50],
            findings=len(result.findings),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify VirusTotal API is accessible.

        Note: This always returns True since we can't test without an API key.
        Actual API access is verified during execute().
        """
        # We can't really health check without an API key
        # Return True and let execute() handle the error
        return True
