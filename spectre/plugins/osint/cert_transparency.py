"""
Certificate Transparency Plugin

Queries Certificate Transparency logs to find certificates
issued for a domain, including historical certificates.
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


class CertTransparencyPlugin(SpectrePlugin):
    """
    Certificate Transparency Plugin.

    Queries crt.sh to find:
    - All certificates issued for a domain
    - Certificate details (issuer, validity, SANs)
    - Historical certificate data
    """

    name = "cert_transparency"
    description = "Query Certificate Transparency logs for domain certificates and SANs"
    category = PluginCategory.OSINT
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.DOMAIN, EntityType.CERTIFICATE]
    required_config: list[str] = []
    rate_limit = RateLimit(requests_per_minute=20, concurrent_requests=2)

    # crt.sh API endpoint
    CRT_SH_URL = "https://crt.sh/"

    def __init__(self) -> None:
        """Initialize the Certificate Transparency plugin."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, config: PluginConfig | None = None) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            timeout = config.timeout_seconds if config else 45
            self._client = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "SPECTRE-OSINT/0.1.0",
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _query_certificates(
        self,
        domain: str,
        client: httpx.AsyncClient,
    ) -> list[dict[str, Any]]:
        """
        Query crt.sh for certificates.

        Returns list of certificate entries.
        """
        certificates: list[dict[str, Any]] = []

        try:
            # Query crt.sh JSON API
            response = await client.get(
                self.CRT_SH_URL,
                params={
                    "q": domain,
                    "output": "json",
                },
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        cert = {
                            "id": entry.get("id"),
                            "issuer_name": entry.get("issuer_name"),
                            "issuer_ca_id": entry.get("issuer_ca_id"),
                            "common_name": entry.get("common_name"),
                            "name_value": entry.get("name_value", ""),
                            "not_before": entry.get("not_before"),
                            "not_after": entry.get("not_after"),
                            "serial_number": entry.get("serial_number"),
                            "entry_timestamp": entry.get("entry_timestamp"),
                        }
                        certificates.append(cert)
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

        return certificates

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse a date string from crt.sh."""
        if not date_str:
            return None
        try:
            # crt.sh returns dates like "2024-01-15T00:00:00"
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _extract_sans(self, name_value: str) -> list[str]:
        """Extract Subject Alternative Names from name_value field."""
        if not name_value:
            return []
        # name_value contains newline-separated names
        sans = []
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*"):
                sans.append(name)
        return sorted(set(sans))

    def _analyze_certificate(self, cert: dict[str, Any], domain: str) -> dict[str, Any]:
        """Analyze a certificate and extract useful information."""
        not_before = self._parse_date(cert.get("not_before"))
        not_after = self._parse_date(cert.get("not_after"))

        now = datetime.now()
        is_valid = False
        is_expired = False
        days_until_expiry = None

        if not_before and not_after:
            # Make datetime objects naive for comparison if needed
            if not_before.tzinfo:
                now = datetime.now(not_before.tzinfo)

            is_valid = not_before <= now <= not_after
            is_expired = now > not_after

            if not is_expired:
                days_until_expiry = (not_after - now).days

        sans = self._extract_sans(cert.get("name_value", ""))

        return {
            "cert_id": cert.get("id"),
            "common_name": cert.get("common_name"),
            "issuer": cert.get("issuer_name"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "is_valid": is_valid,
            "is_expired": is_expired,
            "days_until_expiry": days_until_expiry,
            "san_count": len(sans),
            "sans": sans[:20],  # Limit to first 20 SANs
            "serial_number": cert.get("serial_number"),
        }

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute Certificate Transparency lookup for a domain.

        Args:
            entity: Dict with 'type' and 'value' keys (domain name)
            config: Optional plugin configuration

        Returns:
            PluginResult with certificate data
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

        logger.info("Starting Certificate Transparency lookup", domain=domain)

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(config)

        # Query certificates
        raw_certificates = await self._query_certificates(domain, client)

        # Deduplicate by certificate ID
        seen_ids: set[int] = set()
        unique_certs: list[dict[str, Any]] = []
        for cert in raw_certificates:
            cert_id = cert.get("id")
            if cert_id and cert_id not in seen_ids:
                seen_ids.add(cert_id)
                unique_certs.append(cert)

        # Analyze certificates
        analyzed_certs = [self._analyze_certificate(c, domain) for c in unique_certs]

        # Collect unique issuers
        issuers: set[str] = set()
        all_sans: set[str] = set()
        valid_count = 0
        expired_count = 0

        for cert in analyzed_certs:
            if cert.get("issuer"):
                issuers.add(cert["issuer"])
            if cert.get("is_valid"):
                valid_count += 1
            if cert.get("is_expired"):
                expired_count += 1
            for san in cert.get("sans", []):
                all_sans.add(san)

        # Remove the queried domain from SANs
        all_sans.discard(domain)

        # Add summary finding
        result.add_finding(
            finding_type="cert_transparency_summary",
            data={
                "domain": domain,
                "total_certificates": len(analyzed_certs),
                "valid_certificates": valid_count,
                "expired_certificates": expired_count,
                "unique_issuers": sorted(issuers),
                "unique_sans": len(all_sans),
            },
            confidence=1.0,
        )

        # Add findings for recent/valid certificates (limit to 10)
        valid_certs = [c for c in analyzed_certs if c.get("is_valid")]
        for cert in valid_certs[:10]:
            result.add_finding(
                finding_type="certificate",
                data=cert,
                confidence=1.0,
            )

        # Add discovered domains from SANs
        for san in sorted(all_sans):
            # Only add if it's related to the domain
            if domain in san or san.endswith(f".{domain}"):
                result.add_entity(
                    EntityType.DOMAIN,
                    {
                        "value": san,
                        "source": f"cert_transparency:{domain}",
                        "discovered_via": "certificate_san",
                        "relationship": "san_of",
                    },
                )

        logger.info(
            "Certificate Transparency lookup complete",
            domain=domain,
            certificates_found=len(analyzed_certs),
            sans_discovered=len(all_sans),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify crt.sh is accessible.
        """
        try:
            client = await self._get_client()
            response = await client.get(
                self.CRT_SH_URL,
                params={"q": "example.com", "output": "json"},
            )
            return response.status_code == 200
        except Exception as e:
            logger.error("Cert Transparency health check failed", error=str(e))
            return False
