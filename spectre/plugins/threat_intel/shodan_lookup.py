"""
Shodan Threat Intelligence Plugin

Queries Shodan API for internet-wide device and service exposure data.
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


class ShodanPlugin(SpectrePlugin):
    """
    Shodan Threat Intelligence Plugin.

    Queries the Shodan API for:
    - IP address information (ports, services, vulnerabilities)
    - Domain DNS information
    - Host search capabilities

    Requires a Shodan API key (free tier available).
    """

    name = "shodan_lookup"
    description = "Query Shodan for internet-wide device and service exposure"
    category = PluginCategory.THREAT_INTEL
    input_types = [EntityType.IP_ADDRESS, EntityType.DOMAIN]
    output_types = [EntityType.IP_ADDRESS, EntityType.VULNERABILITY, EntityType.DOMAIN]
    required_config: list[str] = ["api_key"]
    rate_limit = RateLimit(
        requests_per_minute=60,  # Free tier allows 1 request/second
        concurrent_requests=1,
    )

    # API endpoint
    SHODAN_API_BASE = "https://api.shodan.io"

    def __init__(self) -> None:
        """Initialize the Shodan plugin."""
        super().__init__()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, config: PluginConfig | None = None) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            timeout = config.timeout_seconds if config else 30
            self._client = httpx.AsyncClient(
                timeout=timeout,
                headers={
                    "Accept": "application/json",
                },
            )
        return self._client

    async def _query_host(
        self,
        ip: str,
        api_key: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query Shodan for IP host information."""
        try:
            response = await client.get(
                f"{self.SHODAN_API_BASE}/shodan/host/{ip}",
                params={"key": api_key},
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug("IP not found in Shodan", ip=ip)
            else:
                logger.warning(
                    "Shodan host query failed",
                    ip=ip,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error("Shodan host query error", ip=ip, error=str(e))
        return None

    async def _query_dns(
        self,
        domain: str,
        api_key: str,
        client: httpx.AsyncClient,
    ) -> dict[str, Any] | None:
        """Query Shodan DNS for domain information."""
        try:
            response = await client.get(
                f"{self.SHODAN_API_BASE}/dns/domain/{domain}",
                params={"key": api_key},
            )
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.debug("Domain not found in Shodan", domain=domain)
            else:
                logger.warning(
                    "Shodan DNS query failed",
                    domain=domain,
                    status=response.status_code,
                )
        except Exception as e:
            logger.error("Shodan DNS query error", domain=domain, error=str(e))
        return None

    async def _resolve_domain(
        self,
        domain: str,
        api_key: str,
        client: httpx.AsyncClient,
    ) -> list[str]:
        """Resolve domain to IP addresses using Shodan."""
        try:
            response = await client.get(
                f"{self.SHODAN_API_BASE}/dns/resolve",
                params={"hostnames": domain, "key": api_key},
            )
            if response.status_code == 200:
                data = response.json()
                return [data.get(domain)] if data.get(domain) else []
        except Exception as e:
            logger.warning("Shodan DNS resolve failed", domain=domain, error=str(e))
        return []

    def _parse_host_response(
        self,
        data: dict[str, Any],
        result: PluginResult,
    ) -> None:
        """Parse Shodan host response and add findings."""
        # Extract basic info
        ip = data.get("ip_str")
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])

        # Add main host finding
        result.add_finding(
            finding_type="shodan_host",
            data={
                "ip": ip,
                "organization": data.get("org"),
                "asn": data.get("asn"),
                "isp": data.get("isp"),
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "city": data.get("city"),
                "region": data.get("region_code"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "os": data.get("os"),
                "ports": ports,
                "hostnames": hostnames,
                "last_update": data.get("last_update"),
            },
            confidence=1.0,
        )

        # Add port/service findings
        services = data.get("data", [])
        for service in services[:15]:  # Limit to 15 services
            port = service.get("port")
            transport = service.get("transport", "tcp")

            service_finding = {
                "port": port,
                "transport": transport,
                "protocol": service.get("_shodan", {}).get("module"),
                "product": service.get("product"),
                "version": service.get("version"),
                "banner": service.get("data", "")[:500] if service.get("data") else None,
                "ssl": bool(service.get("ssl")),
                "http": service.get("http", {}),
            }

            # Extract HTTP info if available
            http_info = service.get("http", {})
            if http_info:
                service_finding["http_title"] = http_info.get("title")
                service_finding["http_server"] = http_info.get("server")
                service_finding["http_status"] = http_info.get("status")

            result.add_finding(
                finding_type="shodan_service",
                data=service_finding,
                confidence=1.0,
            )

        # Add vulnerabilities
        if vulns:
            result.add_finding(
                finding_type="shodan_vulnerabilities",
                data={
                    "ip": ip,
                    "vulnerability_count": len(vulns),
                    "cves": vulns[:20],  # Limit to 20
                },
                confidence=0.9,
            )

            # Add each CVE as discovered entity
            for cve in vulns[:20]:
                result.add_entity(
                    EntityType.VULNERABILITY,
                    {
                        "value": cve,
                        "source": "shodan",
                        "affected_ip": ip,
                    },
                )

        # Add discovered hostnames as entities
        for hostname in hostnames[:10]:
            result.add_entity(
                EntityType.DOMAIN,
                {
                    "value": hostname,
                    "source": "shodan",
                    "resolves_to": ip,
                    "relationship": "hosted_on",
                },
            )

        # Assess exposure risk
        risk_factors = []
        risk_score = 0

        if vulns:
            risk_factors.append(f"{len(vulns)} known vulnerabilities")
            risk_score += min(len(vulns) * 10, 40)

        # Check for dangerous ports
        dangerous_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
        exposed_dangerous = set(ports) & dangerous_ports
        if exposed_dangerous:
            risk_factors.append(f"Dangerous ports exposed: {exposed_dangerous}")
            risk_score += len(exposed_dangerous) * 10

        if len(ports) > 20:
            risk_factors.append(f"High number of open ports ({len(ports)})")
            risk_score += 15

        risk_level = "low"
        if risk_score >= 50:
            risk_level = "critical"
        elif risk_score >= 30:
            risk_level = "high"
        elif risk_score >= 15:
            risk_level = "medium"

        result.add_finding(
            finding_type="shodan_risk_assessment",
            data={
                "ip": ip,
                "risk_level": risk_level,
                "risk_score": min(risk_score, 100),
                "risk_factors": risk_factors,
                "total_ports": len(ports),
                "total_vulns": len(vulns),
            },
            confidence=0.85,
        )

    def _parse_dns_response(
        self,
        data: dict[str, Any],
        domain: str,
        result: PluginResult,
    ) -> None:
        """Parse Shodan DNS response and add findings."""
        subdomains = data.get("subdomains", [])
        records = data.get("data", [])

        result.add_finding(
            finding_type="shodan_dns",
            data={
                "domain": domain,
                "subdomain_count": len(subdomains),
                "subdomains": subdomains[:50],
                "record_count": len(records),
            },
            confidence=1.0,
        )

        # Add DNS records
        for record in records[:20]:
            result.add_finding(
                finding_type="shodan_dns_record",
                data={
                    "subdomain": record.get("subdomain"),
                    "type": record.get("type"),
                    "value": record.get("value"),
                    "last_seen": record.get("last_seen"),
                },
                confidence=1.0,
            )

        # Add subdomains as discovered entities
        for subdomain in subdomains[:30]:
            full_domain = f"{subdomain}.{domain}" if subdomain else domain
            result.add_entity(
                EntityType.DOMAIN,
                {
                    "value": full_domain,
                    "source": "shodan_dns",
                    "parent_domain": domain,
                    "relationship": "subdomain_of",
                },
            )

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute Shodan lookup for an entity.

        Args:
            entity: Dict with 'type' and 'value' keys
            config: Plugin configuration (must include api_key)

        Returns:
            PluginResult with Shodan exposure findings
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
                error="Shodan API key not configured",
            )

        logger.info(
            "Starting Shodan lookup",
            entity_type=entity_type,
            entity_value=entity_value,
        )

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        client = await self._get_client(config)

        if entity_type == "ip_address":
            # Query host information
            host_data = await self._query_host(entity_value, api_key, client)
            if host_data:
                self._parse_host_response(host_data, result)

        elif entity_type == "domain":
            # Query DNS information
            dns_data = await self._query_dns(entity_value, api_key, client)
            if dns_data:
                self._parse_dns_response(dns_data, entity_value, result)

            # Also resolve domain and query the IP
            ips = await self._resolve_domain(entity_value, api_key, client)
            for ip in ips[:3]:  # Limit to first 3 IPs
                host_data = await self._query_host(ip, api_key, client)
                if host_data:
                    self._parse_host_response(host_data, result)

        # Add summary if no findings
        if len(result.findings) == 0:
            result.add_finding(
                finding_type="shodan_not_found",
                data={
                    "entity": entity_value,
                    "entity_type": entity_type,
                    "message": "No data found in Shodan",
                },
                confidence=0.5,
            )

        logger.info(
            "Shodan lookup complete",
            entity=entity_value,
            findings=len(result.findings),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify Shodan API is accessible.

        Note: Returns True since we can't test without an API key.
        """
        return True
