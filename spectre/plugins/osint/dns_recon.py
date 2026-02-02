"""
DNS Reconnaissance Plugin

Enumerates DNS records for a domain including A, AAAA, MX, NS, TXT, SOA, CNAME.
Uses dnspython for DNS resolution.
"""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
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


class DNSReconPlugin(SpectrePlugin):
    """
    DNS Reconnaissance Plugin.

    Performs comprehensive DNS enumeration for a domain including:
    - A records (IPv4 addresses)
    - AAAA records (IPv6 addresses)
    - MX records (mail servers)
    - NS records (nameservers)
    - TXT records (SPF, DKIM, DMARC, etc.)
    - SOA records (zone authority)
    - CNAME records (aliases)
    """

    name = "dns_recon"
    description = "Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, SOA, CNAME)"
    category = PluginCategory.OSINT
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.IP_ADDRESS, EntityType.DOMAIN]
    required_config: list[str] = []
    rate_limit = RateLimit(requests_per_minute=120, concurrent_requests=10)

    # DNS record types to query
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

    def __init__(self) -> None:
        """Initialize the DNS recon plugin."""
        super().__init__()
        self._resolver: dns.asyncresolver.Resolver | None = None

    def _get_resolver(self, config: PluginConfig | None = None) -> dns.asyncresolver.Resolver:
        """Get or create the async DNS resolver."""
        if self._resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            # Configure resolver
            self._resolver.timeout = config.timeout_seconds if config else 10.0
            self._resolver.lifetime = config.timeout_seconds if config else 30.0
            # Use public DNS servers for reliability
            self._resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        return self._resolver

    async def _query_record(
        self,
        domain: str,
        record_type: str,
        resolver: dns.asyncresolver.Resolver,
    ) -> list[dict[str, Any]]:
        """Query a specific DNS record type."""
        records = []

        try:
            rdtype = dns.rdatatype.from_text(record_type)
            answers = await resolver.resolve(domain, rdtype)

            for rdata in answers:
                record: dict[str, Any] = {
                    "type": record_type,
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                }

                # Parse record-specific data
                if record_type == "A":
                    record["value"] = str(rdata.address)
                    record["ip_version"] = 4

                elif record_type == "AAAA":
                    record["value"] = str(rdata.address)
                    record["ip_version"] = 6

                elif record_type == "MX":
                    record["value"] = str(rdata.exchange).rstrip(".")
                    record["priority"] = rdata.preference

                elif record_type == "NS":
                    record["value"] = str(rdata.target).rstrip(".")

                elif record_type == "TXT":
                    # TXT records can have multiple strings
                    txt_data = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    record["value"] = txt_data

                    # Detect common TXT record types
                    txt_lower = txt_data.lower()
                    if txt_lower.startswith("v=spf1"):
                        record["txt_type"] = "SPF"
                    elif txt_lower.startswith("v=dkim1"):
                        record["txt_type"] = "DKIM"
                    elif txt_lower.startswith("v=dmarc1"):
                        record["txt_type"] = "DMARC"
                    elif "google-site-verification" in txt_lower:
                        record["txt_type"] = "Google Site Verification"
                    elif "ms=" in txt_lower:
                        record["txt_type"] = "Microsoft Verification"
                    elif "docusign" in txt_lower:
                        record["txt_type"] = "DocuSign"
                    else:
                        record["txt_type"] = "Other"

                elif record_type == "SOA":
                    record["value"] = str(rdata.mname).rstrip(".")
                    record["rname"] = str(rdata.rname).rstrip(".")
                    record["serial"] = rdata.serial
                    record["refresh"] = rdata.refresh
                    record["retry"] = rdata.retry
                    record["expire"] = rdata.expire
                    record["minimum"] = rdata.minimum

                elif record_type == "CNAME":
                    record["value"] = str(rdata.target).rstrip(".")

                elif record_type == "CAA":
                    record["value"] = rdata.value.decode("utf-8", errors="replace")
                    record["flags"] = rdata.flags
                    record["tag"] = rdata.tag.decode("utf-8", errors="replace")

                else:
                    record["value"] = str(rdata)

                records.append(record)

        except dns.resolver.NXDOMAIN:
            logger.debug("Domain does not exist", domain=domain, record_type=record_type)
        except dns.resolver.NoAnswer:
            logger.debug("No answer for record type", domain=domain, record_type=record_type)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers available", domain=domain, record_type=record_type)
        except dns.exception.Timeout:
            logger.warning("DNS query timeout", domain=domain, record_type=record_type)
        except Exception as e:
            logger.error(
                "DNS query failed",
                domain=domain,
                record_type=record_type,
                error=str(e),
            )

        return records

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute DNS reconnaissance for a domain.

        Args:
            entity: Dict with 'type' and 'value' keys (domain name)
            config: Optional plugin configuration

        Returns:
            PluginResult with DNS records and discovered IP entities
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

        logger.info("Starting DNS reconnaissance", domain=domain)

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        resolver = self._get_resolver(config)
        all_records: dict[str, list[dict[str, Any]]] = {}
        discovered_ips: set[str] = set()
        discovered_domains: set[str] = set()

        # Query all record types concurrently
        tasks = [
            self._query_record(domain, record_type, resolver)
            for record_type in self.RECORD_TYPES
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for record_type, query_result in zip(self.RECORD_TYPES, results):
            if isinstance(query_result, Exception):
                logger.error(
                    "DNS query exception",
                    domain=domain,
                    record_type=record_type,
                    error=str(query_result),
                )
                continue

            if query_result:
                all_records[record_type] = query_result

                # Extract discovered entities
                for record in query_result:
                    value = record.get("value", "")

                    if record_type in ("A", "AAAA"):
                        discovered_ips.add(value)

                    elif record_type in ("MX", "NS", "CNAME"):
                        if value and value != domain:
                            discovered_domains.add(value)

        # Add findings
        for record_type, records in all_records.items():
            for record in records:
                result.add_finding(
                    finding_type=f"dns_{record_type.lower()}",
                    data=record,
                    confidence=1.0,
                )

        # Add summary finding
        result.add_finding(
            finding_type="dns_summary",
            data={
                "domain": domain,
                "record_counts": {rt: len(recs) for rt, recs in all_records.items()},
                "total_records": sum(len(recs) for recs in all_records.values()),
                "has_spf": any(
                    r.get("txt_type") == "SPF"
                    for r in all_records.get("TXT", [])
                ),
                "has_dmarc": any(
                    r.get("txt_type") == "DMARC"
                    for r in all_records.get("TXT", [])
                ),
                "nameservers": [r["value"] for r in all_records.get("NS", [])],
                "mail_servers": [
                    {"server": r["value"], "priority": r.get("priority")}
                    for r in all_records.get("MX", [])
                ],
            },
            confidence=1.0,
        )

        # Add discovered IP entities
        for ip in discovered_ips:
            result.add_entity(
                EntityType.IP_ADDRESS,
                {
                    "value": ip,
                    "source": f"dns_recon:{domain}",
                    "relationship": "resolves_to",
                },
            )

        # Add discovered domain entities
        for discovered_domain in discovered_domains:
            result.add_entity(
                EntityType.DOMAIN,
                {
                    "value": discovered_domain,
                    "source": f"dns_recon:{domain}",
                    "relationship": "references",
                },
            )

        logger.info(
            "DNS reconnaissance complete",
            domain=domain,
            records_found=sum(len(recs) for recs in all_records.values()),
            ips_discovered=len(discovered_ips),
            domains_discovered=len(discovered_domains),
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify DNS resolution is working.

        Tests by resolving a well-known domain (google.com).
        """
        try:
            resolver = self._get_resolver()
            await resolver.resolve("google.com", "A")
            return True
        except Exception as e:
            logger.error("DNS health check failed", error=str(e))
            return False
