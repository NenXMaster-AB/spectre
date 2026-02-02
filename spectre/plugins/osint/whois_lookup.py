"""
WHOIS Lookup Plugin

Retrieves domain registration information including registrar,
registrant details, and important dates.
"""

import asyncio
from datetime import datetime
from functools import partial
from typing import Any

import structlog
import whois

from spectre.plugins.base import (
    EntityType,
    PluginCategory,
    PluginConfig,
    PluginResult,
    RateLimit,
    SpectrePlugin,
)

logger = structlog.get_logger(__name__)


def _parse_date(date_value: Any) -> str | None:
    """Parse a date value to ISO format string."""
    if date_value is None:
        return None

    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None

    if isinstance(date_value, datetime):
        return date_value.isoformat()

    if isinstance(date_value, str):
        return date_value

    return str(date_value) if date_value else None


def _parse_list(value: Any) -> list[str]:
    """Parse a value that might be a string or list into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def _safe_get(whois_data: Any, key: str, default: Any = None) -> Any:
    """Safely get a value from whois data."""
    try:
        value = getattr(whois_data, key, None)
        if value is None:
            value = whois_data.get(key) if hasattr(whois_data, "get") else None
        return value if value is not None else default
    except Exception:
        return default


class WhoisLookupPlugin(SpectrePlugin):
    """
    WHOIS Lookup Plugin.

    Retrieves domain registration information including:
    - Registrar information
    - Registrant name, organization, email, country
    - Domain creation, expiration, and update dates
    - Nameservers
    - Domain status
    """

    name = "whois_lookup"
    description = "Retrieve domain WHOIS registration data (registrar, dates, registrant)"
    category = PluginCategory.OSINT
    input_types = [EntityType.DOMAIN]
    output_types = [EntityType.EMAIL, EntityType.ORGANIZATION]
    required_config: list[str] = []
    rate_limit = RateLimit(requests_per_minute=30, concurrent_requests=3)

    async def _do_whois_lookup(self, domain: str) -> dict[str, Any]:
        """
        Perform WHOIS lookup in a thread pool.

        python-whois is synchronous, so we run it in an executor.
        """
        loop = asyncio.get_event_loop()

        try:
            # Run synchronous whois in thread pool
            whois_data = await loop.run_in_executor(
                None,
                partial(whois.whois, domain),
            )

            if whois_data is None:
                return {"error": "No WHOIS data returned"}

            # Extract and normalize data
            result: dict[str, Any] = {
                "domain": domain,
                "registrar": _safe_get(whois_data, "registrar"),
                "registrar_url": _safe_get(whois_data, "registrar_url"),
                "registrar_iana_id": _safe_get(whois_data, "registrar_iana_id"),
                # Registrant information
                "registrant_name": _safe_get(whois_data, "name"),
                "registrant_organization": _safe_get(whois_data, "org"),
                "registrant_email": None,
                "registrant_country": _safe_get(whois_data, "country"),
                "registrant_state": _safe_get(whois_data, "state"),
                "registrant_city": _safe_get(whois_data, "city"),
                "registrant_address": _safe_get(whois_data, "address"),
                "registrant_zipcode": _safe_get(whois_data, "zipcode"),
                # Dates
                "creation_date": _parse_date(_safe_get(whois_data, "creation_date")),
                "expiration_date": _parse_date(_safe_get(whois_data, "expiration_date")),
                "updated_date": _parse_date(_safe_get(whois_data, "updated_date")),
                # Technical details
                "nameservers": _parse_list(_safe_get(whois_data, "name_servers")),
                "status": _parse_list(_safe_get(whois_data, "status")),
                "dnssec": _safe_get(whois_data, "dnssec"),
                # Whois server
                "whois_server": _safe_get(whois_data, "whois_server"),
            }

            # Handle emails (can be in different fields)
            emails = _safe_get(whois_data, "emails")
            if emails:
                if isinstance(emails, list):
                    result["registrant_email"] = emails[0] if emails else None
                    result["all_emails"] = emails
                else:
                    result["registrant_email"] = emails
                    result["all_emails"] = [emails]
            else:
                result["all_emails"] = []

            # Clean up nameservers (lowercase, remove trailing dots)
            if result["nameservers"]:
                result["nameservers"] = [
                    ns.lower().rstrip(".") for ns in result["nameservers"]
                ]

            # Store raw data for debugging
            result["raw"] = {
                k: str(v) for k, v in whois_data.items() if v is not None
            } if hasattr(whois_data, "items") else {}

            return result

        except Exception as e:
            logger.warning("WHOIS lookup failed", domain=domain, error=str(e))
            return {"error": f"WHOIS lookup failed: {e}"}

    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute WHOIS lookup for a domain.

        Args:
            entity: Dict with 'type' and 'value' keys (domain name)
            config: Optional plugin configuration

        Returns:
            PluginResult with WHOIS data and discovered entities
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

        # Extract base domain for WHOIS (remove subdomain)
        parts = domain.split(".")
        if len(parts) > 2:
            # Handle common TLDs like co.uk, com.au, etc.
            common_second_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
            if parts[-2] in common_second_level:
                base_domain = ".".join(parts[-3:])
            else:
                base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        logger.info("Starting WHOIS lookup", domain=domain, base_domain=base_domain)

        result = PluginResult(
            success=True,
            plugin_name=self.name,
            input_entity=entity,
        )

        # Perform WHOIS lookup
        whois_data = await self._do_whois_lookup(base_domain)

        if "error" in whois_data:
            result.success = False
            result.error = whois_data["error"]
            return result

        # Add main WHOIS finding
        result.add_finding(
            finding_type="whois_data",
            data={
                "domain": base_domain,
                "registrar": whois_data.get("registrar"),
                "registrar_url": whois_data.get("registrar_url"),
                "creation_date": whois_data.get("creation_date"),
                "expiration_date": whois_data.get("expiration_date"),
                "updated_date": whois_data.get("updated_date"),
                "nameservers": whois_data.get("nameservers", []),
                "status": whois_data.get("status", []),
                "dnssec": whois_data.get("dnssec"),
            },
            confidence=1.0,
        )

        # Add registrant finding if we have data
        registrant_data = {
            "name": whois_data.get("registrant_name"),
            "organization": whois_data.get("registrant_organization"),
            "email": whois_data.get("registrant_email"),
            "country": whois_data.get("registrant_country"),
            "state": whois_data.get("registrant_state"),
            "city": whois_data.get("registrant_city"),
        }

        # Only add if we have any registrant data
        if any(v for v in registrant_data.values()):
            result.add_finding(
                finding_type="whois_registrant",
                data=registrant_data,
                confidence=0.9,  # WHOIS data can be outdated or privacy-protected
            )

        # Calculate domain age
        creation_date = whois_data.get("creation_date")
        expiration_date = whois_data.get("expiration_date")

        domain_age_days = None
        days_until_expiry = None

        if creation_date:
            try:
                created = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
                domain_age_days = (datetime.now(created.tzinfo) - created).days
            except (ValueError, TypeError):
                pass

        if expiration_date:
            try:
                expires = datetime.fromisoformat(expiration_date.replace("Z", "+00:00"))
                days_until_expiry = (expires - datetime.now(expires.tzinfo)).days
            except (ValueError, TypeError):
                pass

        # Add domain age finding
        result.add_finding(
            finding_type="domain_age",
            data={
                "domain": base_domain,
                "age_days": domain_age_days,
                "days_until_expiry": days_until_expiry,
                "is_newly_registered": domain_age_days is not None and domain_age_days < 30,
                "expiring_soon": days_until_expiry is not None and days_until_expiry < 30,
            },
            confidence=1.0 if domain_age_days is not None else 0.5,
        )

        # Discover email entities
        all_emails = whois_data.get("all_emails", [])
        for email in all_emails:
            if email and "@" in email:
                # Skip common privacy/proxy emails
                privacy_indicators = [
                    "privacy", "proxy", "whoisguard", "domains", "protection",
                    "contactprivacy", "whoisprivacy", "redacted",
                ]
                email_lower = email.lower()
                is_privacy = any(ind in email_lower for ind in privacy_indicators)

                result.add_entity(
                    EntityType.EMAIL,
                    {
                        "value": email,
                        "source": f"whois:{base_domain}",
                        "is_privacy_protected": is_privacy,
                        "relationship": "registered_by",
                    },
                )

        # Discover organization entity
        org = whois_data.get("registrant_organization")
        if org and org.lower() not in ("redacted", "n/a", "none", "private"):
            result.add_entity(
                EntityType.ORGANIZATION,
                {
                    "value": org,
                    "source": f"whois:{base_domain}",
                    "country": whois_data.get("registrant_country"),
                    "relationship": "owns",
                },
            )

        logger.info(
            "WHOIS lookup complete",
            domain=base_domain,
            registrar=whois_data.get("registrar"),
            age_days=domain_age_days,
        )

        return result

    async def health_check(self) -> bool:
        """
        Verify WHOIS lookup is working.

        Tests by looking up a well-known domain (google.com).
        """
        try:
            result = await self._do_whois_lookup("google.com")
            return "error" not in result and result.get("registrar") is not None
        except Exception as e:
            logger.error("WHOIS health check failed", error=str(e))
            return False
