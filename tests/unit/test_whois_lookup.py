"""
Tests for the WHOIS Lookup Plugin.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from spectre.plugins.base import EntityType, PluginCategory
from spectre.plugins.osint.whois_lookup import WhoisLookupPlugin


@pytest.fixture
def whois_plugin() -> WhoisLookupPlugin:
    """Create a fresh WHOIS lookup plugin instance."""
    return WhoisLookupPlugin()


@pytest.fixture
def mock_whois_data() -> MagicMock:
    """Create mock WHOIS response data."""
    mock = MagicMock()
    mock.registrar = "Example Registrar, Inc."
    mock.registrar_url = "https://example-registrar.com"
    mock.name = "John Doe"
    mock.org = "Example Organization"
    mock.emails = ["admin@example.com", "tech@example.com"]
    mock.country = "US"
    mock.state = "California"
    mock.city = "San Francisco"
    mock.creation_date = datetime(2020, 1, 15)
    mock.expiration_date = datetime(2025, 1, 15)
    mock.updated_date = datetime(2023, 6, 1)
    mock.name_servers = ["ns1.example.com", "ns2.example.com"]
    mock.status = ["clientTransferProhibited"]
    mock.dnssec = "unsigned"
    mock.whois_server = "whois.example.com"

    # Make it iterable for raw data extraction
    mock.items = MagicMock(return_value=[
        ("registrar", "Example Registrar, Inc."),
        ("name", "John Doe"),
    ])

    return mock


class TestWhoisLookupPlugin:
    """Tests for WhoisLookupPlugin."""

    def test_plugin_attributes(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test plugin has correct attributes."""
        assert whois_plugin.name == "whois_lookup"
        assert whois_plugin.category == PluginCategory.OSINT
        assert EntityType.DOMAIN in whois_plugin.input_types
        assert EntityType.EMAIL in whois_plugin.output_types

    def test_plugin_description(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test plugin has a description."""
        assert whois_plugin.description
        assert "WHOIS" in whois_plugin.description

    def test_accepts_domain_entity(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test plugin accepts domain entities."""
        assert whois_plugin.accepts_entity(EntityType.DOMAIN) is True
        assert whois_plugin.accepts_entity(EntityType.IP_ADDRESS) is False

    def test_get_info(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test get_info returns correct structure."""
        info = whois_plugin.get_info()

        assert info["name"] == "whois_lookup"
        assert info["category"] == "osint"
        assert "domain" in info["input_types"]
        assert info["rate_limit"] is not None

    @pytest.mark.asyncio
    async def test_execute_missing_domain(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test execute fails gracefully with missing domain."""
        entity = {"type": "domain", "value": ""}
        result = await whois_plugin.execute(entity)

        assert result.success is False
        assert "No domain provided" in result.error

    @pytest.mark.asyncio
    async def test_execute_with_mock_whois(
        self,
        whois_plugin: WhoisLookupPlugin,
        mock_whois_data: MagicMock,
    ) -> None:
        """Test execute with mocked WHOIS data."""
        entity = {"type": "domain", "value": "example.com"}

        with patch("spectre.plugins.osint.whois_lookup.whois.whois") as mock_whois:
            mock_whois.return_value = mock_whois_data

            result = await whois_plugin.execute(entity)

        assert result.success is True
        assert result.plugin_name == "whois_lookup"

        # Check findings
        assert len(result.findings) >= 1

        # Should have WHOIS data finding
        whois_findings = [f for f in result.findings if f.type == "whois_data"]
        assert len(whois_findings) == 1
        assert whois_findings[0].data["registrar"] == "Example Registrar, Inc."

        # Should discover email entities
        email_entities = [
            e for e in result.entities_discovered if e["type"] == "email"
        ]
        assert len(email_entities) >= 1

    @pytest.mark.asyncio
    async def test_execute_with_subdomain(
        self,
        whois_plugin: WhoisLookupPlugin,
        mock_whois_data: MagicMock,
    ) -> None:
        """Test execute extracts base domain from subdomain."""
        entity = {"type": "domain", "value": "www.subdomain.example.com"}

        with patch("spectre.plugins.osint.whois_lookup.whois.whois") as mock_whois:
            mock_whois.return_value = mock_whois_data

            result = await whois_plugin.execute(entity)

        # Should still succeed
        assert result.success is True

        # Should have looked up base domain
        whois_findings = [f for f in result.findings if f.type == "whois_data"]
        assert len(whois_findings) == 1

    @pytest.mark.asyncio
    async def test_execute_whois_error(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test execute handles WHOIS errors gracefully."""
        entity = {"type": "domain", "value": "example.com"}

        with patch("spectre.plugins.osint.whois_lookup.whois.whois") as mock_whois:
            mock_whois.side_effect = Exception("WHOIS server unavailable")

            result = await whois_plugin.execute(entity)

        assert result.success is False
        assert "failed" in result.error.lower()

    @pytest.mark.asyncio
    async def test_domain_age_calculation(
        self,
        whois_plugin: WhoisLookupPlugin,
        mock_whois_data: MagicMock,
    ) -> None:
        """Test domain age is calculated correctly."""
        entity = {"type": "domain", "value": "example.com"}

        with patch("spectre.plugins.osint.whois_lookup.whois.whois") as mock_whois:
            mock_whois.return_value = mock_whois_data

            result = await whois_plugin.execute(entity)

        # Find domain_age finding
        age_findings = [f for f in result.findings if f.type == "domain_age"]
        assert len(age_findings) == 1

        age_data = age_findings[0].data
        assert "age_days" in age_data
        assert age_data["age_days"] is not None
        assert age_data["age_days"] > 0

    @pytest.mark.asyncio
    async def test_privacy_protected_email_detection(
        self,
        whois_plugin: WhoisLookupPlugin,
    ) -> None:
        """Test privacy-protected emails are flagged."""
        mock_data = MagicMock()
        mock_data.registrar = "Test Registrar"
        mock_data.emails = ["privacy@whoisguard.com"]
        mock_data.name = None
        mock_data.org = None
        mock_data.country = None
        mock_data.state = None
        mock_data.city = None
        mock_data.creation_date = None
        mock_data.expiration_date = None
        mock_data.updated_date = None
        mock_data.name_servers = []
        mock_data.status = []
        mock_data.dnssec = None
        mock_data.whois_server = None
        mock_data.registrar_url = None
        mock_data.registrar_iana_id = None
        mock_data.address = None
        mock_data.zipcode = None
        mock_data.items = MagicMock(return_value=[])

        entity = {"type": "domain", "value": "example.com"}

        with patch("spectre.plugins.osint.whois_lookup.whois.whois") as mock_whois:
            mock_whois.return_value = mock_data

            result = await whois_plugin.execute(entity)

        # Find email entities
        email_entities = [
            e for e in result.entities_discovered if e["type"] == "email"
        ]

        assert len(email_entities) == 1
        assert email_entities[0]["is_privacy_protected"] is True


class TestWhoisLookupPluginIntegration:
    """Integration tests that make real WHOIS queries."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_execute_real_domain(
        self,
        whois_plugin: WhoisLookupPlugin,
        google_domain_entity: dict[str, str],
    ) -> None:
        """Test execute against a real domain (google.com)."""
        result = await whois_plugin.execute(google_domain_entity)

        assert result.success is True
        assert result.plugin_name == "whois_lookup"
        assert len(result.findings) > 0

        # Should have WHOIS data finding
        whois_findings = [f for f in result.findings if f.type == "whois_data"]
        assert len(whois_findings) == 1

        # Google should have a registrar
        assert whois_findings[0].data.get("registrar") is not None

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_health_check_real(self, whois_plugin: WhoisLookupPlugin) -> None:
        """Test health check makes real WHOIS query."""
        healthy = await whois_plugin.health_check()
        assert healthy is True
