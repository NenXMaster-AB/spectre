"""
Tests for the DNS Reconnaissance Plugin.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spectre.plugins.base import EntityType, PluginCategory, PluginConfig
from spectre.plugins.osint.dns_recon import DNSReconPlugin


@pytest.fixture
def dns_plugin() -> DNSReconPlugin:
    """Create a fresh DNS recon plugin instance."""
    return DNSReconPlugin()


class TestDNSReconPlugin:
    """Tests for DNSReconPlugin."""

    def test_plugin_attributes(self, dns_plugin: DNSReconPlugin) -> None:
        """Test plugin has correct attributes."""
        assert dns_plugin.name == "dns_recon"
        assert dns_plugin.category == PluginCategory.OSINT
        assert EntityType.DOMAIN in dns_plugin.input_types
        assert EntityType.IP_ADDRESS in dns_plugin.output_types
        assert EntityType.DOMAIN in dns_plugin.output_types

    def test_plugin_description(self, dns_plugin: DNSReconPlugin) -> None:
        """Test plugin has a description."""
        assert dns_plugin.description
        assert len(dns_plugin.description) > 10

    def test_accepts_domain_entity(self, dns_plugin: DNSReconPlugin) -> None:
        """Test plugin accepts domain entities."""
        assert dns_plugin.accepts_entity(EntityType.DOMAIN) is True
        assert dns_plugin.accepts_entity(EntityType.IP_ADDRESS) is False

    def test_get_info(self, dns_plugin: DNSReconPlugin) -> None:
        """Test get_info returns correct structure."""
        info = dns_plugin.get_info()

        assert info["name"] == "dns_recon"
        assert info["category"] == "osint"
        assert "domain" in info["input_types"]
        assert "ip_address" in info["output_types"]
        assert info["rate_limit"] is not None

    @pytest.mark.asyncio
    async def test_execute_missing_domain(self, dns_plugin: DNSReconPlugin) -> None:
        """Test execute fails gracefully with missing domain."""
        entity = {"type": "domain", "value": ""}
        result = await dns_plugin.execute(entity)

        assert result.success is False
        assert "No domain provided" in result.error

    @pytest.mark.asyncio
    async def test_execute_with_mock_resolver(self, dns_plugin: DNSReconPlugin) -> None:
        """Test execute with mocked DNS resolver."""
        entity = {"type": "domain", "value": "example.com"}

        # Create mock answer
        mock_a_record = MagicMock()
        mock_a_record.address = "93.184.216.34"

        mock_rrset = MagicMock()
        mock_rrset.ttl = 3600

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([mock_a_record])
        mock_answer.rrset = mock_rrset

        with patch.object(dns_plugin, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(return_value=mock_answer)
            mock_get_resolver.return_value = mock_resolver

            result = await dns_plugin.execute(entity)

        assert result.success is True
        assert result.plugin_name == "dns_recon"
        assert result.input_entity == entity

    @pytest.mark.asyncio
    async def test_health_check_with_mock(self, dns_plugin: DNSReconPlugin) -> None:
        """Test health check with mocked resolver."""
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([])

        with patch.object(dns_plugin, "_get_resolver") as mock_get_resolver:
            mock_resolver = AsyncMock()
            mock_resolver.resolve = AsyncMock(return_value=mock_answer)
            mock_get_resolver.return_value = mock_resolver

            healthy = await dns_plugin.health_check()

        assert healthy is True

    def test_record_types_defined(self, dns_plugin: DNSReconPlugin) -> None:
        """Test that common DNS record types are defined."""
        expected_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        for record_type in expected_types:
            assert record_type in dns_plugin.RECORD_TYPES


class TestDNSReconPluginIntegration:
    """Integration tests that make real DNS queries."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_execute_real_domain(
        self,
        dns_plugin: DNSReconPlugin,
        google_domain_entity: dict[str, str],
    ) -> None:
        """Test execute against a real domain (google.com)."""
        result = await dns_plugin.execute(google_domain_entity)

        assert result.success is True
        assert result.plugin_name == "dns_recon"
        assert len(result.findings) > 0

        # Should have discovered some IPs
        assert len(result.entities_discovered) > 0

        # Check for A record findings
        a_record_findings = [f for f in result.findings if f.type == "dns_a"]
        assert len(a_record_findings) > 0

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_execute_nonexistent_domain(
        self,
        dns_plugin: DNSReconPlugin,
    ) -> None:
        """Test execute against a non-existent domain."""
        entity = {"type": "domain", "value": "thisdomain-definitely-does-not-exist-12345.com"}
        result = await dns_plugin.execute(entity)

        # Should still succeed (no records is not an error)
        assert result.success is True
        # Might have zero findings for non-existent domain
        assert result.findings is not None

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_health_check_real(self, dns_plugin: DNSReconPlugin) -> None:
        """Test health check makes real DNS query."""
        healthy = await dns_plugin.health_check()
        assert healthy is True
