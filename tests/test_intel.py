"""Tests for the SPECTRE intelligence layer."""

import pytest

from spectre.intel.attribution import AttributionPipeline, AttributionStage
from spectre.intel.enrichment import EnrichmentConfig, EnrichmentPipeline
from spectre.intel.mitre_attack import MITREAttack
from spectre.intel.report import ReportFormat, ReportGenerator, ThreatLevel
from spectre.intel.ttp_tagger import TTPTagger
from spectre.plugins.registry import PluginRegistry


class TestMITREAttack:
    """Tests for MITRE ATT&CK integration."""

    def test_ttp_keywords_exist(self) -> None:
        """Test that TTP keywords are defined."""
        mitre = MITREAttack()
        assert len(mitre.TTP_KEYWORDS) > 0
        assert "T1566" in mitre.TTP_KEYWORDS  # Phishing
        assert "T1059" in mitre.TTP_KEYWORDS  # Command & Scripting

    def test_match_ttps_phishing(self) -> None:
        """Test TTP matching for phishing keywords."""
        mitre = MITREAttack()
        # Pre-populate techniques for testing (normally loaded from cache)
        from spectre.intel.mitre_attack import Technique

        mitre._techniques["T1566"] = Technique(
            technique_id="T1566",
            name="Phishing",
            description="Test",
            tactics=["initial-access"],
            platforms=["Windows", "Linux", "macOS"],
        )
        mitre._loaded = True

        matches = mitre.match_ttps("Spearphishing email with malicious attachment")
        assert len(matches) > 0
        assert any(m.technique.technique_id == "T1566" for m in matches)

    def test_match_ttps_ransomware(self) -> None:
        """Test TTP matching for ransomware keywords."""
        mitre = MITREAttack()
        from spectre.intel.mitre_attack import Technique

        mitre._techniques["T1486"] = Technique(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            description="Test",
            tactics=["impact"],
            platforms=["Windows", "Linux"],
        )
        mitre._loaded = True

        matches = mitre.match_ttps("Ransomware encrypted all files and demanded payment")
        assert len(matches) > 0
        assert any(m.technique.technique_id == "T1486" for m in matches)

    def test_match_ttps_no_match(self) -> None:
        """Test TTP matching with no keywords."""
        mitre = MITREAttack()
        mitre._loaded = True

        matches = mitre.match_ttps("Hello world this is a normal message")
        assert len(matches) == 0


class TestAttributionPipeline:
    """Tests for attribution pipeline."""

    def test_list_actors(self) -> None:
        """Test listing known threat actors."""
        pipeline = AttributionPipeline()
        actors = pipeline.list_actors()
        assert len(actors) > 0
        actor_names = [a.name for a in actors]
        assert "APT28" in actor_names
        assert "Lazarus Group" in actor_names

    def test_get_actor_by_name(self) -> None:
        """Test getting actor by name."""
        pipeline = AttributionPipeline()
        actor = pipeline.get_actor("APT28")
        assert actor is not None
        assert actor.name == "APT28"
        assert "Fancy Bear" in actor.aliases

    def test_get_actor_by_alias(self) -> None:
        """Test getting actor by alias."""
        pipeline = AttributionPipeline()
        actor = pipeline.get_actor("Fancy Bear")
        assert actor is not None
        assert actor.name == "APT28"

    def test_attribution_with_ttp_match(self) -> None:
        """Test attribution with TTP overlap."""
        pipeline = AttributionPipeline()

        # APT28 known TTPs
        observed_ttps = ["T1566.001", "T1059.001", "T1071.001"]

        results = pipeline.attribute(
            observed_ttps=observed_ttps,
            min_score=0.0,
        )

        assert len(results) > 0
        # APT28 should have a score since we used their TTPs
        apt28_result = next(
            (r for r in results if r.actor.name == "APT28"), None
        )
        assert apt28_result is not None
        assert apt28_result.stage_scores[0].stage == AttributionStage.TTP_MATCHING
        assert apt28_result.stage_scores[0].score > 0

    def test_attribution_with_tools(self) -> None:
        """Test attribution with tool matches."""
        pipeline = AttributionPipeline()

        results = pipeline.attribute(
            malware_families=["Mimikatz", "Cobalt Strike"],
            min_score=0.0,
        )

        assert len(results) > 0
        # Multiple actors use these tools
        for result in results:
            tooling_score = next(
                s for s in result.stage_scores
                if s.stage == AttributionStage.TOOLING
            )
            # At least some should match
            if tooling_score.score > 0:
                break
        else:
            pytest.fail("No tooling matches found")

    def test_explain_attribution(self) -> None:
        """Test attribution explanation generation."""
        pipeline = AttributionPipeline()

        results = pipeline.attribute(
            observed_ttps=["T1566.001", "T1059.001"],
            target_sectors=["government"],
            min_score=0.0,
        )

        assert len(results) > 0
        explanation = pipeline.explain_attribution(results[0])
        assert "Attribution Analysis:" in explanation
        assert "Stage Breakdown:" in explanation


class TestTTPTagger:
    """Tests for TTP auto-tagger."""

    def test_tag_finding_with_powershell(self) -> None:
        """Test tagging a finding with PowerShell indicators."""
        tagger = TTPTagger()
        tagger.mitre._loaded = True

        from spectre.intel.mitre_attack import Technique

        tagger.mitre._techniques["T1059.001"] = Technique(
            technique_id="T1059.001",
            name="PowerShell",
            description="Test",
            tactics=["execution"],
            platforms=["Windows"],
        )

        finding = {
            "finding_type": "command_execution",
            "data": {
                "command": "powershell -enc SGVsbG8gV29ybGQ=",
                "description": "Encoded PowerShell command",
            },
        }

        tagged = tagger.tag_finding(finding)
        assert len(tagged.ttp_matches) > 0
        assert any(
            m.technique.technique_id == "T1059.001"
            for m in tagged.ttp_matches
        )

    def test_summarize_ttps(self) -> None:
        """Test TTP summarization."""
        tagger = TTPTagger()
        tagger.mitre._loaded = True

        from spectre.intel.mitre_attack import Technique

        tagger.mitre._techniques["T1059.001"] = Technique(
            technique_id="T1059.001",
            name="PowerShell",
            description="Test",
            tactics=["execution"],
            platforms=["Windows"],
        )

        finding1 = {"finding_type": "test", "data": {"cmd": "powershell"}}
        finding2 = {"finding_type": "test", "data": {"cmd": "powershell invoke-expression"}}

        tagged = [
            tagger.tag_finding(finding1),
            tagger.tag_finding(finding2),
        ]

        summary = tagger.summarize_ttps(tagged)
        assert "T1059.001" in summary.techniques
        assert summary.techniques["T1059.001"] >= 1


class TestReportGenerator:
    """Tests for report generator."""

    def test_generate_basic_report(self) -> None:
        """Test generating a basic report."""
        generator = ReportGenerator()

        report = generator.generate_report(
            target="example.com",
            target_type="domain",
        )

        assert report.title == "Threat Intelligence Report: example.com"
        assert report.target == "example.com"
        assert report.target_type == "domain"
        assert report.threat_level == ThreatLevel.UNKNOWN

    def test_format_markdown(self) -> None:
        """Test markdown formatting."""
        generator = ReportGenerator()

        report = generator.generate_report(
            target="test.com",
            target_type="domain",
        )

        markdown = generator.format_report(report, ReportFormat.MARKDOWN)
        assert "# Threat Intelligence Report: test.com" in markdown
        assert "## Executive Summary" in markdown
        assert "SPECTRE" in markdown

    def test_format_json(self) -> None:
        """Test JSON formatting."""
        generator = ReportGenerator()

        report = generator.generate_report(
            target="test.com",
            target_type="domain",
        )

        import json

        json_output = generator.format_report(report, ReportFormat.JSON)
        data = json.loads(json_output)
        assert data["target"] == "test.com"
        assert data["target_type"] == "domain"

    def test_format_html(self) -> None:
        """Test HTML formatting."""
        generator = ReportGenerator()

        report = generator.generate_report(
            target="test.com",
            target_type="domain",
        )

        html = generator.format_report(report, ReportFormat.HTML)
        assert "<!DOCTYPE html>" in html
        assert "test.com" in html
        assert "</html>" in html

    def test_threat_level_determination(self) -> None:
        """Test threat level is determined correctly."""
        generator = ReportGenerator()

        from spectre.intel.enrichment import EnrichmentResult

        # Create mock enrichment with malicious finding
        enrichment = EnrichmentResult(
            entity={"type": "domain", "value": "evil.com"},
            results=[],
            success=True,
            confidence_score=0.9,
            is_malicious=True,
            threat_level="high",
        )

        report = generator.generate_report(
            target="evil.com",
            target_type="domain",
            enrichment=enrichment,
        )

        assert report.threat_level == ThreatLevel.HIGH


class TestEnrichmentPipeline:
    """Tests for enrichment pipeline."""

    def test_default_plugins_exist(self) -> None:
        """Test that default plugins are defined for entity types."""
        pipeline = EnrichmentPipeline()
        assert "domain" in pipeline.DEFAULT_PLUGINS
        assert "ip_address" in pipeline.DEFAULT_PLUGINS
        assert "hash" in pipeline.DEFAULT_PLUGINS

    def test_get_plugins_for_domain(self) -> None:
        """Test getting plugins for domain type."""
        pipeline = EnrichmentPipeline()
        plugins = pipeline._get_plugins_for_type("domain")
        assert "dns_recon" in plugins
        assert "whois_lookup" in plugins

    def test_custom_plugin_config(self) -> None:
        """Test custom plugin configuration."""
        config = EnrichmentConfig(
            plugins_by_type={
                "domain": ["dns_recon"],  # Only use dns_recon
            }
        )
        pipeline = EnrichmentPipeline(config=config)

        plugins = pipeline._get_plugins_for_type("domain")
        assert plugins == ["dns_recon"]

    @pytest.mark.asyncio
    async def test_enrich_entity_no_api_keys(self) -> None:
        """Test enrichment skips plugins requiring API keys."""
        config = EnrichmentConfig(
            skip_unconfigured=True,
            plugins_by_type={
                "domain": ["virustotal"],  # Requires API key
            },
        )
        registry = PluginRegistry()
        pipeline = EnrichmentPipeline(registry=registry, config=config)

        result = await pipeline.enrich({"type": "domain", "value": "test.com"})
        # Should succeed but with no results (plugin skipped)
        assert result.success
