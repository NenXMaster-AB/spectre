"""
Report Generator

Generates threat intelligence reports from investigation results.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

from spectre.intel.attribution import AttributionResult
from spectre.intel.enrichment import EnrichmentResult
from spectre.intel.ttp_tagger import TaggedFinding, TTPSummary

logger = structlog.get_logger(__name__)


class ReportFormat(Enum):
    """Available report formats."""

    TEXT = "text"
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


class ThreatLevel(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


@dataclass
class ReportSection:
    """A section of a report."""

    title: str
    content: str | dict[str, Any] | list[Any]
    level: int = 2  # Heading level


@dataclass
class InvestigationReport:
    """Complete investigation report."""

    title: str
    target: str
    target_type: str
    timestamp: datetime
    threat_level: ThreatLevel
    executive_summary: str
    sections: list[ReportSection] = field(default_factory=list)
    indicators: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "title": self.title,
            "target": self.target,
            "target_type": self.target_type,
            "timestamp": self.timestamp.isoformat(),
            "threat_level": self.threat_level.value,
            "executive_summary": self.executive_summary,
            "sections": [
                {"title": s.title, "content": s.content, "level": s.level}
                for s in self.sections
            ],
            "indicators": self.indicators,
            "recommendations": self.recommendations,
        }


class ReportGenerator:
    """
    Generates threat intelligence reports.

    Supports multiple output formats:
    - Plain text
    - Markdown
    - JSON
    - HTML
    """

    def __init__(self) -> None:
        """Initialize the report generator."""
        pass

    def _determine_threat_level(
        self,
        enrichment: EnrichmentResult | None = None,
        attribution: list[AttributionResult] | None = None,
        ttp_summary: TTPSummary | None = None,
    ) -> ThreatLevel:
        """Determine overall threat level from analysis results."""
        if enrichment:
            if enrichment.threat_level == "critical":
                return ThreatLevel.CRITICAL
            elif enrichment.threat_level == "high":
                return ThreatLevel.HIGH
            elif enrichment.threat_level == "medium":
                return ThreatLevel.MEDIUM
            elif enrichment.threat_level == "low":
                return ThreatLevel.LOW
            elif enrichment.threat_level == "clean":
                return ThreatLevel.INFORMATIONAL

        if attribution:
            top_score = max(a.overall_score for a in attribution)
            if top_score >= 0.7:
                return ThreatLevel.CRITICAL
            elif top_score >= 0.5:
                return ThreatLevel.HIGH
            elif top_score >= 0.3:
                return ThreatLevel.MEDIUM

        if ttp_summary and ttp_summary.techniques:
            technique_count = len(ttp_summary.techniques)
            if technique_count >= 5:
                return ThreatLevel.HIGH
            elif technique_count >= 3:
                return ThreatLevel.MEDIUM
            elif technique_count >= 1:
                return ThreatLevel.LOW

        return ThreatLevel.UNKNOWN

    def _generate_executive_summary(
        self,
        target: str,
        target_type: str,
        enrichment: EnrichmentResult | None = None,
        attribution: list[AttributionResult] | None = None,
        ttp_summary: TTPSummary | None = None,
    ) -> str:
        """Generate executive summary paragraph."""
        parts = [f"Investigation of {target_type} '{target}'"]

        if enrichment:
            if enrichment.is_malicious:
                parts.append(
                    f"identified as malicious with {enrichment.confidence_score:.0%} confidence"
                )
            elif enrichment.threat_level != "unknown":
                parts.append(f"assessed as {enrichment.threat_level} threat level")

            finding_count = len(enrichment.all_findings)
            if finding_count > 0:
                parts.append(f"based on {finding_count} findings from threat intelligence sources")

        if attribution:
            top_attr = attribution[0]
            parts.append(
                f"Potential attribution to {top_attr.actor.name} "
                f"({top_attr.confidence} confidence, {top_attr.overall_score:.0%} score)"
            )

        if ttp_summary and ttp_summary.techniques:
            technique_count = len(ttp_summary.techniques)
            parts.append(f"{technique_count} MITRE ATT&CK techniques identified")

        return ". ".join(parts) + "."

    def _build_enrichment_section(
        self,
        enrichment: EnrichmentResult,
    ) -> ReportSection:
        """Build threat intelligence section from enrichment."""
        content_parts = []

        content_parts.append(f"**Threat Level:** {enrichment.threat_level.upper()}")
        content_parts.append(f"**Confidence Score:** {enrichment.confidence_score:.0%}")
        content_parts.append(f"**Is Malicious:** {'Yes' if enrichment.is_malicious else 'No'}")

        # Group findings by plugin
        findings_by_plugin: dict[str, list[dict[str, Any]]] = {}
        for result in enrichment.results:
            if result.success and result.findings:
                plugin = result.plugin_name
                if plugin not in findings_by_plugin:
                    findings_by_plugin[plugin] = []
                findings_by_plugin[plugin].extend(result.findings)

        content_parts.append("\n### Sources Queried")
        for plugin, findings in findings_by_plugin.items():
            content_parts.append(f"- **{plugin}**: {len(findings)} findings")

        return ReportSection(
            title="Threat Intelligence Analysis",
            content="\n".join(content_parts),
        )

    def _build_attribution_section(
        self,
        attribution: list[AttributionResult],
    ) -> ReportSection:
        """Build attribution section."""
        content_parts = []

        for i, attr in enumerate(attribution[:3]):
            content_parts.append(f"### {i + 1}. {attr.actor.name}")
            content_parts.append(f"**Aliases:** {', '.join(attr.actor.aliases)}")
            content_parts.append(f"**Overall Score:** {attr.overall_score:.0%}")
            content_parts.append(f"**Confidence:** {attr.confidence.upper()}")

            if attr.actor.attribution_country:
                content_parts.append(f"**Attribution Country:** {attr.actor.attribution_country}")

            content_parts.append("\n**Stage Scores:**")
            for score in attr.stage_scores:
                stage_name = score.stage.value.replace("_", " ").title()
                content_parts.append(f"- {stage_name}: {score.score:.0%}")

            content_parts.append("")

        return ReportSection(
            title="Attribution Analysis",
            content="\n".join(content_parts),
        )

    def _build_ttp_section(
        self,
        ttp_summary: TTPSummary,
    ) -> ReportSection:
        """Build TTP analysis section."""
        content_parts = []

        content_parts.append("### Tactics")
        for tactic, count in ttp_summary.top_tactics[:10]:
            content_parts.append(f"- {tactic}: {count} occurrences")

        content_parts.append("\n### Techniques")
        for technique_id, count in ttp_summary.top_techniques[:10]:
            # Find technique name from matches
            name = technique_id
            for match in ttp_summary.matches:
                if match.technique.technique_id == technique_id:
                    name = f"{technique_id}: {match.technique.name}"
                    break
            content_parts.append(f"- {name} ({count} occurrences)")

        return ReportSection(
            title="MITRE ATT&CK Analysis",
            content="\n".join(content_parts),
        )

    def _extract_indicators(
        self,
        enrichment: EnrichmentResult | None = None,
        tagged_findings: list[TaggedFinding] | None = None,
    ) -> list[dict[str, Any]]:
        """Extract IOCs from results."""
        indicators = []
        seen = set()

        if enrichment:
            for entity in enrichment.all_entities:
                value = entity.get("value", "")
                if value and value not in seen:
                    seen.add(value)
                    indicators.append({
                        "type": entity.get("type", "unknown"),
                        "value": value,
                        "source": entity.get("source", "enrichment"),
                        "is_malicious": entity.get("is_malicious", False),
                    })

        return indicators

    def _generate_recommendations(
        self,
        threat_level: ThreatLevel,
        enrichment: EnrichmentResult | None = None,
        ttp_summary: TTPSummary | None = None,
    ) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        if threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            recommendations.extend([
                "Immediately block identified malicious indicators at perimeter",
                "Conduct endpoint investigation for presence of identified IOCs",
                "Review logs for historical connections to identified infrastructure",
                "Consider engaging incident response team",
            ])

        if threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Add identified indicators to monitoring watchlist",
                "Review security controls for potential weaknesses",
                "Continue monitoring for additional suspicious activity",
            ])

        if ttp_summary and ttp_summary.techniques:
            recommendations.append(
                f"Review detection capabilities for {len(ttp_summary.techniques)} "
                "identified MITRE ATT&CK techniques"
            )

        if not recommendations:
            recommendations.append("No immediate action required based on current findings")

        return recommendations

    def generate_report(
        self,
        target: str,
        target_type: str,
        enrichment: EnrichmentResult | None = None,
        attribution: list[AttributionResult] | None = None,
        ttp_summary: TTPSummary | None = None,
        tagged_findings: list[TaggedFinding] | None = None,
    ) -> InvestigationReport:
        """
        Generate a complete investigation report.

        Args:
            target: Investigation target value
            target_type: Type of target (domain, ip, hash, etc.)
            enrichment: Enrichment results
            attribution: Attribution results
            ttp_summary: TTP analysis summary
            tagged_findings: Tagged findings with TTPs

        Returns:
            InvestigationReport object
        """
        threat_level = self._determine_threat_level(
            enrichment, attribution, ttp_summary
        )

        executive_summary = self._generate_executive_summary(
            target, target_type, enrichment, attribution, ttp_summary
        )

        sections = []

        if enrichment:
            sections.append(self._build_enrichment_section(enrichment))

        if attribution:
            sections.append(self._build_attribution_section(attribution))

        if ttp_summary and ttp_summary.techniques:
            sections.append(self._build_ttp_section(ttp_summary))

        indicators = self._extract_indicators(enrichment, tagged_findings)
        recommendations = self._generate_recommendations(
            threat_level, enrichment, ttp_summary
        )

        return InvestigationReport(
            title=f"Threat Intelligence Report: {target}",
            target=target,
            target_type=target_type,
            timestamp=datetime.utcnow(),
            threat_level=threat_level,
            executive_summary=executive_summary,
            sections=sections,
            indicators=indicators,
            recommendations=recommendations,
        )

    def format_report(
        self,
        report: InvestigationReport,
        format: ReportFormat = ReportFormat.MARKDOWN,
    ) -> str:
        """
        Format report to string.

        Args:
            report: Report to format
            format: Output format

        Returns:
            Formatted report string
        """
        if format == ReportFormat.JSON:
            return json.dumps(report.to_dict(), indent=2)

        elif format == ReportFormat.MARKDOWN:
            return self._format_markdown(report)

        elif format == ReportFormat.HTML:
            return self._format_html(report)

        else:  # TEXT
            return self._format_text(report)

    def _format_markdown(self, report: InvestigationReport) -> str:
        """Format report as Markdown."""
        lines = [
            f"# {report.title}",
            "",
            f"**Generated:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Target:** `{report.target}` ({report.target_type})",
            f"**Threat Level:** {report.threat_level.value.upper()}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
        ]

        for section in report.sections:
            lines.append(f"{'#' * section.level} {section.title}")
            lines.append("")
            if isinstance(section.content, str):
                lines.append(section.content)
            else:
                lines.append(json.dumps(section.content, indent=2))
            lines.append("")

        if report.indicators:
            lines.append("## Indicators of Compromise")
            lines.append("")
            lines.append("| Type | Value | Malicious |")
            lines.append("|------|-------|-----------|")
            for ioc in report.indicators[:50]:
                malicious = "Yes" if ioc.get("is_malicious") else "No"
                lines.append(f"| {ioc['type']} | `{ioc['value']}` | {malicious} |")
            lines.append("")

        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---")
        lines.append("*Report generated by SPECTRE Threat Intelligence Platform*")

        return "\n".join(lines)

    def _format_text(self, report: InvestigationReport) -> str:
        """Format report as plain text."""
        lines = [
            "=" * 60,
            report.title.center(60),
            "=" * 60,
            "",
            f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Target: {report.target} ({report.target_type})",
            f"Threat Level: {report.threat_level.value.upper()}",
            "",
            "-" * 40,
            "EXECUTIVE SUMMARY",
            "-" * 40,
            "",
            report.executive_summary,
            "",
        ]

        for section in report.sections:
            lines.append("-" * 40)
            lines.append(section.title.upper())
            lines.append("-" * 40)
            lines.append("")
            if isinstance(section.content, str):
                # Strip markdown formatting
                content = section.content.replace("**", "").replace("###", "")
                lines.append(content)
            else:
                lines.append(str(section.content))
            lines.append("")

        if report.recommendations:
            lines.append("-" * 40)
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 40)
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("=" * 60)
        lines.append("Report generated by SPECTRE".center(60))
        lines.append("=" * 60)

        return "\n".join(lines)

    def _format_html(self, report: InvestigationReport) -> str:
        """Format report as HTML."""
        threat_colors = {
            ThreatLevel.CRITICAL: "#dc3545",
            ThreatLevel.HIGH: "#fd7e14",
            ThreatLevel.MEDIUM: "#ffc107",
            ThreatLevel.LOW: "#28a745",
            ThreatLevel.INFORMATIONAL: "#17a2b8",
            ThreatLevel.UNKNOWN: "#6c757d",
        }

        color = threat_colors.get(report.threat_level, "#6c757d")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; }}
        h1 {{ color: #333; border-bottom: 2px solid {color}; padding-bottom: 0.5em; }}
        h2 {{ color: #555; margin-top: 1.5em; }}
        .meta {{ color: #666; margin-bottom: 1em; }}
        .threat-level {{ display: inline-block; padding: 0.25em 0.5em; background: {color}; color: white; border-radius: 4px; }}
        .summary {{ background: #f8f9fa; padding: 1em; border-radius: 4px; margin: 1em 0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5em; text-align: left; }}
        th {{ background: #f4f4f4; }}
        code {{ background: #eee; padding: 0.1em 0.3em; border-radius: 3px; }}
        .recommendations {{ background: #fff3cd; padding: 1em; border-radius: 4px; }}
        .recommendations li {{ margin: 0.5em 0; }}
        footer {{ margin-top: 2em; padding-top: 1em; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>{report.title}</h1>
    <div class="meta">
        <p>Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Target: <code>{report.target}</code> ({report.target_type})</p>
        <p>Threat Level: <span class="threat-level">{report.threat_level.value.upper()}</span></p>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary">{report.executive_summary}</div>
"""

        for section in report.sections:
            content = section.content if isinstance(section.content, str) else json.dumps(section.content, indent=2)
            # Convert markdown to basic HTML
            content = content.replace("**", "<strong>").replace("###", "<h3>").replace("\n", "<br>")
            html += f"""
    <h2>{section.title}</h2>
    <div>{content}</div>
"""

        if report.indicators:
            html += """
    <h2>Indicators of Compromise</h2>
    <table>
        <tr><th>Type</th><th>Value</th><th>Malicious</th></tr>
"""
            for ioc in report.indicators[:50]:
                malicious = "Yes" if ioc.get("is_malicious") else "No"
                html += f"        <tr><td>{ioc['type']}</td><td><code>{ioc['value']}</code></td><td>{malicious}</td></tr>\n"
            html += "    </table>\n"

        if report.recommendations:
            html += """
    <h2>Recommendations</h2>
    <div class="recommendations"><ul>
"""
            for rec in report.recommendations:
                html += f"        <li>{rec}</li>\n"
            html += "    </ul></div>\n"

        html += """
    <footer>Report generated by SPECTRE Threat Intelligence Platform</footer>
</body>
</html>"""

        return html

    def save_report(
        self,
        report: InvestigationReport,
        output_path: Path | str,
        format: ReportFormat | None = None,
    ) -> Path:
        """
        Save report to file.

        Args:
            report: Report to save
            output_path: Output file path
            format: Output format (inferred from extension if not provided)

        Returns:
            Path to saved file
        """
        output_path = Path(output_path)

        # Infer format from extension if not provided
        if format is None:
            ext = output_path.suffix.lower()
            format_map = {
                ".json": ReportFormat.JSON,
                ".md": ReportFormat.MARKDOWN,
                ".markdown": ReportFormat.MARKDOWN,
                ".html": ReportFormat.HTML,
                ".htm": ReportFormat.HTML,
            }
            format = format_map.get(ext, ReportFormat.TEXT)

        content = self.format_report(report, format)
        output_path.write_text(content)

        logger.info("Report saved", path=str(output_path), format=format.value)
        return output_path
