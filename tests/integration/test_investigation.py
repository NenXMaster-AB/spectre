"""
Integration tests for the full investigation workflow.

Tests: query -> plan -> execute -> correlate
"""

import pytest

from spectre.agent.correlator import Correlator, correlate_results
from spectre.agent.executor import ExecutorConfig, InvestigationExecutor, execute_plan
from spectre.agent.planner import (
    ExtractedEntity,
    InvestigationDepth,
    InvestigationPlan,
    InvestigationPlanner,
    PluginTask,
)
from spectre.plugins.base import EntityType
from spectre.plugins.registry import PluginRegistry, get_registry, reset_registry


@pytest.fixture
def registry() -> PluginRegistry:
    """Get a fresh plugin registry."""
    reset_registry()
    reg = get_registry()
    return reg


class TestRuleBasedPlanning:
    """Tests for rule-based (non-LLM) planning."""

    def test_plan_domain_investigation(self, registry: PluginRegistry) -> None:
        """Test planning a domain investigation without LLM."""
        planner = InvestigationPlanner(llm_client=None, registry=registry)  # type: ignore
        plan = planner.plan_sync("Investigate example.com", InvestigationDepth.STANDARD)

        assert plan.query == "Investigate example.com"
        assert plan.depth == InvestigationDepth.STANDARD
        assert len(plan.entities) >= 1
        assert plan.entities[0].type == EntityType.DOMAIN
        assert plan.entities[0].value == "example.com"
        assert len(plan.tasks) >= 1

    def test_plan_extracts_ip(self, registry: PluginRegistry) -> None:
        """Test that planner extracts IP addresses."""
        planner = InvestigationPlanner(llm_client=None, registry=registry)  # type: ignore
        plan = planner.plan_sync("Check 8.8.8.8 and 1.1.1.1", InvestigationDepth.STANDARD)

        ip_entities = [e for e in plan.entities if e.type == EntityType.IP_ADDRESS]
        assert len(ip_entities) == 2
        values = {e.value for e in ip_entities}
        assert "8.8.8.8" in values
        assert "1.1.1.1" in values

    def test_plan_extracts_email(self, registry: PluginRegistry) -> None:
        """Test that planner extracts email addresses."""
        planner = InvestigationPlanner(llm_client=None, registry=registry)  # type: ignore
        plan = planner.plan_sync("Find info about admin@example.com", InvestigationDepth.STANDARD)

        email_entities = [e for e in plan.entities if e.type == EntityType.EMAIL]
        assert len(email_entities) == 1
        assert email_entities[0].value == "admin@example.com"

    def test_plan_execution_order(self, registry: PluginRegistry) -> None:
        """Test that execution order respects dependencies."""
        # Create a plan with dependencies
        entities = [
            ExtractedEntity(type=EntityType.DOMAIN, value="example.com"),
        ]
        tasks = [
            PluginTask(
                plugin_name="dns_recon",
                entity=entities[0],
                priority=0,
                depends_on=[],
            ),
            PluginTask(
                plugin_name="whois_lookup",
                entity=entities[0],
                priority=0,
                depends_on=[],
            ),
        ]

        plan = InvestigationPlan(
            query="test",
            entities=entities,
            tasks=tasks,
            depth=InvestigationDepth.STANDARD,
        )

        waves = plan.get_execution_order()
        # Both tasks should be in the same wave (no dependencies)
        assert len(waves) == 1
        assert len(waves[0]) == 2


class TestExecutorUnit:
    """Unit tests for the executor."""

    @pytest.mark.asyncio
    async def test_execute_single_plugin(self, registry: PluginRegistry) -> None:
        """Test executing a single plugin directly."""
        executor = InvestigationExecutor(registry)

        result = await executor.execute_single_plugin(
            plugin_name="dns_recon",
            entity_type="domain",
            entity_value="google.com",
        )

        assert result.success is True
        assert result.plugin_name == "dns_recon"
        assert len(result.findings) > 0


class TestFullInvestigationWorkflow:
    """Full integration tests for the investigation workflow."""

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_full_domain_investigation(self, registry: PluginRegistry) -> None:
        """Test a full domain investigation: plan -> execute -> correlate."""
        # Step 1: Plan
        planner = InvestigationPlanner(llm_client=None, registry=registry)  # type: ignore
        plan = planner.plan_sync("Investigate google.com", InvestigationDepth.STANDARD)

        assert len(plan.entities) >= 1
        assert len(plan.tasks) >= 1

        # Step 2: Execute
        executor = InvestigationExecutor(
            registry,
            config=ExecutorConfig(
                max_retries=1,
                task_timeout_seconds=30,
            ),
        )
        execution_result = await executor.execute(plan)

        assert execution_result.success_count >= 1
        assert len(execution_result.all_results) >= 1

        # Step 3: Correlate
        correlation_result = correlate_results(execution_result)

        assert len(correlation_result.entities) >= 1
        assert correlation_result.total_findings > 0

        # Should have discovered IPs from DNS
        ip_entities = correlation_result.get_entities_by_type(EntityType.IP_ADDRESS)
        assert len(ip_entities) >= 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_execute_with_subdomain_enum(self, registry: PluginRegistry) -> None:
        """Test investigation with subdomain enumeration."""
        # Create a focused plan with subdomain_enum
        entities = [
            ExtractedEntity(type=EntityType.DOMAIN, value="github.com"),
        ]
        tasks = [
            PluginTask(
                plugin_name="subdomain_enum",
                entity=entities[0],
                priority=0,
            ),
        ]

        plan = InvestigationPlan(
            query="Find subdomains of github.com",
            entities=entities,
            tasks=tasks,
            depth=InvestigationDepth.STANDARD,
        )

        execution_result = await execute_plan(plan, registry)

        assert execution_result.success_count >= 1

        # Check that the plugin ran (may not find subdomains due to network issues)
        for result in execution_result.all_results:
            if result.plugin_name == "subdomain_enum" and result.success:
                # Plugin should return at least a summary finding
                assert len(result.findings) >= 1
                break

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_correlation_builds_relationships(self, registry: PluginRegistry) -> None:
        """Test that correlation builds entity relationships."""
        # Execute DNS recon for a domain
        executor = InvestigationExecutor(registry)
        result = await executor.execute_single_plugin(
            plugin_name="dns_recon",
            entity_type="domain",
            entity_value="google.com",
        )

        # Create a mock execution result
        from spectre.agent.executor import ExecutionResult, TaskExecution, TaskStatus
        from spectre.agent.planner import ExtractedEntity, InvestigationPlan, PluginTask

        entity = ExtractedEntity(type=EntityType.DOMAIN, value="google.com")
        task = PluginTask(plugin_name="dns_recon", entity=entity)
        execution = TaskExecution(task=task, status=TaskStatus.COMPLETED, result=result)

        plan = InvestigationPlan(
            query="test",
            entities=[entity],
            tasks=[task],
            depth=InvestigationDepth.STANDARD,
        )

        exec_result = ExecutionResult(
            plan=plan,
            executions=[execution],
            success_count=1,
            failure_count=0,
            skip_count=0,
        )

        # Correlate
        correlator = Correlator()
        correlation = correlator.correlate(exec_result)

        # Should have relationships from DNS records
        assert len(correlation.relationships) > 0

        # Check for resolves_to relationships
        resolves_to = [r for r in correlation.relationships if r.relationship_type == "resolves_to"]
        assert len(resolves_to) > 0


class TestExecutorErrorHandling:
    """Test executor error handling and retries."""

    @pytest.mark.asyncio
    async def test_handles_plugin_not_found(self, registry: PluginRegistry) -> None:
        """Test that executor handles missing plugins gracefully."""
        entities = [
            ExtractedEntity(type=EntityType.DOMAIN, value="example.com"),
        ]
        tasks = [
            PluginTask(
                plugin_name="nonexistent_plugin",
                entity=entities[0],
                priority=0,
            ),
        ]

        plan = InvestigationPlan(
            query="test",
            entities=entities,
            tasks=tasks,
            depth=InvestigationDepth.STANDARD,
        )

        executor = InvestigationExecutor(registry)
        result = await executor.execute(plan)

        assert result.failure_count == 1
        assert result.success_count == 0

    @pytest.mark.asyncio
    async def test_respects_fail_fast(self, registry: PluginRegistry) -> None:
        """Test fail_fast stops execution on first failure."""
        entities = [
            ExtractedEntity(type=EntityType.DOMAIN, value="example.com"),
        ]
        tasks = [
            PluginTask(
                plugin_name="nonexistent_plugin",
                entity=entities[0],
                priority=0,
                task_id="task1",
            ),
            PluginTask(
                plugin_name="dns_recon",
                entity=entities[0],
                priority=1,
                depends_on=["task1"],
                task_id="task2",
            ),
        ]

        plan = InvestigationPlan(
            query="test",
            entities=entities,
            tasks=tasks,
            depth=InvestigationDepth.STANDARD,
        )

        executor = InvestigationExecutor(
            registry,
            config=ExecutorConfig(fail_fast=True),
        )
        result = await executor.execute(plan)

        # Second task should be skipped due to dependency failure
        assert result.failure_count >= 1
        assert result.skip_count >= 1 or result.failure_count == 2
