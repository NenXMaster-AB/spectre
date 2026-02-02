"""
Investigation Executor

Executes investigation plans by running plugins with
dependency resolution, retry logic, and parallel execution.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from spectre.agent.planner import InvestigationPlan, PluginTask
from spectre.plugins.base import PluginConfig, PluginResult
from spectre.plugins.registry import PluginNotFoundError, PluginRegistry

logger = structlog.get_logger(__name__)


class TaskStatus(str, Enum):
    """Status of a task execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TaskExecution:
    """Tracks execution of a single task."""

    task: PluginTask
    status: TaskStatus = TaskStatus.PENDING
    result: PluginResult | None = None
    error: str | None = None
    start_time: float | None = None
    end_time: float | None = None
    retries: int = 0

    @property
    def duration_ms(self) -> float:
        """Get execution duration in milliseconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0


@dataclass
class ExecutionResult:
    """Result of executing an investigation plan."""

    plan: InvestigationPlan
    executions: list[TaskExecution]
    total_duration_ms: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    skip_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def all_results(self) -> list[PluginResult]:
        """Get all successful plugin results."""
        return [e.result for e in self.executions if e.result is not None]

    def get_execution(self, task_id: str) -> TaskExecution | None:
        """Get execution by task ID."""
        for e in self.executions:
            if e.task.task_id == task_id:
                return e
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan": self.plan.to_dict(),
            "executions": [
                {
                    "task_id": e.task.task_id,
                    "plugin": e.task.plugin_name,
                    "status": e.status.value,
                    "duration_ms": e.duration_ms,
                    "retries": e.retries,
                    "error": e.error,
                    "findings_count": len(e.result.findings) if e.result else 0,
                }
                for e in self.executions
            ],
            "summary": {
                "total_duration_ms": self.total_duration_ms,
                "success_count": self.success_count,
                "failure_count": self.failure_count,
                "skip_count": self.skip_count,
                "success_rate": self.success_rate,
            },
        }


@dataclass
class ExecutorConfig:
    """Configuration for the executor."""

    max_retries: int = 2
    retry_delay_seconds: float = 1.0
    task_timeout_seconds: float = 60.0
    max_concurrent_tasks: int = 5
    fail_fast: bool = False  # Stop on first failure


class InvestigationExecutor:
    """
    Executes investigation plans.

    Handles plugin execution with:
    - Dependency resolution
    - Parallel execution
    - Retry logic
    - Timeout handling
    """

    def __init__(
        self,
        registry: PluginRegistry,
        config: ExecutorConfig | None = None,
        plugin_config: PluginConfig | None = None,
    ) -> None:
        """Initialize the executor."""
        self.registry = registry
        self.config = config or ExecutorConfig()
        self.plugin_config = plugin_config

    async def execute(self, plan: InvestigationPlan) -> ExecutionResult:
        """
        Execute an investigation plan.

        Args:
            plan: The investigation plan to execute

        Returns:
            ExecutionResult with all task executions
        """
        logger.info(
            "Starting investigation execution",
            query=plan.query,
            task_count=len(plan.tasks),
            depth=plan.depth.value,
        )

        start_time = time.time()
        executions: dict[str, TaskExecution] = {}

        # Initialize executions
        for task in plan.tasks:
            executions[task.task_id] = TaskExecution(task=task)

        # Get execution waves (tasks that can run in parallel)
        waves = plan.get_execution_order()

        for wave_idx, wave in enumerate(waves):
            logger.debug(
                "Executing wave",
                wave=wave_idx + 1,
                tasks=[t.task_id for t in wave],
            )

            # Execute tasks in parallel (with concurrency limit)
            semaphore = asyncio.Semaphore(self.config.max_concurrent_tasks)

            async def run_with_semaphore(task: PluginTask) -> None:
                async with semaphore:
                    await self._execute_task(task, executions)

            await asyncio.gather(
                *[run_with_semaphore(task) for task in wave],
                return_exceptions=True,
            )

            # Check for fail-fast
            if self.config.fail_fast:
                failed = [e for e in executions.values() if e.status == TaskStatus.FAILED]
                if failed:
                    logger.warning("Fail-fast triggered, stopping execution")
                    # Mark remaining as skipped
                    for remaining_wave in waves[wave_idx + 1:]:
                        for task in remaining_wave:
                            if executions[task.task_id].status == TaskStatus.PENDING:
                                executions[task.task_id].status = TaskStatus.SKIPPED
                    break

        # Build result
        total_duration = (time.time() - start_time) * 1000
        execution_list = list(executions.values())

        result = ExecutionResult(
            plan=plan,
            executions=execution_list,
            total_duration_ms=total_duration,
            success_count=sum(1 for e in execution_list if e.status == TaskStatus.COMPLETED),
            failure_count=sum(1 for e in execution_list if e.status == TaskStatus.FAILED),
            skip_count=sum(1 for e in execution_list if e.status == TaskStatus.SKIPPED),
        )

        logger.info(
            "Investigation execution complete",
            duration_ms=total_duration,
            success=result.success_count,
            failed=result.failure_count,
            skipped=result.skip_count,
        )

        return result

    async def _execute_task(
        self,
        task: PluginTask,
        executions: dict[str, TaskExecution],
    ) -> None:
        """Execute a single task with retry logic."""
        execution = executions[task.task_id]

        # Check dependencies
        for dep_id in task.depends_on:
            dep_execution = executions.get(dep_id)
            if dep_execution and dep_execution.status != TaskStatus.COMPLETED:
                logger.warning(
                    "Skipping task due to failed dependency",
                    task=task.task_id,
                    dependency=dep_id,
                )
                execution.status = TaskStatus.SKIPPED
                execution.error = f"Dependency {dep_id} not completed"
                return

        # Get the plugin
        try:
            plugin = self.registry.get_plugin(task.plugin_name)
        except PluginNotFoundError as e:
            execution.status = TaskStatus.FAILED
            execution.error = str(e)
            return

        # Build entity dict for plugin
        entity = {
            "type": task.entity.type.value,
            "value": task.entity.value,
        }

        # Execute with retries
        execution.status = TaskStatus.RUNNING
        execution.start_time = time.time()

        last_error: str | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                # Execute with timeout
                result = await asyncio.wait_for(
                    plugin.execute(entity, self.plugin_config),
                    timeout=self.config.task_timeout_seconds,
                )

                execution.result = result
                execution.status = TaskStatus.COMPLETED
                execution.end_time = time.time()

                logger.debug(
                    "Task completed",
                    task=task.task_id,
                    findings=len(result.findings),
                    duration_ms=execution.duration_ms,
                )
                return

            except asyncio.TimeoutError:
                last_error = f"Task timed out after {self.config.task_timeout_seconds}s"
                logger.warning(
                    "Task timeout",
                    task=task.task_id,
                    attempt=attempt + 1,
                )

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "Task failed",
                    task=task.task_id,
                    attempt=attempt + 1,
                    error=str(e),
                )

            execution.retries = attempt + 1

            # Wait before retry (except on last attempt)
            if attempt < self.config.max_retries:
                await asyncio.sleep(self.config.retry_delay_seconds)

        # All retries exhausted
        execution.status = TaskStatus.FAILED
        execution.error = last_error
        execution.end_time = time.time()

    async def execute_single_plugin(
        self,
        plugin_name: str,
        entity_type: str,
        entity_value: str,
    ) -> PluginResult:
        """
        Execute a single plugin directly (without a full plan).

        Args:
            plugin_name: Name of the plugin to execute
            entity_type: Type of the entity
            entity_value: Value of the entity

        Returns:
            PluginResult from the plugin
        """
        plugin = self.registry.get_plugin(plugin_name)
        entity = {"type": entity_type, "value": entity_value}

        return await plugin.execute(entity, self.plugin_config)


async def execute_plan(
    plan: InvestigationPlan,
    registry: PluginRegistry,
    config: ExecutorConfig | None = None,
) -> ExecutionResult:
    """
    Convenience function to execute a plan.

    Args:
        plan: Investigation plan to execute
        registry: Plugin registry
        config: Optional executor configuration

    Returns:
        ExecutionResult with all results
    """
    executor = InvestigationExecutor(registry, config)
    return await executor.execute(plan)
