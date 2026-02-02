"""
Agent Core - Orchestration engine for SPECTRE.

The agent core handles:
- LLM-powered investigation planning
- Plugin execution with dependency resolution
- Cross-source entity correlation
- Report generation
"""

from spectre.agent.correlator import (
    CorrelatedEntity,
    CorrelationResult,
    Correlator,
    EntityRelationship,
    correlate_results,
)
from spectre.agent.executor import (
    ExecutionResult,
    ExecutorConfig,
    InvestigationExecutor,
    TaskExecution,
    TaskStatus,
    execute_plan,
)
from spectre.agent.llm import (
    BaseLLMClient,
    ClaudeClient,
    LLMConfig,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    OllamaClient,
    OpenAIClient,
    create_llm_client,
)
from spectre.agent.planner import (
    ExtractedEntity,
    InvestigationDepth,
    InvestigationPlan,
    InvestigationPlanner,
    PluginTask,
)

__all__ = [
    # LLM
    "LLMProvider",
    "LLMConfig",
    "LLMMessage",
    "LLMResponse",
    "BaseLLMClient",
    "ClaudeClient",
    "OpenAIClient",
    "OllamaClient",
    "create_llm_client",
    # Planner
    "InvestigationDepth",
    "ExtractedEntity",
    "PluginTask",
    "InvestigationPlan",
    "InvestigationPlanner",
    # Executor
    "TaskStatus",
    "TaskExecution",
    "ExecutionResult",
    "ExecutorConfig",
    "InvestigationExecutor",
    "execute_plan",
    # Correlator
    "CorrelatedEntity",
    "EntityRelationship",
    "CorrelationResult",
    "Correlator",
    "correlate_results",
]
