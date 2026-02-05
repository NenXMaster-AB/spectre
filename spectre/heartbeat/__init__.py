"""
Heartbeat Engine

Proactive monitoring and scheduling for SPECTRE.

Provides:
- Watch definitions for continuous monitoring
- Scheduler for periodic execution
- Diff detection for change tracking
- Alert routing to multiple channels
"""

from spectre.heartbeat.models import (
    Watch,
    WatchType,
    WatchStatus,
    WatchCondition,
    WatchResult,
    WatchResultChange,
    Alert,
    AlertChannel,
    AlertConfig,
    AlertSeverity,
)
from spectre.heartbeat.scheduler import (
    HeartbeatScheduler,
    get_scheduler,
)
from spectre.heartbeat.store import (
    WatchStore,
    get_watch_store,
)
from spectre.heartbeat.watchers import (
    WatchExecutor,
    get_watch_executor,
)
from spectre.heartbeat.alerts import (
    AlertRouter,
    get_alert_router,
)
from spectre.heartbeat.diff import (
    compute_diff,
    check_conditions,
)

__all__ = [
    # Models
    "Watch",
    "WatchType",
    "WatchStatus",
    "WatchCondition",
    "WatchResult",
    "WatchResultChange",
    "Alert",
    "AlertChannel",
    "AlertConfig",
    "AlertSeverity",
    # Scheduler
    "HeartbeatScheduler",
    "get_scheduler",
    # Store
    "WatchStore",
    "get_watch_store",
    # Executor
    "WatchExecutor",
    "get_watch_executor",
    # Alerts
    "AlertRouter",
    "get_alert_router",
    # Diff
    "compute_diff",
    "check_conditions",
]
