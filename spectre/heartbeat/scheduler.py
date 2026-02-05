"""
Heartbeat Scheduler

APScheduler-based scheduler for running watches on schedule.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable, Awaitable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor

from spectre.heartbeat.models import Watch, WatchStatus

logger = structlog.get_logger(__name__)

# Type for watch executor callback
WatchExecutor = Callable[[Watch], Awaitable[None]]


class HeartbeatScheduler:
    """
    Manages scheduled execution of watches.

    Uses APScheduler to run watch jobs at configured intervals.
    Supports dynamic adding/removing of watches.
    """

    def __init__(self, executor: WatchExecutor | None = None) -> None:
        """
        Initialize the scheduler.

        Args:
            executor: Async function to execute watches. If None, must be set
                     before starting via set_executor().
        """
        self._executor = executor
        self._scheduler: AsyncIOScheduler | None = None
        self._watches: dict[str, Watch] = {}
        self._running = False

    def set_executor(self, executor: WatchExecutor) -> None:
        """Set the watch executor callback."""
        self._executor = executor

    def _create_scheduler(self) -> AsyncIOScheduler:
        """Create and configure the APScheduler instance."""
        jobstores = {
            "default": MemoryJobStore(),
        }
        executors = {
            "default": AsyncIOExecutor(),
        }
        job_defaults = {
            "coalesce": True,  # Combine missed runs into one
            "max_instances": 1,  # Only one instance of each job at a time
            "misfire_grace_time": 300,  # 5 minutes grace for missed jobs
        }

        return AsyncIOScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone="UTC",
        )

    async def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        if self._executor is None:
            raise RuntimeError("No executor set. Call set_executor() before start().")

        logger.info("Starting heartbeat scheduler")
        self._scheduler = self._create_scheduler()
        self._scheduler.start()
        self._running = True

        # Schedule any existing watches
        for watch in self._watches.values():
            if watch.status == WatchStatus.ACTIVE:
                self._schedule_watch(watch)

        logger.info("Heartbeat scheduler started", watch_count=len(self._watches))

    async def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if not self._running or self._scheduler is None:
            return

        logger.info("Stopping heartbeat scheduler")
        self._scheduler.shutdown(wait=True)
        self._scheduler = None
        self._running = False
        logger.info("Heartbeat scheduler stopped")

    @property
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running

    def add_watch(self, watch: Watch) -> None:
        """
        Add a watch to the scheduler.

        Args:
            watch: The watch to add
        """
        self._watches[watch.id] = watch

        if self._running and watch.status == WatchStatus.ACTIVE:
            self._schedule_watch(watch)

        logger.info(
            "Watch added",
            watch_id=watch.id,
            watch_name=watch.name,
            interval_minutes=watch.interval_minutes,
        )

    def remove_watch(self, watch_id: str) -> bool:
        """
        Remove a watch from the scheduler.

        Args:
            watch_id: ID of the watch to remove

        Returns:
            True if removed, False if not found
        """
        if watch_id not in self._watches:
            return False

        # Remove from scheduler if running
        if self._running and self._scheduler:
            try:
                self._scheduler.remove_job(watch_id)
            except Exception:
                pass  # Job might not exist

        del self._watches[watch_id]
        logger.info("Watch removed", watch_id=watch_id)
        return True

    def pause_watch(self, watch_id: str) -> bool:
        """Pause a watch."""
        if watch_id not in self._watches:
            return False

        watch = self._watches[watch_id]
        watch.pause()

        if self._running and self._scheduler:
            try:
                self._scheduler.pause_job(watch_id)
            except Exception:
                pass

        logger.info("Watch paused", watch_id=watch_id)
        return True

    def resume_watch(self, watch_id: str) -> bool:
        """Resume a paused watch."""
        if watch_id not in self._watches:
            return False

        watch = self._watches[watch_id]
        watch.resume()

        if self._running and self._scheduler:
            try:
                self._scheduler.resume_job(watch_id)
            except Exception:
                # Job might have been removed, re-schedule it
                self._schedule_watch(watch)

        logger.info("Watch resumed", watch_id=watch_id)
        return True

    def get_watch(self, watch_id: str) -> Watch | None:
        """Get a watch by ID."""
        return self._watches.get(watch_id)

    def list_watches(self, status: WatchStatus | None = None) -> list[Watch]:
        """
        List all watches, optionally filtered by status.

        Args:
            status: Filter by this status, or None for all

        Returns:
            List of watches
        """
        watches = list(self._watches.values())
        if status:
            watches = [w for w in watches if w.status == status]
        return sorted(watches, key=lambda w: w.created_at, reverse=True)

    def _schedule_watch(self, watch: Watch) -> None:
        """Schedule a watch for execution."""
        if self._scheduler is None:
            return

        # Determine when to run first
        if watch.next_run and watch.next_run > datetime.now(timezone.utc):
            # Schedule for the planned next run
            trigger = DateTrigger(run_date=watch.next_run)
        else:
            # Run soon, then on interval
            trigger = IntervalTrigger(
                minutes=watch.interval_minutes,
                start_date=datetime.now(timezone.utc),
            )

        try:
            self._scheduler.add_job(
                self._run_watch,
                trigger=trigger,
                id=watch.id,
                name=f"watch:{watch.name}",
                args=[watch.id],
                replace_existing=True,
            )
        except Exception as e:
            logger.error("Failed to schedule watch", watch_id=watch.id, error=str(e))

    async def _run_watch(self, watch_id: str) -> None:
        """
        Execute a watch.

        This is called by APScheduler when a watch is due.
        """
        watch = self._watches.get(watch_id)
        if not watch:
            logger.warning("Watch not found for execution", watch_id=watch_id)
            return

        if watch.status != WatchStatus.ACTIVE:
            logger.debug("Skipping inactive watch", watch_id=watch_id, status=watch.status)
            return

        logger.info("Executing watch", watch_id=watch_id, watch_name=watch.name)

        try:
            watch.mark_run_started()
            await self._executor(watch)
        except Exception as e:
            logger.error("Watch execution failed", watch_id=watch_id, error=str(e))
            watch.mark_run_failed(str(e))

        # Reschedule with interval trigger for subsequent runs
        if self._scheduler and watch.status == WatchStatus.ACTIVE:
            try:
                self._scheduler.reschedule_job(
                    watch_id,
                    trigger=IntervalTrigger(minutes=watch.interval_minutes),
                )
            except Exception:
                # Job might not exist, re-add it
                self._schedule_watch(watch)

    async def run_watch_now(self, watch_id: str) -> bool:
        """
        Manually trigger a watch to run immediately.

        Args:
            watch_id: ID of the watch to run

        Returns:
            True if triggered, False if not found
        """
        watch = self._watches.get(watch_id)
        if not watch:
            return False

        logger.info("Manually triggering watch", watch_id=watch_id)
        await self._run_watch(watch_id)
        return True

    def get_next_run_times(self) -> dict[str, datetime | None]:
        """Get next scheduled run time for all watches."""
        result = {}
        for watch_id, watch in self._watches.items():
            result[watch_id] = watch.next_run
        return result


# Global scheduler instance
_scheduler: HeartbeatScheduler | None = None


def get_scheduler() -> HeartbeatScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = HeartbeatScheduler()
    return _scheduler
