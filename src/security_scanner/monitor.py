"""Monitoring daemon with signal handling and graceful shutdown."""

import asyncio
import contextlib
import signal

from security_scanner.alerters.manager import AlertManager
from security_scanner.config import Settings
from security_scanner.scheduler import ScanScheduler
from security_scanner.storage.database import DatabaseManager
from security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class MonitorDaemon:
    """Long-running monitoring daemon.

    Wraps the ScanScheduler with signal handling for graceful shutdown
    and provides lifecycle management.
    """

    def __init__(
        self,
        settings: Settings,
        db: DatabaseManager,
        domains: list[str],
        interval_seconds: int = 3600,
    ) -> None:
        alert_manager = AlertManager(settings=settings, db=db)
        self.scheduler = ScanScheduler(
            settings=settings,
            db=db,
            domains=domains,
            interval_seconds=interval_seconds,
            alert_manager=alert_manager if alert_manager.has_channels else None,
        )
        self._shutdown_event = asyncio.Event()

    async def run(self) -> None:
        """Run the monitoring daemon until interrupted."""
        loop = asyncio.get_running_loop()

        # Register signal handlers for graceful shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal, sig)

        logger.info(
            "Monitor daemon started",
            domains=self.scheduler.domains,
            interval=self.scheduler.interval_seconds,
        )

        # Run scheduler in a task so we can cancel it on shutdown
        scheduler_task = asyncio.create_task(self.scheduler.start())

        # Wait for shutdown signal
        await self._shutdown_event.wait()

        # Graceful shutdown
        logger.info("Initiating graceful shutdown...")
        await self.scheduler.stop()

        # Give the scheduler a chance to finish the current scan
        try:
            await asyncio.wait_for(scheduler_task, timeout=60)
        except TimeoutError:
            logger.warning("Scheduler did not stop within timeout, cancelling")
            scheduler_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scheduler_task

        logger.info(
            "Monitor daemon stopped",
            total_scans=self.scheduler.scan_count,
        )

    def _handle_signal(self, sig: signal.Signals) -> None:
        """Handle shutdown signals."""
        logger.info("Received signal", signal=sig.name)
        self._shutdown_event.set()
