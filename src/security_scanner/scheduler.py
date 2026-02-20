"""Scan scheduling engine for continuous monitoring."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from security_scanner.config import Settings
from security_scanner.orchestrator import ScanOrchestrator
from security_scanner.storage.database import DatabaseManager
from security_scanner.utils.logger import get_logger

if TYPE_CHECKING:
    from security_scanner.alerters.manager import AlertManager

logger = get_logger(__name__)


class ScanScheduler:
    """Schedules and executes periodic security scans.

    Runs scans at a fixed interval, tracks results, and detects
    new or changed findings between consecutive runs.
    """

    def __init__(
        self,
        settings: Settings,
        db: DatabaseManager,
        domains: list[str],
        interval_seconds: int = 3600,
        alert_manager: AlertManager | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.domains = domains
        self.interval_seconds = interval_seconds
        self.alert_manager = alert_manager
        self._orchestrator: ScanOrchestrator | None = None
        self._running = False
        self._scan_count = 0
        self._last_scan_id: str | None = None

    async def start(self) -> None:
        """Start the scheduling loop."""
        self._running = True

        async with ScanOrchestrator(settings=self.settings, db=self.db) as orchestrator:
            self._orchestrator = orchestrator

            logger.info(
                "Scheduler started",
                domains=self.domains,
                interval=self.interval_seconds,
            )

            try:
                while self._running:
                    await self._run_scan()
                    if self._running:
                        logger.info(
                            "Next scan in",
                            seconds=self.interval_seconds,
                        )
                        await asyncio.sleep(self.interval_seconds)
            finally:
                self._orchestrator = None

    async def stop(self) -> None:
        """Signal the scheduler to stop after the current scan."""
        self._running = False
        logger.info("Scheduler stop requested")

    async def _run_scan(self) -> dict[str, Any] | None:
        """Execute a single scan cycle."""
        if self._orchestrator is None:
            raise RuntimeError("Scheduler not started")
        self._scan_count += 1
        scan_start = datetime.now(UTC)

        logger.info(
            "Starting scheduled scan",
            scan_number=self._scan_count,
            domains=self.domains,
        )

        try:
            result = await self._orchestrator.scan(self.domains)
            scan_id = result["scan_id"]
            findings = result["findings"]
            summary = result["summary"]

            # Delta detection: compare with previous scan
            new_findings = await self._detect_new_findings(findings)

            # Dispatch alerts for new findings
            if new_findings and self.alert_manager is not None:
                try:
                    await self.alert_manager.process_findings(new_findings, scan_id)
                except Exception:
                    logger.exception("Alert processing failed", scan_id=scan_id)

            logger.info(
                "Scheduled scan completed",
                scan_id=scan_id,
                scan_number=self._scan_count,
                total_findings=len(findings),
                new_findings=len(new_findings),
                summary=summary,
                duration=(datetime.now(UTC) - scan_start).total_seconds(),
            )

            self._last_scan_id = scan_id
            return result

        except Exception:
            logger.exception(
                "Scheduled scan failed",
                scan_number=self._scan_count,
            )
            return None

    async def _detect_new_findings(
        self,
        findings: list[Any],
    ) -> list[Any]:
        """Identify findings that are new since the last scan.

        A finding is considered "new" if no similar finding (same domain +
        same type) exists within the past 7 days.
        """
        new_findings = []

        for finding in findings:
            similar = await self.db.get_similar_findings(
                domain=finding.domain,
                finding_type=finding.type,
                days=7,
            )
            # If only this finding matches (the one we just stored), it's new
            if len(similar) <= 1:
                new_findings.append(finding)

        return new_findings

    @property
    def is_running(self) -> bool:
        """Whether the scheduler is currently running."""
        return self._running

    @property
    def scan_count(self) -> int:
        """Number of completed scan cycles."""
        return self._scan_count

    @property
    def last_scan_id(self) -> str | None:
        """ID of the most recent scan."""
        return self._last_scan_id
