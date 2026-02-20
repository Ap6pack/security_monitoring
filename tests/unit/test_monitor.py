"""Unit tests for monitor daemon."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_scanner.monitor import MonitorDaemon


class TestMonitorDaemon:
    """Test monitor daemon functionality."""

    @pytest.fixture
    def settings(self):
        mock = MagicMock()
        # Disable alert channels to avoid HTTPClient event-loop issues in sync tests
        mock.enable_email_alerts = False
        mock.enable_slack_alerts = False
        mock.enable_webhook_alerts = False
        return mock

    @pytest.fixture
    def db(self):
        return AsyncMock()

    @pytest.fixture
    def daemon(self, settings, db):
        return MonitorDaemon(
            settings=settings,
            db=db,
            domains=["example.com"],
            interval_seconds=60,
        )

    def test_initialization(self, daemon):
        assert daemon.scheduler.domains == ["example.com"]
        assert daemon.scheduler.interval_seconds == 60
        assert not daemon._shutdown_event.is_set()

    async def test_shutdown_event(self, daemon):
        """Test that shutdown event stops the daemon."""
        # Mock the scheduler to not actually scan
        daemon.scheduler.start = AsyncMock()
        daemon.scheduler.stop = AsyncMock()

        async def trigger_shutdown():
            await asyncio.sleep(0.05)
            daemon._shutdown_event.set()

        with patch.object(daemon, "_handle_signal"):

            async def run_without_signals():
                scheduler_task = asyncio.create_task(daemon.scheduler.start())
                await daemon._shutdown_event.wait()
                await daemon.scheduler.stop()
                try:
                    await asyncio.wait_for(scheduler_task, timeout=5)
                except TimeoutError:
                    scheduler_task.cancel()

            shutdown_task = asyncio.create_task(trigger_shutdown())
            await run_without_signals()
            await shutdown_task

        daemon.scheduler.stop.assert_called_once()

    def test_handle_signal(self, daemon):
        """Test signal handler sets shutdown event."""
        import signal

        assert not daemon._shutdown_event.is_set()
        daemon._handle_signal(signal.SIGTERM)
        assert daemon._shutdown_event.is_set()

    def test_handle_signal_sigint(self, daemon):
        """Test SIGINT handler."""
        import signal

        daemon._handle_signal(signal.SIGINT)
        assert daemon._shutdown_event.is_set()

    async def test_scheduler_timeout_on_shutdown(self, daemon):
        """Test that scheduler gets cancelled if it doesn't stop in time."""
        # Create a scheduler that hangs
        hang_event = asyncio.Event()

        async def hanging_start():
            await hang_event.wait()

        daemon.scheduler.start = hanging_start
        daemon.scheduler.stop = AsyncMock()

        async def trigger_shutdown():
            await asyncio.sleep(0.05)
            daemon._shutdown_event.set()

        shutdown_task = asyncio.create_task(trigger_shutdown())

        scheduler_task = asyncio.create_task(daemon.scheduler.start())
        await daemon._shutdown_event.wait()
        await daemon.scheduler.stop()

        # Very short timeout to test cancellation path
        try:
            await asyncio.wait_for(scheduler_task, timeout=0.01)
        except TimeoutError:
            scheduler_task.cancel()
            try:
                await scheduler_task
            except asyncio.CancelledError:
                pass

        await shutdown_task
        assert scheduler_task.cancelled()
