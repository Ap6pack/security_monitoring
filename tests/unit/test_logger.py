# Copyright (c) 2024 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the logger module."""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import structlog

from security_scanner.utils.logger import (
    add_app_context,
    drop_color_message_key,
    get_logger,
    setup_logging,
)


class TestAddAppContext:
    """Test the add_app_context processor."""

    def test_adds_app_key(self) -> None:
        """Test that the 'app' key is added to the event dict."""
        event_dict = {"event": "something happened", "level": "info"}
        result = add_app_context(MagicMock(), "info", event_dict)

        assert "app" in result
        assert result["app"] == "security-scanner"

    def test_preserves_existing_keys(self) -> None:
        """Test that existing keys in the event dict are preserved."""
        event_dict = {"event": "test", "extra": "data", "count": 42}
        result = add_app_context(MagicMock(), "info", event_dict)

        assert result["event"] == "test"
        assert result["extra"] == "data"
        assert result["count"] == 42
        assert result["app"] == "security-scanner"

    def test_overwrites_existing_app_key(self) -> None:
        """Test that an existing 'app' key gets overwritten."""
        event_dict = {"event": "test", "app": "old-value"}
        result = add_app_context(MagicMock(), "info", event_dict)

        assert result["app"] == "security-scanner"


class TestDropColorMessageKey:
    """Test the drop_color_message_key processor."""

    def test_removes_color_message_key(self) -> None:
        """Test that 'color_message' key is removed from event dict."""
        event_dict = {
            "event": "test",
            "color_message": "\x1b[32mtest\x1b[0m",
        }
        result = drop_color_message_key(MagicMock(), "info", event_dict)

        assert "color_message" not in result
        assert result["event"] == "test"

    def test_idempotent_when_key_absent(self) -> None:
        """Test that calling when 'color_message' is absent does nothing."""
        event_dict = {"event": "test", "level": "info"}
        result = drop_color_message_key(MagicMock(), "info", event_dict)

        assert "color_message" not in result
        assert result["event"] == "test"
        assert result["level"] == "info"

    def test_preserves_other_keys(self) -> None:
        """Test that other keys are untouched when color_message is removed."""
        event_dict = {
            "event": "test",
            "color_message": "colored",
            "extra": "data",
            "count": 5,
        }
        result = drop_color_message_key(MagicMock(), "info", event_dict)

        assert "color_message" not in result
        assert result["extra"] == "data"
        assert result["count"] == 5


class TestSetupLogging:
    """Test the setup_logging function."""

    def setup_method(self) -> None:
        """Reset logging state before each test."""
        # Reset structlog configuration
        structlog.reset_defaults()
        # Remove all handlers from root logger except the default
        root = logging.getLogger()
        for handler in root.handlers[:]:
            root.removeHandler(handler)

    def test_console_format(self) -> None:
        """Test setup_logging with console format."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_level="INFO", log_format="console")

            mock_configure.assert_called_once()
            call_kwargs = mock_configure.call_args[1]
            processors = call_kwargs["processors"]

            # Console format should use ConsoleRenderer as the last processor
            last_processor = processors[-1]
            assert isinstance(last_processor, structlog.dev.ConsoleRenderer)

    def test_json_format(self) -> None:
        """Test setup_logging with JSON format."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_level="INFO", log_format="json")

            mock_configure.assert_called_once()
            call_kwargs = mock_configure.call_args[1]
            processors = call_kwargs["processors"]

            # JSON format should use JSONRenderer as the last processor
            last_processor = processors[-1]
            assert isinstance(last_processor, structlog.processors.JSONRenderer)

            # JSON format should include drop_color_message_key
            assert drop_color_message_key in processors

    def test_json_format_includes_drop_color_message(self) -> None:
        """Test that JSON format includes the drop_color_message_key processor."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_format="json")

            call_kwargs = mock_configure.call_args[1]
            processors = call_kwargs["processors"]
            assert drop_color_message_key in processors

    def test_console_format_excludes_drop_color_message(self) -> None:
        """Test that console format does not include drop_color_message_key."""
        with patch("structlog.configure") as mock_configure:
            setup_logging(log_format="console")

            call_kwargs = mock_configure.call_args[1]
            processors = call_kwargs["processors"]
            assert drop_color_message_key not in processors

    def test_log_level_info(self) -> None:
        """Test that INFO log level is passed to basicConfig."""
        with patch("security_scanner.utils.logger.logging.basicConfig") as mock_basic:
            setup_logging(log_level="INFO")

            mock_basic.assert_called_once()
            assert mock_basic.call_args[1]["level"] == logging.INFO

    def test_log_level_debug(self) -> None:
        """Test that DEBUG log level is passed to basicConfig."""
        with patch("security_scanner.utils.logger.logging.basicConfig") as mock_basic:
            setup_logging(log_level="DEBUG")

            mock_basic.assert_called_once()
            assert mock_basic.call_args[1]["level"] == logging.DEBUG

    def test_log_level_warning(self) -> None:
        """Test that WARNING log level is passed to basicConfig."""
        with patch("security_scanner.utils.logger.logging.basicConfig") as mock_basic:
            setup_logging(log_level="WARNING")

            mock_basic.assert_called_once()
            assert mock_basic.call_args[1]["level"] == logging.WARNING

    def test_log_level_error(self) -> None:
        """Test that ERROR log level is passed to basicConfig."""
        with patch("security_scanner.utils.logger.logging.basicConfig") as mock_basic:
            setup_logging(log_level="ERROR")

            mock_basic.assert_called_once()
            assert mock_basic.call_args[1]["level"] == logging.ERROR

    def test_debug_flag_overrides_level(self) -> None:
        """Test that debug=True forces DEBUG level regardless of log_level."""
        with patch("security_scanner.utils.logger.logging.basicConfig") as mock_basic:
            setup_logging(log_level="ERROR", debug=True)

            mock_basic.assert_called_once()
            assert mock_basic.call_args[1]["level"] == logging.DEBUG

    def test_with_log_file(self, tmp_path: Path) -> None:
        """Test setup_logging creates a file handler for a log file."""
        log_file = tmp_path / "logs" / "test.log"

        setup_logging(log_level="INFO", log_file=log_file)

        # The log directory should have been created
        assert log_file.parent.exists()

        # A FileHandler should have been added to the root logger
        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

        # Cleanup
        for h in file_handlers:
            root.removeHandler(h)
            h.close()

    def test_with_log_file_json_format(self, tmp_path: Path) -> None:
        """Test log file handler uses correct formatter for JSON format."""
        log_file = tmp_path / "logs" / "test.log"

        setup_logging(log_level="INFO", log_file=log_file, log_format="json")

        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

        # JSON format should use simple "%(message)s" formatter
        handler = file_handlers[0]
        assert handler.formatter._fmt == "%(message)s"

        # Cleanup
        for h in file_handlers:
            root.removeHandler(h)
            h.close()

    def test_with_log_file_console_format(self, tmp_path: Path) -> None:
        """Test log file handler uses correct formatter for console format."""
        log_file = tmp_path / "logs" / "test.log"

        setup_logging(log_level="INFO", log_file=log_file, log_format="console")

        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) >= 1

        handler = file_handlers[0]
        assert "asctime" in handler.formatter._fmt
        assert "levelname" in handler.formatter._fmt

        # Cleanup
        for h in file_handlers:
            root.removeHandler(h)
            h.close()

    def test_without_log_file(self) -> None:
        """Test setup_logging without a log file adds no FileHandler."""
        setup_logging(log_level="INFO", log_file=None)

        root = logging.getLogger()
        file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert len(file_handlers) == 0

    def test_third_party_loggers_silenced(self) -> None:
        """Test that noisy third-party library loggers are set to WARNING."""
        setup_logging(log_level="DEBUG")

        assert logging.getLogger("aiohttp").level == logging.WARNING
        assert logging.getLogger("asyncio").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_structlog_configured_with_bound_logger(self) -> None:
        """Test that structlog is configured with BoundLogger wrapper."""
        with patch("structlog.configure") as mock_configure:
            setup_logging()

            call_kwargs = mock_configure.call_args[1]
            assert call_kwargs["wrapper_class"] is structlog.stdlib.BoundLogger

    def test_common_processors_included(self) -> None:
        """Test that common processors are included in all formats."""
        for fmt in ("console", "json"):
            with patch("structlog.configure") as mock_configure:
                setup_logging(log_format=fmt)

                call_kwargs = mock_configure.call_args[1]
                processors = call_kwargs["processors"]
                assert add_app_context in processors


class TestGetLogger:
    """Test the get_logger function."""

    def test_creates_logger_with_name(self) -> None:
        """Test that get_logger creates a logger with the specified name."""
        logger = get_logger("test.module")

        # structlog returns a BoundLogger proxy; verify it works
        assert logger is not None

    def test_creates_logger_without_name(self) -> None:
        """Test that get_logger works without a name."""
        logger = get_logger()

        assert logger is not None

    def test_logger_with_initial_values(self) -> None:
        """Test that get_logger binds initial values to the logger."""
        with patch("structlog.get_logger") as mock_get_logger:
            mock_bound = MagicMock()
            mock_bound.bind.return_value = mock_bound
            mock_get_logger.return_value = mock_bound

            logger = get_logger("test", component="scanner", version="1.0")

            mock_get_logger.assert_called_once_with("test")
            mock_bound.bind.assert_called_once_with(component="scanner", version="1.0")
            assert logger is mock_bound

    def test_logger_without_initial_values(self) -> None:
        """Test that get_logger does not call bind when no initial values given."""
        with patch("structlog.get_logger") as mock_get_logger:
            mock_bound = MagicMock()
            mock_get_logger.return_value = mock_bound

            logger = get_logger("test")

            mock_get_logger.assert_called_once_with("test")
            mock_bound.bind.assert_not_called()
            assert logger is mock_bound
