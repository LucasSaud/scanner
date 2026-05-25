from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

LOG_DIR = Path.home() / ".scanner" / "logs"

try:
    import structlog

    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False


class TelemetryLogger:
    def __init__(self, enabled: bool = True, log_file: Optional[Path] = None,
                 log_level: str = "INFO"):
        self.enabled = enabled and HAS_STRUCTLOG
        self.log_file = log_file or (LOG_DIR / "scanner.log")
        self._logger: Optional[logging.Logger] = None
        if self.enabled:
            self._setup(log_level)
        else:
            self._logger = logging.getLogger("scanner")
            self._logger.addHandler(logging.NullHandler())

    def _setup(self, log_level: str) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer(),
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        level = getattr(logging, log_level.upper(), logging.INFO)
        handlers: list[logging.Handler] = [
            logging.FileHandler(str(self.log_file), encoding="utf-8"),
        ]
        if sys.stdout.isatty():
            handlers.append(logging.StreamHandler(sys.stdout))
        logging.basicConfig(
            format="%(message)s",
            level=level,
            handlers=handlers,
        )
        self._logger = logging.getLogger("scanner")

    def info(self, event: str, **kwargs) -> None:
        if not self._logger:
            return
        if HAS_STRUCTLOG:
            structlog.get_logger().info(event, **kwargs)
        else:
            self._logger.info(f"{event} {kwargs}")

    def warning(self, event: str, **kwargs) -> None:
        if not self._logger:
            return
        if HAS_STRUCTLOG:
            structlog.get_logger().warning(event, **kwargs)
        else:
            self._logger.warning(f"{event} {kwargs}")

    def error(self, event: str, **kwargs) -> None:
        if not self._logger:
            return
        if HAS_STRUCTLOG:
            structlog.get_logger().error(event, **kwargs)
        else:
            self._logger.error(f"{event} {kwargs}")

    def debug(self, event: str, **kwargs) -> None:
        if not self._logger:
            return
        if HAS_STRUCTLOG:
            structlog.get_logger().debug(event, **kwargs)
        else:
            self._logger.debug(f"{event} {kwargs}")


telemetry_logger = TelemetryLogger(enabled=True)
