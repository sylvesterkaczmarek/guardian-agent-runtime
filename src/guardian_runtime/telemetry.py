from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any


_EVENT_ATTRIBUTE = "guardian_event"


class JsonEventFormatter(logging.Formatter):
    """Format Guardian operational events as one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = getattr(record, _EVENT_ATTRIBUTE, None)
        if isinstance(event, Mapping):
            payload["event"] = dict(event)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured operational event without logging request payloads or secrets."""

    logger.info(event, extra={_EVENT_ATTRIBUTE: {"name": event, **fields}})
