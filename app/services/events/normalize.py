import uuid
from typing import Any, Dict, Optional

from app.services.events.model import EventRecord


def _coerce_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def normalize_timeline_event(event: Dict[str, object]) -> Optional[EventRecord]:
    try:
        source = str(event.get("source") or "system")
        if source == "filterlog":
            source = "firewall"
        title = str(event.get("title") or "Event")
        detail = event.get("detail")
        summary = str(detail) if detail else "State change observed"
        severity = str(event.get("severity") or "info")
        meta = event.get("meta") or {}
        if isinstance(meta, dict):
            for key in ["message", "raw", "raw_log", "line"]:
                if key in meta:
                    meta.pop(key, None)
        ts = _coerce_int(event.get("ts"))
        return EventRecord(
            id=str(uuid.uuid4()),
            ts=ts,
            source=source,
            severity=severity,
            title=title,
            summary=summary,
            tags=["ACTIVITY"],
            evidence=meta if isinstance(meta, dict) else {},
            rule_id=None,
            dedupe_key=None,
            window_sec=None,
            count=1,
            kind="activity",
        )
    except Exception:
        return None
