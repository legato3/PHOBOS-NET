import threading
import time
from typing import Dict, Optional

from app.services.change_timeline import record_change
from app.services.timeline.model import TimelineEvent
from app.services.timeline.store import get_timeline_store

_STALE_AFTER_S = 3600

_state_lock = threading.Lock()
_source_state: Dict[str, Dict[str, Optional[object]]] = {
    "netflow": {"last_seen": None, "active": None},
    "syslog_514": {"last_seen": None, "active": None},
    "syslog_515": {"last_seen": None, "active": None},
    "firewall_stream": {"last_seen": None, "active": None},
}


def _emit_event(event: TimelineEvent) -> None:
    get_timeline_store().add_event(event)


def record_netflow_activity(
    ts: Optional[float] = None, count: Optional[int] = None
) -> None:
    now_ts = int(ts or time.time())
    with _state_lock:
        state = _source_state["netflow"]
        state["last_seen"] = now_ts
        if state.get("active") is True:
            return
        state["active"] = True
    meta = {"count": count} if count is not None else {}
    _emit_event(
        TimelineEvent(
            ts=now_ts,
            type="netflow_active",
            severity="info",
            title="NetFlow ingestion active",
            detail=None,
            source="netflow",
            meta=meta,
        )
    )
    record_change(
        source="netflow",
        title="NetFlow active",
        detail="Ingestion resumed",
        level="info",
        ts=now_ts,
        key="netflow_active",
    )


def record_syslog_activity(port: int, ts: Optional[float] = None) -> None:
    now_ts = int(ts or time.time())
    key = "syslog_514" if int(port) == 514 else "syslog_515"
    with _state_lock:
        state = _source_state[key]
        state["last_seen"] = now_ts
        if state.get("active") is True:
            return
        state["active"] = True
    _emit_event(
        TimelineEvent(
            ts=now_ts,
            type="syslog_active",
            severity="info",
            title=f"Syslog receiver active (port {port})",
            detail=None,
            source="syslog",
            meta={"port": int(port)},
        )
    )
    record_change(
        source="syslog",
        title="Syslog active",
        detail=f"Port {int(port)} receiving",
        level="info",
        ts=now_ts,
        key=f"syslog_active_{int(port)}",
    )


def record_firewall_stream_activity(ts: Optional[float] = None) -> None:
    now_ts = int(ts or time.time())
    should_emit = False
    with _state_lock:
        state = _source_state["firewall_stream"]
        last_seen = state.get("last_seen")
        stale = last_seen is None or (now_ts - int(last_seen) > _STALE_AFTER_S)
        state["last_seen"] = now_ts
        if stale:
            should_emit = True
            state["active"] = True
    if should_emit:
        _emit_event(
            TimelineEvent(
                ts=now_ts,
                type="firewall_stream_active",
                severity="notice",
                title="Firewall stream active",
                detail=None,
                source="firewall",
                meta={},
            )
        )
        record_change(
            source="firewall",
            title="Firewall log stream active",
            detail="Recent firewall activity detected",
            level="notice",
            ts=now_ts,
            key="firewall_stream_active",
        )


def emit_snmp_transition(
    available: bool, host: str, ts: Optional[float] = None, error: Optional[str] = None
) -> None:
    now_ts = int(ts or time.time())
    if available:
        _emit_event(
            TimelineEvent(
                ts=now_ts,
                type="snmp_reachable",
                severity="notice",
                title="Firewall SNMP reachable",
                detail=None,
                source="snmp",
                meta={"host": host, "state": "reachable"},
            )
        )
        record_change(
            source="snmp",
            title="SNMP reachable",
            detail="Polling resumed",
            level="notice",
            ts=now_ts,
            key="snmp_reachable",
        )
    else:
        _emit_event(
            TimelineEvent(
                ts=now_ts,
                type="snmp_unreachable",
                severity="warn",
                title="Firewall SNMP unreachable",
                detail=None,
                source="snmp",
                meta={
                    "host": host,
                    "state": "unreachable",
                    "error": error or "UNKNOWN",
                },
            )
        )
        record_change(
            source="snmp",
            title="SNMP unreachable",
            detail="Polling failed",
            level="warn",
            ts=now_ts,
            key="snmp_unreachable",
        )


def emit_system_event(
    event_type: str,
    title: str,
    detail: Optional[str] = None,
    ts: Optional[float] = None,
) -> None:
    now_ts = int(ts or time.time())
    _emit_event(
        TimelineEvent(
            ts=now_ts,
            type=event_type,
            severity="info",
            title=title,
            detail=detail,
            source="system",
            meta={},
        )
    )
    record_change(
        source="system",
        title=title,
        detail=detail,
        level="info",
        ts=now_ts,
        key=f"system_{event_type}",
    )


def check_stale_transitions(now_ts: Optional[float] = None) -> None:
    now_ts = int(now_ts or time.time())
    stale_events = []
    with _state_lock:
        for key, state in _source_state.items():
            if key == "firewall_stream":
                continue
            last_seen = state.get("last_seen")
            active = state.get("active")
            if last_seen is None or active is False:
                continue
            if now_ts - int(last_seen) <= _STALE_AFTER_S:
                continue
            state["active"] = False
            stale_events.append((key, int(last_seen)))

    for key, last_seen in stale_events:
        if key == "netflow":
            _emit_event(
                TimelineEvent(
                    ts=now_ts,
                    type="netflow_inactive",
                    severity="notice",
                    title="NetFlow ingestion inactive (stale)",
                    detail=None,
                    source="netflow",
                    meta={"last_seen_ts": last_seen},
                )
            )
            record_change(
                source="netflow",
                title="NetFlow inactive",
                detail="No recent flow files",
                level="notice",
                ts=now_ts,
                key="netflow_inactive",
            )
        elif key == "syslog_514":
            _emit_event(
                TimelineEvent(
                    ts=now_ts,
                    type="syslog_inactive",
                    severity="notice",
                    title="Syslog receiver inactive (stale) (port 514)",
                    detail=None,
                    source="syslog",
                    meta={"port": 514, "last_seen_ts": last_seen},
                )
            )
            record_change(
                source="syslog",
                title="Syslog inactive",
                detail="Port 514 silent",
                level="notice",
                ts=now_ts,
                key="syslog_inactive_514",
            )
        elif key == "syslog_515":
            _emit_event(
                TimelineEvent(
                    ts=now_ts,
                    type="syslog_inactive",
                    severity="notice",
                    title="Syslog receiver inactive (stale) (port 515)",
                    detail=None,
                    source="syslog",
                    meta={"port": 515, "last_seen_ts": last_seen},
                )
            )
            record_change(
                source="syslog",
                title="Syslog inactive",
                detail="Port 515 silent",
                level="notice",
                ts=now_ts,
                key="syslog_inactive_515",
            )
