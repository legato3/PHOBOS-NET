import threading
import time
import uuid
from collections import deque, Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.config import PULSE_SIMULATE
from app.core import app_state
from app.core.app_state import get_dependency_health
from app.db.sqlite import _trends_db_connect, _trends_db_init
from app.services.events.store import fetch_events
from app.services.firewall.store import firewall_store
from app.services.shared.ingestion_metrics import ingestion_tracker
from app.services.shared.snmp import get_snmp_data
from app.services.syslog.firewall_listener import get_firewall_syslog_stats


@dataclass
class PulseEvent:
    id: str
    ts: int
    source: str
    severity: str
    kind: str
    title: str
    detail: str
    tags: List[str] = field(default_factory=list)
    entity: Optional[str] = None
    count: int = 1
    evidence: Dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""
    window_sec: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "source": self.source,
            "severity": self.severity,
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "tags": self.tags,
            "entity": self.entity,
            "count": self.count,
            "evidence": self.evidence,
            "dedupe_key": self.dedupe_key,
            "window_sec": self.window_sec,
        }


class PulseStore:
    def __init__(self, max_events: int = 800) -> None:
        self._max_events = max_events
        self._events: Dict[str, PulseEvent] = {}
        self._order: deque[str] = deque()
        self._dedupe_index: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._rate_ts: deque[int] = deque()

    def _cooldown_for(self, event: PulseEvent) -> int:
        if event.kind == "notable":
            return 600
        if "change" in (event.tags or []):
            return 120
        return 30

    def _trim(self) -> None:
        while len(self._events) > self._max_events:
            oldest_id = min(self._events.values(), key=lambda e: e.ts).id
            self._events.pop(oldest_id, None)
            try:
                self._order.remove(oldest_id)
            except ValueError:
                pass

    def _rate_limit(self, now: int) -> None:
        cutoff = now - 60
        while self._rate_ts and self._rate_ts[0] < cutoff:
            self._rate_ts.popleft()
        if len(self._rate_ts) <= 30:
            return
        # Drop lowest severity from last minute
        severity_rank = {"info": 0, "notice": 1, "warn": 2}
        candidates = [ev for ev in self._events.values() if ev.ts >= cutoff]
        candidates.sort(key=lambda ev: (severity_rank.get(ev.severity, 0), ev.ts))
        while len(self._rate_ts) > 30 and candidates:
            ev = candidates.pop(0)
            self._events.pop(ev.id, None)
            if ev.dedupe_key and self._dedupe_index.get(ev.dedupe_key) == ev.id:
                self._dedupe_index.pop(ev.dedupe_key, None)
            try:
                self._order.remove(ev.id)
            except ValueError:
                pass
            if self._rate_ts:
                self._rate_ts.popleft()

    def add_event(self, event: PulseEvent) -> None:
        now = event.ts
        with self._lock:
            dedupe_key = event.dedupe_key
            if dedupe_key in self._dedupe_index:
                existing_id = self._dedupe_index[dedupe_key]
                existing = self._events.get(existing_id)
                if existing:
                    cooldown = self._cooldown_for(event)
                    if now - existing.ts <= cooldown:
                        existing.ts = max(existing.ts, event.ts)
                        existing.count = (existing.count or 1) + (event.count or 1)
                        if event.detail:
                            existing.detail = event.detail
                        if event.evidence:
                            existing.evidence.update(event.evidence)
                        existing.tags = list(
                            {*(existing.tags or []), *(event.tags or [])}
                        )
                        return

            self._events[event.id] = event
            self._order.append(event.id)
            if dedupe_key:
                self._dedupe_index[dedupe_key] = event.id
            self._rate_ts.append(now)
            self._rate_limit(now)
            self._trim()

    def list_events(
        self,
        limit: int = 200,
        source: Optional[str] = None,
        kind: Optional[str] = None,
        query: Optional[str] = None,
        range_s: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            events = list(self._events.values())

        if range_s:
            cutoff = int(time.time()) - int(range_s)
            events = [e for e in events if e.ts >= cutoff]
        if source and source != "all":
            events = [e for e in events if e.source == source]
        if kind and kind != "all":
            events = [e for e in events if e.kind == kind]
        if query:
            q = query.lower()

            def _match(ev: PulseEvent) -> bool:
                hay = " ".join(
                    [ev.title, ev.detail, ev.entity or ""] + (ev.tags or [])
                ).lower()
                if q in hay:
                    return True
                return any(q in str(v).lower() for v in (ev.evidence or {}).values())

            events = [e for e in events if _match(e)]

        events.sort(key=lambda e: e.ts, reverse=True)
        return [e.to_dict() for e in events[:limit]]


class PulseGenerator:
    def __init__(self, store: PulseStore) -> None:
        self.store = store
        self._last_emit: Dict[str, int] = {}
        self._prev_values: Dict[str, Any] = {}
        self._last_any_emit: int = 0
        self._simulate_seeded: bool = False

    def _emit(self, event: PulseEvent) -> None:
        self.store.add_event(event)

    def _top_from_trends(self) -> Dict[str, Optional[str]]:
        _trends_db_init()
        conn = _trends_db_connect()
        try:
            cur = conn.execute("SELECT MAX(bucket_end) FROM top_dests")
            row = cur.fetchone()
            bucket_end = row[0] if row and row[0] else None
            if not bucket_end:
                return {"top_dst": None, "top_src": None}
            cur = conn.execute(
                "SELECT ip FROM top_dests WHERE bucket_end=? ORDER BY bytes DESC LIMIT 1",
                (bucket_end,),
            )
            top_dst = cur.fetchone()
            cur = conn.execute(
                "SELECT ip FROM top_sources WHERE bucket_end=? ORDER BY bytes DESC LIMIT 1",
                (bucket_end,),
            )
            top_src = cur.fetchone()
            return {
                "top_dst": top_dst[0] if top_dst else None,
                "top_src": top_src[0] if top_src else None,
            }
        finally:
            conn.close()

    def _top_port_from_flow_history(self) -> Optional[int]:
        now = time.time()
        cutoff = now - 60
        counts: Counter = Counter()
        with app_state._flow_history_lock:
            for (src, dst, port), entries in app_state._flow_history.items():
                for entry in entries:
                    if entry.get("ts", 0) >= cutoff:
                        counts[int(port)] += 1
        if not counts:
            return None
        return counts.most_common(1)[0][0]

    def _syslog_514_stats(self) -> Dict[str, Any]:
        with app_state._syslog_stats_lock:
            return dict(app_state._syslog_stats)

    def _firewall_top(self) -> Dict[str, Optional[str]]:
        now = datetime.utcnow()
        recent = firewall_store.get_events(limit=200, since=now - timedelta(seconds=60))
        rule_counts: Counter = Counter()
        iface_counts: Counter = Counter()
        for event in recent:
            rule = event.get("rule_label") or event.get("rule_id")
            if rule:
                rule_counts[str(rule)] += 1
            iface = event.get("interface")
            if iface:
                iface_counts[str(iface)] += 1
        top_rule = rule_counts.most_common(1)[0][0] if rule_counts else None
        top_iface = iface_counts.most_common(1)[0][0] if iface_counts else None
        return {"top_rule": top_rule, "top_iface": top_iface}

    def _emit_heartbeat(
        self, source: str, detail: str, evidence: Dict[str, Any]
    ) -> None:
        now = int(time.time())
        last = self._last_emit.get(source, 0)
        if now - last < 20:
            return
        self._last_emit[source] = now
        self._emit(
            PulseEvent(
                id=str(uuid.uuid4()),
                ts=now,
                source=source,
                severity="info",
                kind="activity",
                title=f"{source.upper()}_HEARTBEAT",
                detail=detail,
                tags=["heartbeat"],
                entity=source,
                count=1,
                evidence=evidence,
                dedupe_key=f"{source}_heartbeat",
                window_sec=60,
            )
        )

    def tick(self) -> None:
        now = int(time.time())
        if PULSE_SIMULATE and not self._simulate_seeded:
            self._simulate_seeded = True
            for i in range(30):
                ts = now - (i * 20)
                sample = [
                    {
                        "source": "netflow",
                        "severity": "notice",
                        "kind": "notable",
                        "title": "PORT_SPIKE",
                        "detail": "port 443 ×3 baseline",
                        "tags": ["port"],
                        "entity": "443",
                    },
                    {
                        "source": "syslog",
                        "severity": "info",
                        "kind": "activity",
                        "title": "SYSLOG_ACTIVE",
                        "detail": "receiver OK",
                        "tags": ["receiver"],
                        "entity": "514",
                    },
                    {
                        "source": "firewall",
                        "severity": "notice",
                        "kind": "activity",
                        "title": "FIREWALL_STREAM_ACTIVE",
                        "detail": "stream resumed",
                        "tags": ["stream"],
                        "entity": "firewall",
                    },
                    {
                        "source": "snmp",
                        "severity": "info",
                        "kind": "activity",
                        "title": "SNMP_REACHABLE",
                        "detail": "poll ok",
                        "tags": ["snmp"],
                        "entity": "snmp",
                    },
                    {
                        "source": "system",
                        "severity": "info",
                        "kind": "activity",
                        "title": "SYSTEM_HEALTHY",
                        "detail": "baseline normal",
                        "tags": ["stable"],
                        "entity": "system",
                    },
                ]
                pick = sample[i % len(sample)]
                self._emit(
                    PulseEvent(
                        id=str(uuid.uuid4()),
                        ts=ts,
                        source=pick["source"],
                        severity=pick["severity"],
                        kind=pick["kind"],
                        title=pick["title"],
                        detail=pick["detail"],
                        tags=pick["tags"],
                        entity=pick["entity"],
                        count=1,
                        evidence={},
                        dedupe_key=f"simulate:{pick['source']}:{i}",
                        window_sec=60,
                    )
                )
        rates = ingestion_tracker.get_rates()
        top = self._top_from_trends()
        top_port = self._top_port_from_flow_history()
        syslog514 = self._syslog_514_stats()
        syslog515 = get_firewall_syslog_stats()
        fw_counts = firewall_store.get_counts(
            since=datetime.utcnow() - timedelta(seconds=60)
        )
        fw_top = self._firewall_top()

        # Heartbeats
        self._emit_heartbeat(
            "netflow",
            f"eps={rates.get('netflow_eps', 0)} top_dst={top.get('top_dst', '—')} top_port={top_port or '—'}",
            {
                "eps": rates.get("netflow_eps"),
                "top_dst": top.get("top_dst"),
                "top_port": top_port,
            },
        )
        self._emit_heartbeat(
            "syslog",
            f"514 rcv={syslog514.get('received', 0)} parsed={syslog514.get('parsed', 0)} err={syslog514.get('errors', 0)} age={int(time.time() - (syslog514.get('last_log') or 0))}s",
            {
                "port": 514,
                "received": syslog514.get("received"),
                "parsed": syslog514.get("parsed"),
                "errors": syslog514.get("errors"),
                "last_log": syslog514.get("last_log"),
            },
        )
        self._emit_heartbeat(
            "syslog",
            f"515 rcv={syslog515.get('received', 0)} parsed={syslog515.get('parsed', 0)} err={syslog515.get('errors', 0)} age={int(time.time() - (syslog515.get('last_log') or 0))}s",
            {
                "port": 515,
                "received": syslog515.get("received"),
                "parsed": syslog515.get("parsed"),
                "errors": syslog515.get("errors"),
                "last_log": syslog515.get("last_log"),
            },
        )
        self._emit_heartbeat(
            "firewall",
            f"pass={fw_counts['by_action'].get('pass', 0)} block={fw_counts['by_action'].get('block', 0)} top_rule={fw_top.get('top_rule', '—')} iface={fw_top.get('top_iface', '—')}",
            {
                "pass": fw_counts["by_action"].get("pass", 0),
                "block": fw_counts["by_action"].get("block", 0),
                "top_rule": fw_top.get("top_rule"),
                "top_interface": fw_top.get("top_iface"),
            },
        )

        # SNMP heartbeat (cached)
        snmp = get_snmp_data()
        if snmp and isinstance(snmp, dict):
            cpu = snmp.get("cpu_percent")
            mem = snmp.get("mem_percent")
            self._emit_heartbeat(
                "snmp",
                f"cpu={cpu if cpu is not None else '—'}% mem={mem if mem is not None else '—'}%",
                {"cpu_percent": cpu, "mem_percent": mem},
            )

        deps = get_dependency_health()
        api_ok = deps.get("system", {}).get("status")
        db_ok = deps.get("database", {}).get("status")
        self._emit_heartbeat(
            "system",
            f"api={api_ok or '—'} db={db_ok or '—'}",
            {"api": api_ok, "db": db_ok},
        )

        if (
            rates.get("netflow_eps", 0)
            + rates.get("syslog_eps", 0)
            + rates.get("firewall_eps", 0)
        ) > 0:
            if now - self._last_any_emit >= 10:
                self._last_any_emit = now
                self._emit(
                    PulseEvent(
                        id=str(uuid.uuid4()),
                        ts=now,
                        source="system",
                        severity="info",
                        kind="activity",
                        title="SYSTEM_HEALTHY",
                        detail="ingest active",
                        tags=["heartbeat"],
                        entity="system",
                        count=1,
                        evidence={},
                        dedupe_key="system_healthy",
                        window_sec=60,
                    )
                )

        # Change events
        if top.get("top_dst") and top.get("top_dst") != self._prev_values.get(
            "top_dst"
        ):
            self._prev_values["top_dst"] = top.get("top_dst")
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="netflow",
                    severity="notice",
                    kind="activity",
                    title="NETFLOW_TOP_DST_CHANGED",
                    detail=f"top dst {top.get('top_dst')}",
                    tags=["change"],
                    entity=top.get("top_dst"),
                    count=1,
                    evidence={"top_dst": top.get("top_dst")},
                    dedupe_key=f"netflow_top_dst:{top.get('top_dst')}",
                    window_sec=60,
                )
            )

        if top_port and top_port != self._prev_values.get("top_port"):
            self._prev_values["top_port"] = top_port
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="netflow",
                    severity="notice",
                    kind="activity",
                    title="NETFLOW_TOP_PORT_CHANGED",
                    detail=f"top port {top_port}",
                    tags=["change"],
                    entity=str(top_port),
                    count=1,
                    evidence={"top_port": top_port},
                    dedupe_key=f"netflow_top_port:{top_port}",
                    window_sec=60,
                )
            )

        fw_block = fw_counts["by_action"].get("block", 0)
        prev_block = self._prev_values.get("fw_block", 0)
        if prev_block and fw_block >= prev_block * 2:
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="firewall",
                    severity="warn",
                    kind="activity",
                    title="FIREWALL_BLOCK_RATE_JUMP",
                    detail=f"block/min {fw_block} (prev {prev_block})",
                    tags=["change"],
                    entity="block_rate",
                    count=fw_block,
                    evidence={"current": fw_block, "previous": prev_block},
                    dedupe_key="firewall_block_rate",
                    window_sec=60,
                )
            )
        self._prev_values["fw_block"] = fw_block

        if top.get("top_src") and top.get("top_src") != self._prev_values.get(
            "top_src"
        ):
            self._prev_values["top_src"] = top.get("top_src")
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="netflow",
                    severity="notice",
                    kind="activity",
                    title="NETFLOW_TOP_TALKER_CHANGED",
                    detail=f"top src {top.get('top_src')}",
                    tags=["change"],
                    entity=top.get("top_src"),
                    count=1,
                    evidence={"top_src": top.get("top_src")},
                    dedupe_key=f"netflow_top_src:{top.get('top_src')}",
                    window_sec=60,
                )
            )

        if fw_top.get("top_rule") and fw_top.get("top_rule") != self._prev_values.get(
            "top_rule"
        ):
            self._prev_values["top_rule"] = fw_top.get("top_rule")
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="firewall",
                    severity="notice",
                    kind="activity",
                    title="FIREWALL_TOP_RULE_CHANGED",
                    detail=f"top rule {fw_top.get('top_rule')}",
                    tags=["change"],
                    entity=fw_top.get("top_rule"),
                    count=1,
                    evidence={"top_rule": fw_top.get("top_rule")},
                    dedupe_key=f"firewall_top_rule:{fw_top.get('top_rule')}",
                    window_sec=60,
                )
            )

        if snmp and isinstance(snmp, dict):
            wan_util = snmp.get("wan_util_percent")
            if wan_util is not None:
                prev_util = self._prev_values.get("wan_util")
                if prev_util is not None and abs(wan_util - prev_util) >= 10:
                    self._emit(
                        PulseEvent(
                            id=str(uuid.uuid4()),
                            ts=now,
                            source="snmp",
                            severity="notice",
                            kind="activity",
                            title="SNMP_IFACE_UTIL_JUMP",
                            detail=f"wan util {wan_util}% (prev {prev_util}%)",
                            tags=["change"],
                            entity="wan",
                            count=1,
                            evidence={"wan_util": wan_util, "prev": prev_util},
                            dedupe_key="snmp_wan_util",
                            window_sec=60,
                        )
                    )
                self._prev_values["wan_util"] = wan_util

        # Notable events from existing rules
        for ev in fetch_events("notable", range_sec=600, limit=50):
            dedupe_key = ev.get("dedupe_key") or ev.get("id") or str(uuid.uuid4())
            self._emit(
                PulseEvent(
                    id=ev.get("id") or str(uuid.uuid4()),
                    ts=int(ev.get("ts", now)),
                    source=ev.get("source", "system"),
                    severity=ev.get("severity", "notice"),
                    kind="notable",
                    title=ev.get("title", "Notable"),
                    detail=ev.get("summary", ""),
                    tags=ev.get("tags", []),
                    entity=ev.get("primary_entity"),
                    count=ev.get("count", 1),
                    evidence=ev.get("evidence", {}),
                    dedupe_key=str(dedupe_key),
                    window_sec=ev.get("window_sec") or 60,
                )
            )

        if PULSE_SIMULATE:
            self._emit(
                PulseEvent(
                    id=str(uuid.uuid4()),
                    ts=now,
                    source="system",
                    severity="info",
                    kind="activity",
                    title="SIMULATED_EVENT",
                    detail="pulse simulate enabled",
                    tags=["simulate"],
                    entity="dev",
                    count=1,
                    evidence={},
                    dedupe_key="simulate",
                    window_sec=60,
                )
            )


_pulse_store = PulseStore()
_pulse_generator = PulseGenerator(_pulse_store)


def get_pulse_store() -> PulseStore:
    return _pulse_store


def pulse_tick() -> None:
    _pulse_generator.tick()
