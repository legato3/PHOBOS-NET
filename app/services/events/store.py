import json
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from app.db.sqlite import _trends_db_connect, _trends_db_init, _trends_db_lock
from app.services.events.model import EventRecord


SEVERITY_RANK = {"info": 0, "notice": 1, "warn": 2}


def _json_dump(value: Any) -> str:
    try:
        return json.dumps(value or {}, sort_keys=True)
    except (TypeError, ValueError):
        return "{}"


def _ensure_db() -> None:
    _trends_db_init()


def _cleanup_old_events(conn, retention_sec: int = 86400) -> None:
    cutoff = time.time() - retention_sec
    conn.execute("DELETE FROM event_log WHERE ts < ?", (cutoff,))


def _primary_entity(event: EventRecord) -> Optional[str]:
    if not event.evidence:
        return None
    val = event.evidence.get("primary_entity")
    if val is None:
        return None
    return str(val)


def insert_activity_event(event: EventRecord) -> None:
    _ensure_db()
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            _cleanup_old_events(conn)
            conn.execute(
                """
                INSERT INTO event_log (id, ts, source, severity, title, summary, tags, evidence, rule_id,
                    dedupe_key, window_sec, count, kind, updated_ts, primary_entity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.ts,
                    event.source,
                    event.severity,
                    event.title,
                    event.summary,
                    _json_dump(event.tags),
                    _json_dump(event.evidence),
                    event.rule_id,
                    event.dedupe_key,
                    event.window_sec,
                    event.count,
                    "activity",
                    event.ts,
                    _primary_entity(event),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def upsert_notable_event(
    event: EventRecord,
    cooldown_sec: int = 600,
    max_per_hour: int = 8,
) -> Optional[str]:
    _ensure_db()
    now_ts = time.time()
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            _cleanup_old_events(conn)
            existing = None
            if event.dedupe_key:
                cur = conn.execute(
                    """
                    SELECT id, ts, count, severity FROM event_log
                    WHERE kind = 'notable' AND dedupe_key = ?
                    ORDER BY ts DESC
                    LIMIT 1
                    """,
                    (event.dedupe_key,),
                )
                existing = cur.fetchone()

            if existing and (now_ts - existing[1]) <= cooldown_sec:
                new_count = int(existing[2] or 1) + max(1, event.count)
                conn.execute(
                    """
                    UPDATE event_log
                    SET ts = ?, title = ?, summary = ?, tags = ?, evidence = ?,
                        count = ?, severity = ?, rule_id = ?, window_sec = ?, updated_ts = ?, primary_entity = ?
                    WHERE id = ?
                    """,
                    (
                        event.ts,
                        event.title,
                        event.summary,
                        _json_dump(event.tags),
                        _json_dump(event.evidence),
                        new_count,
                        event.severity,
                        event.rule_id,
                        event.window_sec,
                        event.ts,
                        _primary_entity(event),
                        existing[0],
                    ),
                )
                conn.commit()
                return existing[0]

            hour_cutoff = now_ts - 3600
            cur = conn.execute(
                """
                SELECT id, severity, ts FROM event_log
                WHERE kind = 'notable' AND ts >= ?
                ORDER BY ts ASC
                """,
                (hour_cutoff,),
            )
            rows = cur.fetchall()
            if len(rows) >= max_per_hour:
                rows_sorted = sorted(
                    rows, key=lambda r: (SEVERITY_RANK.get(r[1], 0), r[2])
                )
                lowest = rows_sorted[0]
                if SEVERITY_RANK.get(event.severity, 0) <= SEVERITY_RANK.get(
                    lowest[1], 0
                ):
                    return None
                conn.execute("DELETE FROM event_log WHERE id = ?", (lowest[0],))

            event_id = event.id or str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO event_log (id, ts, source, severity, title, summary, tags, evidence, rule_id,
                    dedupe_key, window_sec, count, kind, updated_ts, primary_entity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event.ts,
                    event.source,
                    event.severity,
                    event.title,
                    event.summary,
                    _json_dump(event.tags),
                    _json_dump(event.evidence),
                    event.rule_id,
                    event.dedupe_key,
                    event.window_sec,
                    max(1, event.count),
                    "notable",
                    event.ts,
                    _primary_entity(event),
                ),
            )
            conn.commit()
            return event_id
        finally:
            conn.close()


def fetch_events(
    kind: str, range_sec: int, limit: int, source: Optional[str] = None
) -> List[Dict[str, Any]]:
    _ensure_db()
    now_ts = time.time()
    cutoff = now_ts - range_sec
    params: List[Any] = [kind, cutoff]
    source_clause = ""
    if source:
        source_clause = " AND source = ?"
        params.append(source)
    params.append(limit)

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                f"""
                SELECT id, ts, source, severity, title, summary, tags, evidence, rule_id, dedupe_key, window_sec, count, kind, primary_entity
                FROM event_log
                WHERE kind = ? AND ts >= ? {source_clause}
                ORDER BY ts DESC
                LIMIT ?
                """,
                params,
            )
            rows = cur.fetchall()
        finally:
            conn.close()

    results = []
    for row in rows:
        results.append(
            {
                "id": row[0],
                "ts": int(row[1]),
                "source": row[2],
                "severity": row[3],
                "title": row[4],
                "summary": row[5],
                "tags": json.loads(row[6] or "[]"),
                "evidence": json.loads(row[7] or "{}"),
                "rule_id": row[8],
                "dedupe_key": row[9],
                "window_sec": row[10],
                "count": row[11],
                "kind": row[12],
                "primary_entity": row[13],
            }
        )
    return results


def fetch_event_detail(event_id: str) -> Optional[Dict[str, Any]]:
    _ensure_db()
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                """
                SELECT id, ts, source, severity, title, summary, tags, evidence, rule_id, dedupe_key, window_sec, count, kind, primary_entity
                FROM event_log
                WHERE id = ?
                LIMIT 1
                """,
                (event_id,),
            )
            row = cur.fetchone()
        finally:
            conn.close()

    if not row:
        return None
    return {
        "id": row[0],
        "ts": int(row[1]),
        "source": row[2],
        "severity": row[3],
        "title": row[4],
        "summary": row[5],
        "tags": json.loads(row[6] or "[]"),
        "evidence": json.loads(row[7] or "{}"),
        "rule_id": row[8],
        "dedupe_key": row[9],
        "window_sec": row[10],
        "count": row[11],
        "kind": row[12],
        "primary_entity": row[13],
    }


def fetch_related_events(
    *,
    event_id: str,
    ts: int,
    window_sec: int,
    primary_entity: Optional[str],
    source: str,
    limit: int = 12,
) -> List[Dict[str, Any]]:
    _ensure_db()
    start_ts = ts - window_sec
    end_ts = ts + window_sec
    params: List[Any] = [event_id, start_ts, end_ts]
    clause = "source = ?"
    params.append(source)
    if primary_entity:
        clause = "(primary_entity = ? OR source = ?)"
        params = [event_id, start_ts, end_ts, primary_entity, source]
    params.append(limit)

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                f"""
                SELECT id, ts, source, severity, title, summary, tags, evidence, rule_id, dedupe_key, window_sec, count, kind
                FROM event_log
                WHERE id != ? AND ts BETWEEN ? AND ? AND {clause}
                ORDER BY ts DESC
                LIMIT ?
                """,
                params,
            )
            rows = cur.fetchall()
        finally:
            conn.close()

    results = []
    for row in rows:
        results.append(
            {
                "id": row[0],
                "ts": int(row[1]),
                "source": row[2],
                "severity": row[3],
                "title": row[4],
                "summary": row[5],
                "tags": json.loads(row[6] or "[]"),
                "evidence": json.loads(row[7] or "{}"),
                "rule_id": row[8],
                "dedupe_key": row[9],
                "window_sec": row[10],
                "count": row[11],
                "kind": row[12],
            }
        )
    return results
