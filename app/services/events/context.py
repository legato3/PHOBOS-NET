import re
from collections import Counter
from typing import Any, Dict, List, Optional

from app.core import app_state
from app.db.sqlite import _firewall_db_connect, _firewall_db_init, _firewall_db_lock
from app.services.events.store import fetch_event_detail, fetch_related_events
from app.services.timeline.store import get_timeline_store


_EXPLAIN = {
    "NEW_EXTERNAL_DESTINATION": "New public destination not seen in the last 24h.",
    "TOP_TALKER_CHANGED": "Top talker changed compared to the previous 5m window.",
    "PORT_SPIKE": "Port activity spiked against the 60m baseline.",
    "BLOCK_SPIKE": "Firewall blocks spiked against the 60m baseline.",
    "NEW_INBOUND_WAN_SOURCE": "New inbound WAN source not seen in the last 24h.",
    "RULE_HIT_SPIKE": "Firewall rule hits spiked against the 60m baseline.",
    "NXDOMAIN_BURST": "NXDOMAIN responses spiked against the 60m baseline.",
    "NEW_DOMAIN_TO_MANY_HOSTS": "A new domain was queried by many hosts in a short window.",
    "SOURCE_STALE": "Data source has been quiet beyond the expected threshold.",
    "PARSER_ERROR_SPIKE": "Parser errors spiked against the 60m baseline.",
}

_dns_query_re = re.compile(r"query: ([A-Za-z0-9._-]+)")
_dns_from_re = re.compile(r"from ([0-9a-fA-F:.]+)")
_dns_nxdomain_re = re.compile(r"NXDOMAIN", re.IGNORECASE)


def _top_list(counter: Counter, limit: int = 5) -> List[Dict[str, Any]]:
    return [{"label": k, "count": v} for k, v in counter.most_common(limit)]


def _parse_dns(message: str) -> Optional[Dict[str, str]]:
    if not message:
        return None
    if not _dns_nxdomain_re.search(message) and "query:" not in message:
        return None
    domain_match = _dns_query_re.search(message)
    client_match = _dns_from_re.search(message)
    return {
        "domain": domain_match.group(1) if domain_match else "",
        "client": client_match.group(1) if client_match else "",
        "nxdomain": "1" if _dns_nxdomain_re.search(message) else "0",
    }


def _netflow_top(window_start: int, window_end: int) -> Dict[str, List[Dict[str, Any]]]:
    src_counts: Counter = Counter()
    dst_counts: Counter = Counter()
    port_counts: Counter = Counter()
    with app_state._flow_history_lock:
        for (src, dst, port), entries in app_state._flow_history.items():
            for entry in entries:
                ts = int(entry.get("ts", 0))
                if ts < window_start or ts > window_end:
                    continue
                src_counts[src] += 1
                dst_counts[dst] += 1
                port_counts[int(port)] += 1
    return {
        "top_src_ips": _top_list(src_counts),
        "top_dst_ips": _top_list(dst_counts),
        "top_dst_ports": _top_list(port_counts),
    }


def _firewall_top(
    window_start: int, window_end: int
) -> Dict[str, List[Dict[str, Any]]]:
    _firewall_db_init()
    src_counts: Counter = Counter()
    port_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute(
                """
                SELECT src_ip, dst_port, rule_id, rule_label
                FROM fw_logs
                WHERE timestamp >= ? AND timestamp <= ?
                """,
                (window_start, window_end),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    for src_ip, dst_port, rule_id, rule_label in rows:
        if src_ip:
            src_counts[src_ip] += 1
        if dst_port:
            port_counts[int(dst_port)] += 1
        rule_key = rule_label or rule_id
        if rule_key:
            rule_counts[str(rule_key)] += 1
    return {
        "top_src_ips": _top_list(src_counts),
        "top_dst_ports": _top_list(port_counts),
        "top_rules": _top_list(rule_counts),
    }


def _syslog_top(window_start: int, window_end: int) -> Dict[str, List[Dict[str, Any]]]:
    _firewall_db_init()
    domain_counts: Counter = Counter()
    client_counts: Counter = Counter()
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute(
                """
                SELECT message FROM syslog_events
                WHERE timestamp >= ? AND timestamp <= ?
                """,
                (window_start, window_end),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    for (message,) in rows:
        parsed = _parse_dns(message or "")
        if not parsed:
            continue
        if parsed.get("domain"):
            domain_counts[parsed["domain"]] += 1
        if parsed.get("client"):
            client_counts[parsed["client"]] += 1
    return {
        "top_domains": _top_list(domain_counts),
        "top_clients": _top_list(client_counts),
    }


def build_event_context(event_id: str) -> Optional[Dict[str, Any]]:
    event = fetch_event_detail(event_id)
    if not event:
        return None
    rule_id = event.get("rule_id")
    explain = _EXPLAIN.get(rule_id) if rule_id else None

    ts = int(event.get("ts") or 0)
    primary_entity = event.get("primary_entity") or event.get("evidence", {}).get(
        "primary_entity"
    )
    window_sec = int(event.get("window_sec") or 600)

    related = fetch_related_events(
        event_id=event_id,
        ts=ts,
        window_sec=600,
        primary_entity=str(primary_entity) if primary_entity else None,
        source=event.get("source") or "system",
        limit=12,
    )

    window_start = ts - window_sec
    window_end = ts
    source = event.get("source") or "system"
    if source == "netflow":
        top = _netflow_top(window_start, window_end)
    elif source in ("firewall", "filterlog"):
        top = _firewall_top(window_start, window_end)
    elif source == "syslog":
        top = _syslog_top(window_start, window_end)
    else:
        top = {}

    timeline = get_timeline_store().list_events_between(
        start_ts=ts - 600,
        end_ts=ts + 600,
        source=source,
        limit=10,
    )

    return {
        "event": event,
        "explain": explain,
        "related": related,
        "top": top,
        "timeline": timeline,
    }
