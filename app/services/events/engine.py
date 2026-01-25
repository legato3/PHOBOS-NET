import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from app.core import app_state
from app.core.app_state import get_dependency_health
from app.db.sqlite import (
    _firewall_db_connect,
    _firewall_db_init,
    _firewall_db_lock,
    _trends_db_connect,
    _trends_db_init,
    _trends_db_lock,
    _get_bucket_end,
)
from app.services.events.rules import (
    rule_block_spike,
    rule_new_domain_to_many_hosts,
    rule_new_external_destination,
    rule_new_inbound_wan_source,
    rule_nxdomain_burst,
    rule_parser_error_spike,
    rule_port_spike,
    rule_rule_hit_spike,
    rule_source_stale,
    rule_top_talker_changed,
)
from app.services.events.store import upsert_notable_event
from app.services.shared.geoip import lookup_geo
from app.services.shared.helpers import is_internal


WINDOW_SEC = 300
BASELINE_SEC = 3600

MIN_TOP_BYTES = 5 * 1024 * 1024
MIN_PORT_COUNT = 50
MIN_BLOCK_COUNT = 50
MIN_RULE_COUNT = 20
MIN_NXDOMAIN = 20
MIN_PARSER_ERRORS = 20
MIN_DOMAIN_HOSTS = 5

STALE_THRESHOLDS = {
    "netflow": 300,
    "syslog_514": 180,
    "syslog_515": 180,
    "snmp": 240,
}

_error_history: Dict[str, deque] = {
    "syslog_514": deque(maxlen=12),
    "syslog_515": deque(maxlen=12),
}
_last_error_counts: Dict[str, int] = {
    "syslog_514": 0,
    "syslog_515": 0,
}

_dns_query_re = re.compile(r"query: ([A-Za-z0-9._-]+)")
_dns_from_re = re.compile(r"from ([0-9a-fA-F:.]+)")
_dns_nxdomain_re = re.compile(r"NXDOMAIN", re.IGNORECASE)


def _bucket_ends(now_dt: datetime) -> Tuple[int, int]:
    current_end = _get_bucket_end(now_dt)
    last_end = int((current_end - timedelta(minutes=5)).timestamp())
    prev_end = int((current_end - timedelta(minutes=10)).timestamp())
    return last_end, prev_end


def _get_top_ip(table: str, bucket_end: int) -> Optional[Tuple[str, int]]:
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                f"SELECT ip, bytes FROM {table} WHERE bucket_end=? ORDER BY bytes DESC LIMIT 1",
                (bucket_end,),
            )
            row = cur.fetchone()
        finally:
            conn.close()
    if not row:
        return None
    return row[0], int(row[1])


def _list_top_dests(bucket_end: int, limit: int = 20) -> List[Tuple[str, int, int]]:
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT ip, bytes, flows FROM top_dests WHERE bucket_end=? ORDER BY bytes DESC LIMIT ?",
                (bucket_end, limit),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
    return [(r[0], int(r[1]), int(r[2])) for r in rows]


def _recent_dest_history(cutoff_ts: int, end_ts: Optional[int] = None) -> set:
    query = "SELECT DISTINCT ip FROM top_dests WHERE bucket_end >= ?"
    params: List = [cutoff_ts]
    if end_ts:
        query += " AND bucket_end < ?"
        params.append(end_ts)
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(query, params)
            rows = cur.fetchall()
        finally:
            conn.close()
    return {r[0] for r in rows}


def _flow_history_by_port(window_sec: int, now_ts: int) -> Dict[int, int]:
    counts: Dict[int, int] = defaultdict(int)
    cutoff = now_ts - window_sec
    with app_state._flow_history_lock:
        for (src, dst, port), entries in app_state._flow_history.items():
            for entry in entries:
                if entry.get("ts", 0) >= cutoff:
                    counts[int(port)] += 1
    return counts


def _flow_history_top_for_port(
    port: int, now_ts: int
) -> Tuple[Optional[str], Optional[str]]:
    cutoff = now_ts - WINDOW_SEC
    src_counts: Counter = Counter()
    dst_counts: Counter = Counter()
    with app_state._flow_history_lock:
        for (src, dst, p), entries in app_state._flow_history.items():
            if int(p) != int(port):
                continue
            for entry in entries:
                if entry.get("ts", 0) >= cutoff:
                    src_counts[src] += 1
                    dst_counts[dst] += 1
    top_src = src_counts.most_common(1)[0][0] if src_counts else None
    top_dst = dst_counts.most_common(1)[0][0] if dst_counts else None
    return top_src, top_dst


def _flow_history_for_dest(dst_ip: str, now_ts: int) -> Tuple[List[int], Optional[str]]:
    cutoff = now_ts - WINDOW_SEC
    ports: Counter = Counter()
    src_counts: Counter = Counter()
    with app_state._flow_history_lock:
        for (src, dst, port), entries in app_state._flow_history.items():
            if dst != dst_ip:
                continue
            for entry in entries:
                if entry.get("ts", 0) >= cutoff:
                    ports[int(port)] += 1
                    src_counts[src] += 1
    dst_ports = [p for p, _ in ports.most_common(3)]
    top_src = src_counts.most_common(1)[0][0] if src_counts else None
    return dst_ports, top_src


def _firewall_counts(
    start_ts: float, end_ts: float, where_clause: str = ""
) -> Tuple[int, List[Tuple]]:
    _firewall_db_init()
    query = (
        "SELECT src_ip, dst_ip, dst_port, rule_id, rule_label, interface, action, direction "
        "FROM fw_logs WHERE timestamp >= ? AND timestamp < ? "
    )
    if where_clause:
        query += where_clause
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute(query, (start_ts, end_ts))
            rows = cur.fetchall()
        finally:
            conn.close()
    return len(rows), rows


def _parse_dns_syslog(message: str) -> Tuple[Optional[str], Optional[str], bool]:
    if not message:
        return None, None, False
    domain = None
    client_ip = None
    match = _dns_query_re.search(message)
    if match:
        domain = match.group(1)
    match = _dns_from_re.search(message)
    if match:
        client_ip = match.group(1)
    is_nxdomain = bool(_dns_nxdomain_re.search(message))
    return domain, client_ip, is_nxdomain


def _collect_syslog_dns(
    start_ts: float, end_ts: float
) -> Tuple[List[Tuple[str, str, bool]], List[str]]:
    _firewall_db_init()
    rows: List[Tuple[str, str, bool]] = []
    samples: List[str] = []
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute(
                """
                SELECT message FROM syslog_events
                WHERE timestamp >= ? AND timestamp < ?
                ORDER BY timestamp DESC
                """,
                (start_ts, end_ts),
            )
            for (message,) in cur.fetchall():
                domain, client_ip, is_nxdomain = _parse_dns_syslog(message or "")
                if domain or is_nxdomain:
                    rows.append((domain or "", client_ip or "", is_nxdomain))
                if len(samples) < 3 and message:
                    samples.append(message[:160])
        finally:
            conn.close()
    return rows, samples


def run_notable_rules() -> None:
    now_ts = int(time.time())
    window_start = now_ts - WINDOW_SEC
    baseline_start = now_ts - BASELINE_SEC
    baseline_end = window_start

    _trends_db_init()
    events: List = []

    # NETFLOW: Top talker changes
    last_end, prev_end = _bucket_ends(datetime.now())
    current_src = _get_top_ip("top_sources", last_end)
    prev_src = _get_top_ip("top_sources", prev_end)
    if (
        current_src
        and prev_src
        and current_src[0] != prev_src[0]
        and current_src[1] >= MIN_TOP_BYTES
    ):
        delta_pct = ((current_src[1] - prev_src[1]) / max(prev_src[1], 1)) * 100
        events.append(
            rule_top_talker_changed(
                ts=now_ts,
                direction="src",
                old_top=prev_src[0],
                new_top=current_src[0],
                delta_pct=delta_pct,
                bytes_count=current_src[1],
                baseline_value=prev_src[1],
                min_abs_threshold=MIN_TOP_BYTES,
            )
        )

    current_dst = _get_top_ip("top_dests", last_end)
    prev_dst = _get_top_ip("top_dests", prev_end)
    if (
        current_dst
        and prev_dst
        and current_dst[0] != prev_dst[0]
        and current_dst[1] >= MIN_TOP_BYTES
    ):
        delta_pct = ((current_dst[1] - prev_dst[1]) / max(prev_dst[1], 1)) * 100
        events.append(
            rule_top_talker_changed(
                ts=now_ts,
                direction="dst",
                old_top=prev_dst[0],
                new_top=current_dst[0],
                delta_pct=delta_pct,
                bytes_count=current_dst[1],
                baseline_value=prev_dst[1],
                min_abs_threshold=MIN_TOP_BYTES,
            )
        )

    # NETFLOW: New external destination
    history_cutoff = int(time.time() - 86400)
    seen_dests = _recent_dest_history(history_cutoff, end_ts=last_end)
    for dst_ip, bytes_count, flows_count in _list_top_dests(last_end, limit=10):
        if dst_ip in seen_dests:
            continue
        if is_internal(dst_ip):
            continue
        geo = lookup_geo(dst_ip) or {}
        ports, top_src = _flow_history_for_dest(dst_ip, now_ts)
        events.append(
            rule_new_external_destination(
                ts=now_ts,
                dst_ip=dst_ip,
                country=geo.get("country") or geo.get("country_iso") or "",
                dst_ports=ports,
                top_src_ip=top_src,
                bytes_count=bytes_count,
                flows_count=flows_count,
                min_abs_threshold=1,
            )
        )

    # NETFLOW: Port spike (from flow history)
    current_ports = _flow_history_by_port(WINDOW_SEC, now_ts)
    baseline_ports = _flow_history_by_port(BASELINE_SEC, now_ts)
    for port, current_count in sorted(
        current_ports.items(), key=lambda kv: kv[1], reverse=True
    )[:10]:
        baseline_total = baseline_ports.get(port, 0)
        baseline_avg = baseline_total / max(BASELINE_SEC / WINDOW_SEC, 1)
        if (
            current_count >= MIN_PORT_COUNT
            and baseline_avg > 0
            and current_count >= baseline_avg * 3
        ):
            top_src, top_dst = _flow_history_top_for_port(port, now_ts)
            events.append(
                rule_port_spike(
                    ts=now_ts,
                    port=port,
                    current=current_count,
                    baseline=baseline_avg,
                    top_src=top_src,
                    top_dst=top_dst,
                    min_abs_threshold=MIN_PORT_COUNT,
                )
            )

    # FIREWALL: Block spike
    current_count, current_rows = _firewall_counts(
        window_start, now_ts, "AND action = 'block'"
    )
    _, all_rows = _firewall_counts(window_start, now_ts)
    baseline_count, _ = _firewall_counts(
        baseline_start, baseline_end, "AND action = 'block'"
    )
    baseline_avg = baseline_count / max(BASELINE_SEC / WINDOW_SEC, 1)
    if (
        current_count >= MIN_BLOCK_COUNT
        and baseline_avg > 0
        and current_count >= baseline_avg * 3
    ):
        top_src = Counter([r[0] for r in current_rows]).most_common(1)
        top_dst = Counter([r[1] for r in current_rows]).most_common(1)
        top_port = Counter([r[2] for r in current_rows if r[2]]).most_common(1)
        interface = current_rows[0][5] if current_rows else "UNKNOWN"
        events.append(
            rule_block_spike(
                ts=now_ts,
                interface=(interface or "unknown"),
                action="block",
                current=current_count,
                baseline=baseline_avg,
                top_src=top_src[0][0] if top_src else None,
                top_dst=top_dst[0][0] if top_dst else None,
                top_port=top_port[0][0] if top_port else None,
                min_abs_threshold=MIN_BLOCK_COUNT,
            )
        )

    # FIREWALL: New inbound WAN source
    _, inbound_rows = _firewall_counts(
        window_start,
        now_ts,
        "AND lower(interface) LIKE '%wan%' AND lower(direction) LIKE 'in%'",
    )
    inbound_srcs = {r[0] for r in inbound_rows if r[0]}
    for src_ip in list(inbound_srcs)[:5]:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute(
                    """
                    SELECT 1 FROM fw_logs
                    WHERE src_ip = ? AND timestamp < ? AND timestamp >= ?
                    AND lower(interface) LIKE '%wan%' AND lower(direction) LIKE 'in%'
                    LIMIT 1
                    """,
                    (src_ip, window_start, time.time() - 86400),
                )
                seen = cur.fetchone()
                cur = conn.execute(
                    """
                    SELECT dst_port, rule_label FROM fw_logs
                    WHERE src_ip = ? AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (src_ip, window_start),
                )
                last_row = cur.fetchone()
            finally:
                conn.close()
        if seen:
            continue
        geo = lookup_geo(src_ip) or {}
        dst_port = int(last_row[0]) if last_row and last_row[0] else 0
        rule_label = last_row[1] if last_row else None
        events.append(
            rule_new_inbound_wan_source(
                ts=now_ts,
                src_ip=src_ip,
                country=geo.get("country") or geo.get("country_iso") or "",
                dst_port=dst_port,
                rule_label=rule_label,
                min_abs_threshold=1,
            )
        )

    # FIREWALL: Rule hit spike
    rule_counts = Counter()
    for row in all_rows:
        rule_key = row[3] or row[4]
        if rule_key:
            rule_counts[rule_key] += 1
    for rule_key, current in rule_counts.most_common(5):
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute(
                    """
                    SELECT COUNT(*) FROM fw_logs
                    WHERE (rule_id = ? OR rule_label = ?) AND timestamp >= ? AND timestamp < ?
                    """,
                    (rule_key, rule_key, baseline_start, baseline_end),
                )
                baseline_count = cur.fetchone()[0] or 0
            finally:
                conn.close()
        baseline_avg = baseline_count / max(BASELINE_SEC / WINDOW_SEC, 1)
        if (
            current >= MIN_RULE_COUNT
            and baseline_avg > 0
            and current >= baseline_avg * 3
        ):
            events.append(
                rule_rule_hit_spike(
                    ts=now_ts,
                    rule_id=rule_key,
                    rule_label=rule_key,
                    current=current,
                    baseline=baseline_avg,
                    min_abs_threshold=MIN_RULE_COUNT,
                )
            )

    # SYSLOG: NXDOMAIN burst + new domain to many hosts
    dns_rows, samples = _collect_syslog_dns(window_start, now_ts)
    nxdomain_count = sum(1 for _, _, is_nxdomain in dns_rows if is_nxdomain)
    baseline_rows, _ = _collect_syslog_dns(baseline_start, baseline_end)
    baseline_nx = sum(1 for _, _, is_nxdomain in baseline_rows if is_nxdomain)
    baseline_avg = baseline_nx / max(BASELINE_SEC / WINDOW_SEC, 1)
    if (
        nxdomain_count >= MIN_NXDOMAIN
        and baseline_avg > 0
        and nxdomain_count >= baseline_avg * 3
    ):
        domains = Counter([d for d, _, is_nxdomain in dns_rows if is_nxdomain and d])
        clients = Counter([c for _, c, is_nxdomain in dns_rows if is_nxdomain and c])
        events.append(
            rule_nxdomain_burst(
                ts=now_ts,
                current=nxdomain_count,
                baseline=baseline_avg,
                top_domains=[d for d, _ in domains.most_common(3)],
                top_clients=[c for c, _ in clients.most_common(3)],
                min_abs_threshold=MIN_NXDOMAIN,
            )
        )

    domain_hosts: Dict[str, set] = defaultdict(set)
    for domain, client, _ in dns_rows:
        if domain and client:
            domain_hosts[domain].add(client)
    if domain_hosts:
        history_rows, _ = _collect_syslog_dns(now_ts - 86400, window_start)
        history_domains = {d for d, _, _ in history_rows if d}
        for domain, hosts in list(domain_hosts.items())[:10]:
            if domain in history_domains:
                continue
            if len(hosts) >= MIN_DOMAIN_HOSTS:
                events.append(
                    rule_new_domain_to_many_hosts(
                        ts=now_ts,
                        domain=domain,
                        host_count=len(hosts),
                        top_hosts=list(hosts)[:3],
                        min_abs_threshold=MIN_DOMAIN_HOSTS,
                    )
                )

    # SYSTEM: Source stale
    deps = get_dependency_health()
    for source, threshold in STALE_THRESHOLDS.items():
        if source == "netflow":
            last_age = deps.get("nfcapd", {}).get("latest_file_age_sec")
        else:
            last_age = deps.get(source, {}).get("last_packet_time_age_sec")
            if source == "snmp":
                last_age = deps.get("snmp", {}).get("last_poll_time_age_sec")
        if last_age and last_age >= threshold:
            events.append(
                rule_source_stale(
                    ts=now_ts,
                    source=source,
                    last_seen_age=float(last_age),
                    threshold=threshold,
                    min_abs_threshold=threshold,
                )
            )

    # SYSTEM: Parser error spike (syslog parse errors)
    for parser in ["syslog_514", "syslog_515"]:
        current_errors = int(deps.get(parser, {}).get("errors") or 0)
        last_errors = _last_error_counts.get(parser, 0)
        delta = max(0, current_errors - last_errors)
        _last_error_counts[parser] = current_errors
        _error_history[parser].append(delta)
        if len(_error_history[parser]) < 3:
            continue
        baseline_vals = list(_error_history[parser])[:-1]
        baseline_avg = sum(baseline_vals) / max(len(baseline_vals), 1)
        if (
            delta >= MIN_PARSER_ERRORS
            and baseline_avg > 0
            and delta >= baseline_avg * 3
        ):
            events.append(
                rule_parser_error_spike(
                    ts=now_ts,
                    parser=parser,
                    current=delta,
                    baseline=baseline_avg,
                    sample_error=None,
                    min_abs_threshold=MIN_PARSER_ERRORS,
                )
            )

    for event in events:
        upsert_notable_event(event)
