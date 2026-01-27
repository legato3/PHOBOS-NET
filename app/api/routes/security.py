from . import bp

"""Flask routes for PHOBOS-NET application.

This module contains all API routes extracted from netflow-dashboard.py.
Routes are organized in a single Flask Blueprint.
"""
from flask import (
    Blueprint,
    render_template,
    jsonify,
    request,
    Response,
    stream_with_context,
    current_app,
)
import time
import logging
import os
import json
import hashlib
import socket
import threading
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor
import sqlite3

from app.services.shared.service_resolution import resolve_service_name

# Import from service modules (already extracted)
from app.services.netflow.netflow import (
    get_common_nfdump_data,
    run_nfdump,
    parse_csv,
    get_traffic_direction,
    get_raw_flows,
)
from app.services.security.threats import (
    fetch_threat_feed,
    get_threat_info,
    update_threat_timeline,
    get_threat_timeline,
    load_watchlist,
    add_to_watchlist,
    remove_from_watchlist,
    detect_anomalies,
    run_all_detections,
    load_threatlist,
    get_feed_label,
    send_notifications,
    lookup_threat_intelligence,
    detect_ip_anomalies,
    generate_ip_anomaly_alerts,
    lookup_threat_intelligence,
    detect_ip_anomalies,
    generate_ip_anomaly_alerts,
    add_health_alert_to_history,
    get_active_threats,
)
from app.services.netflow.stats import calculate_security_score
from app.services.shared.metrics import (
    track_performance,
    track_error,
    get_performance_metrics,
    get_performance_lock,
)
from app.services.shared.snmp import get_snmp_data, start_snmp_thread
from app.services.shared.cpu import calculate_cpu_percent_from_stat
from app.core.background import (
    start_threat_thread,
    start_trends_thread,
    start_agg_thread,
)
from app.services.shared.helpers import (
    is_internal,
    get_region,
    fmt_bytes,
    get_time_range,
    flag_from_iso,
    load_list,
    check_disk_space,
    format_duration,
    validate_ip_input,
)
from app.core.app_state import (
    _shutdown_event,
    _lock_summary,
    _lock_sources,
    _lock_dests,
    _lock_ports,
    _lock_protocols,
    _lock_alerts,
    _lock_flags,
    _lock_asns,
    _lock_durations,
    _lock_bandwidth,
    _lock_flows,
    _lock_countries,
    _lock_worldmap,
    _lock_proto_hierarchy,
    _lock_noise,
    _lock_attack_timeline,
    _lock_top_threats,
    _cache_lock,
    _mock_lock,
    _throttle_lock,
    _common_data_lock,
    _cpu_stat_lock,
    _stats_summary_cache,
    _stats_sources_cache,
    _stats_dests_cache,
    _stats_ports_cache,
    _stats_protocols_cache,
    _stats_alerts_cache,
    _stats_flags_cache,
    _stats_asns_cache,
    _stats_durations_cache,
    _stats_pkts_cache,
    _stats_countries_cache,
    _stats_talkers_cache,
    _stats_services_cache,
    _stats_hourly_cache,
    _stats_flow_stats_cache,
    _stats_proto_mix_cache,
    _stats_net_health_cache,
    _stats_proto_hierarchy_cache,
    _stats_noise_metrics_cache,
    _stats_attack_timeline_cache,
    _stats_top_threats_cache,
    _server_health_cache,
    _bandwidth_cache,
    _bandwidth_history_cache,
    _flows_cache,
    _common_data_cache,
    _request_times,
    _metric_nfdump_calls,
    _metric_stats_cache_hits,
    _metric_bw_cache_hits,
    _metric_conv_cache_hits,
    _metric_flow_cache_hits,
    _metric_http_429,
    _cpu_stat_prev,
    _threat_thread_started,
    _trends_thread_started,
    _agg_thread_started,
    _syslog_thread_started,
    _snmp_thread_started,
    _syslog_stats,
    _syslog_stats_lock,
    _syslog_buffer,
    _syslog_buffer_lock,
    _syslog_buffer_size,
    _snmp_cache,
    _snmp_cache_lock,
    _snmp_prev_sample,
    _snmp_backoff,
    _has_nfdump,
    _dns_resolver_executor,
    _flow_history,
    _flow_history_lock,
    _flow_history_ttl,
    _app_log_buffer,
    _app_log_buffer_lock,
    add_app_log,
)

# Import threats module to access threat state
import app.services.security.threats as threats_module
import app.core.app_state as state
from app.services.shared.config_helpers import (
    load_notify_cfg,
    save_notify_cfg,
    load_thresholds,
    save_thresholds,
    load_config,
    save_config,
)
from app.services.shared.formatters import format_time_ago, format_uptime
from app.services.shared.geoip import lookup_geo, load_city_db
import app.services.shared.geoip as geoip_module
from app.services.shared.dns import resolve_ip
import app.services.shared.dns as dns_module
from app.services.shared.decorators import throttle, cached_endpoint
from app.services.change_timeline import record_firewall_blocks_change
from app.db.sqlite import (
    _get_firewall_block_stats,
    _firewall_db_connect,
    _firewall_db_init,
    _trends_db_init,
    _get_bucket_end,
    _ensure_rollup_for_bucket,
    _trends_db_lock,
    _firewall_db_lock,
    _trends_db_connect,
)
from app.config import (
    FIREWALL_DB_PATH,
    TRENDS_DB_PATH,
    PORTS,
    PROTOS,
    SUSPICIOUS_PORTS,
    NOTIFY_CFG_PATH,
    THRESHOLDS_CFG_PATH,
    CONFIG_PATH,
    THREAT_WHITELIST,
    LONG_LOW_DURATION_THRESHOLD,
    LONG_LOW_BYTES_THRESHOLD,
    RULE_LABELS,
)

# Create Blueprint
logger = logging.getLogger(__name__)

# Routes extracted from netflow-dashboard.py
# Changed @app.route() to @bp.route()


@bp.route("/api/stats/net_health")
@throttle(30, 10)
@cached_endpoint(_stats_net_health_cache, _cache_lock, key_params=["range"])
def api_stats_net_health():
    """System Health Check (Operability Focus)."""
    range_key = request.args.get("range", "1h")
    now = time.time()
    tf = get_time_range(range_key)

    # 1. System Availability Checks
    health_score = 100
    status_issues = []

    # Check nfdump availability
    nfdump_available = state._has_nfdump if state._has_nfdump is not None else True
    if not nfdump_available:
        health_score = 0
        status_issues.append("NetFlow engine unavailable")

    # Check Syslog status (Firewall visibility)
    deps = state.get_dependency_health()
    syslog_generic_info = deps.get("syslog_514", {})
    syslog_fw_info = deps.get("syslog_515", {})

    syslog_generic_active = syslog_generic_info.get("listening", False)
    syslog_fw_active = syslog_fw_info.get("listening", False)

    # Check if we have RECENT logs (stalls)
    last_log_ts_generic = syslog_generic_info.get("last_packet_time")
    last_log_ts_fw = syslog_fw_info.get("last_packet_time")

    # Use the most recent log time from either source
    last_log_ts = last_log_ts_generic
    if last_log_ts_fw and (not last_log_ts or last_log_ts_fw > last_log_ts):
        last_log_ts = last_log_ts_fw

    syslog_stalled = False
    if last_log_ts and (now - last_log_ts > 3600):  # No logs for 1 hour
        syslog_stalled = True
        status_issues.append("Syslog ingestion stalled > 1h")
        health_score -= 20

    if not (syslog_generic_active or syslog_fw_active):
        status_issues.append("Syslog receivers inactive")
        health_score -= 10  # Not critical as NetFlow might still work

    # Check Database
    with _firewall_db_lock:
        try:
            conn = _firewall_db_connect()
            conn.close()
        except sqlite3.Error:
            health_score -= 20
            status_issues.append("Database connection failed")

    # 2. Traffic Indicators
    indicators = []
    try:
        output = run_nfdump(["-n", "1000"], tf)
        if output and isinstance(output, str) and output.strip():
            lines = output.strip().split("\n")
            total_flows = 0
            rst_count = 0
            syn_only = 0
            icmp_count = 0
            for line in lines[1:]:
                if not line or line.startswith("ts,"):
                    continue
                total_flows += 1
                if "R" in line:
                    rst_count += 1
                if "S" in line and "A" not in line:
                    syn_only += 1
                if "ICMP" in line or ",1," in line:
                    icmp_count += 1

            if total_flows > 0:
                rst_pct = rst_count / total_flows * 100
                syn_pct = syn_only / total_flows * 100
                icmp_pct = icmp_count / total_flows * 100
                if rst_pct > 15:
                    indicators.append(
                        {
                            "name": "TCP Resets",
                            "value": f"{rst_pct:.1f}%",
                            "status": "warn",
                            "icon": "⚠️",
                        }
                    )
                    threats_module.add_health_signal(
                        "tcp_reset",
                        f"Elevated TCP Resets: {rst_pct:.1f}%",
                        level="elevated",
                    )
                elif rst_pct < 5:
                    indicators.append(
                        {
                            "name": "TCP Resets",
                            "value": f"{rst_pct:.1f}%",
                            "status": "good",
                            "icon": "✅",
                        }
                    )
                if syn_pct > 10:
                    indicators.append(
                        {
                            "name": "SYN-Only Flows",
                            "value": f"{syn_pct:.1f}%",
                            "status": "warn",
                            "icon": "⚠️",
                        }
                    )
                    threats_module.add_health_signal(
                        "syn_scan",
                        f"Elevated SYN-Only Flows: {syn_pct:.1f}%",
                        level="elevated",
                    )
                if icmp_pct > 15:
                    indicators.append(
                        {
                            "name": "ICMP Traffic",
                            "value": f"{icmp_pct:.1f}%",
                            "status": "warn",
                            "icon": "⚠️",
                        }
                    )
    except Exception as e:
        status_issues.append(f"Traffic analysis error: {str(e)[:30]}")
        health_score -= 10

    # 3. Determine Overall Status
    health_score = max(0, min(100, health_score))
    if health_score >= 80:
        status, status_text, status_icon = "healthy", "Healthy", "💚"
    elif health_score >= 40:
        status, status_text, status_icon = "fair", "Degraded", "💛"
    else:
        status, status_text, status_icon = "poor", "Unavailable", "❤️"

    if status_issues:
        indicators.insert(
            0,
            {
                "name": "System Issues",
                "value": str(len(status_issues)),
                "status": "bad",
                "icon": "🔧",
            },
        )
        for issue in status_issues:
            indicators.append(
                {"name": "Status", "value": issue, "status": "bad", "icon": "⚠️"}
            )

    return {
        "indicators": indicators,
        "health_score": health_score,
        "status": status,
        "status_text": status_text,
        "status_icon": status_icon,
        "total_flows": 0,
        "firewall_active": syslog_fw_active or syslog_generic_active,
        "blocks_1h": 0,
    }


# ===== Trends (5-minute rollups stored in SQLite) =====


@bp.route("/api/firewall/logs/stats")
@throttle(5, 10)
def api_firewall_logs_stats():
    """Get firewall log statistics."""
    range_key = request.args.get("range", "1h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 3600)
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Total blocks and passes
            cur = conn.execute(
                """
                SELECT action, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? GROUP BY action
            """,
                (cutoff,),
            )
            counts = {row[0]: row[1] for row in cur.fetchall()}

            blocks = counts.get("block", 0) + counts.get("reject", 0)
            passes = counts.get("pass", 0)

            # Unique blocked IPs
            cur = conn.execute(
                """
                SELECT COUNT(DISTINCT src_ip) FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """,
                (cutoff,),
            )
            unique_blocked = cur.fetchone()[0] or 0

            # Top blocked ports
            cur = conn.execute(
                """
                SELECT dst_port, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject') AND dst_port > 0
                GROUP BY dst_port ORDER BY cnt DESC LIMIT 10
            """,
                (cutoff,),
            )
            top_ports = [
                {
                    "port": row[0],
                    "count": row[1],
                    "service": PORTS.get(row[0], "Unknown"),
                }
                for row in cur.fetchall()
            ]

            # Top blocked countries
            cur = conn.execute(
                """
                SELECT country_iso, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject') AND country_iso IS NOT NULL
                GROUP BY country_iso ORDER BY cnt DESC LIMIT 10
            """,
                (cutoff,),
            )
            top_countries = [{"iso": row[0], "count": row[1]} for row in cur.fetchall()]

            data = {
                "blocks": blocks,
                "passes": passes,
                "unique_blocked": unique_blocked,
                "top_ports": top_ports,
                "top_countries": top_countries,
            }
            return jsonify(data)
        except (sqlite3.Error, ValueError, KeyError, TypeError) as e:
            add_app_log(f"Firewall stats error: {e}", "ERROR")
            return jsonify({"error": str(e)}), 500


# ===== Hosts Page =====


@bp.route("/api/hosts/stats")
@throttle(5, 10)
def api_hosts_stats():
    """Get summarized host statistics."""
    from app.services.netflow.netflow import get_merged_host_stats
    from app.services.security.threats import is_ip_threat, get_recent_alert_ips
    from datetime import datetime, timedelta

    # Fetch 48h stats to determine new hosts (baseline comparison)
    hosts_48h = get_merged_host_stats("48h", limit=10000)

    # 24h stats for Total Hosts count (to be consistent with the "Total Hosts (24h)" label)
    # Note: hosts_48h contains 24h hosts too, but we want the count specifically for the last 24h window
    hosts_24h = [
        h
        for h in hosts_48h
        if h.get("last_seen", "")
        > (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    ]
    total_hosts = len(hosts_24h)

    # Active hosts (current window: 1h)
    cutoff_1h = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    active_hosts = sum(1 for h in hosts_48h if h.get("last_seen", "") > cutoff_1h)

    # New Hosts (last hour) Logic
    # Check if we have sufficient history (data older than ~1h)
    new_hosts = 0
    new_hosts_display = "—"

    all_first_seens = [h["first_seen"] for h in hosts_48h if h.get("first_seen")]
    if all_first_seens:
        # Lexical sort works for nfdump ISO timestamps
        min_seen = min(all_first_seens)
        cutoff_1h_str = (datetime.now() - timedelta(hours=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # If the oldest data point is newer than ~1h ago, we are still warming up
        # We give a 1-minute buffer to be safe against slight clock skews/intervals
        baseline_check_str = (datetime.now() - timedelta(minutes=59)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        if min_seen > baseline_check_str:
            new_hosts_display = "Baseline warming"
        else:
            # We have history. Count hosts first seen AFTER the 1h cutoff
            count = sum(1 for h in hosts_48h if h.get("first_seen", "") > cutoff_1h_str)
            new_hosts_display = count

    # Anomalies Logic
    # 1. IPs currently in threat feeds
    anomaly_ips = set()
    for host in hosts_24h:
        if is_ip_threat(host["ip"]):
            anomaly_ips.add(host["ip"])

    # 2. IPs involved in recent behavioral alerts (last 24h)
    recent_alerts = get_recent_alert_ips(86400)
    anomaly_ips.update(recent_alerts)

    anomalies = len(anomaly_ips)

    data = {
        "total_hosts": total_hosts,
        "active_hosts": active_hosts,
        "new_hosts": new_hosts_display,
        "anomalies": anomalies,
    }
    return jsonify(data)


@bp.route("/api/hosts/list")
@throttle(5, 10)
def api_hosts_list():
    """Get list of hosts."""
    range_key = request.args.get("range", "24h")
    try:
        limit = int(request.args.get("limit", 100))
    except (ValueError, TypeError):
        limit = 100

    from app.services.netflow.netflow import get_merged_host_stats

    data = get_merged_host_stats(range_key, limit=limit)
    try:
        from app.db.sqlite import get_hosts_metadata

        meta = get_hosts_metadata([h.get("ip") for h in data if h.get("ip")])
        for host in data:
            host_meta = meta.get(host.get("ip"), {})
            host.update(
                {
                    "tags": host_meta.get("tags", []),
                    "owner": host_meta.get("owner", ""),
                    "device_type": host_meta.get("device_type", ""),
                    "criticality": host_meta.get("criticality", ""),
                    "notes": host_meta.get("notes", ""),
                }
            )
    except Exception as e:
        add_app_log(f"Host metadata merge failed: {e}", "WARN")
    return jsonify(data)


@bp.route("/api/hosts/<path:ip>/detail")
@throttle(10, 20)
def api_host_detail(ip):
    """Get details for a specific host."""
    try:
        validate_ip_input(ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Overview: Geo, ASN, DNS
    from app.services.shared.geoip import lookup_geo
    from app.services.shared.dns import resolve_ip

    from app.services.security.threats import is_ip_threat, get_threat_info

    geo = lookup_geo(ip) or {}
    hostname = resolve_ip(ip) if ip else ""
    is_threat = is_ip_threat(ip)
    threat_info = get_threat_info(ip) if is_threat else {}

    # Activity: recent ports/destinations
    from app.services.netflow.netflow import (
        run_nfdump,
        parse_csv,
        get_time_range,
        get_traffic_direction,
    )
    from app.config import PORTS, REGION_MAPPING

    # Use 48h range to match Hosts List baseline
    tf = get_time_range("48h")

    # Traffic Direction
    direction = get_traffic_direction(ip, tf)

    # Insight: "Src Ports" in the UI should reflect "Services Hosted" (Inbound traffic to this node)
    # Standard "Source Ports" are usually random ephemeral ports and not useful.
    # So we map "src_ports" -> Destination Ports of INBOUND flows (dst ip = this host)
    inbound_svc_csv = run_nfdump(
        ["-s", "dstport/bytes", "-n", "10", "dst", "ip", ip], tf
    )
    src_ports = parse_csv(inbound_svc_csv, expected_key="dp")
    for p in src_ports:
        try:
            port_num = int(p.get("key", 0))
            p["service"] = PORTS.get(port_num, "Unknown")
        except (ValueError, TypeError):
            p["service"] = "Unknown"

    # Insight: "Dst Ports" in the UI should reflect "Services Accessed" (Outbound traffic from this node)
    # This maps to Destination Ports of OUTBOUND flows (src ip = this host)
    outbound_svc_csv = run_nfdump(
        ["-s", "dstport/bytes", "-n", "10", "src", "ip", ip], tf
    )
    dst_ports = parse_csv(outbound_svc_csv, expected_key="dp")
    for p in dst_ports:
        try:
            port_num = int(p.get("key", 0))
            p["service"] = PORTS.get(port_num, "Unknown")
        except (ValueError, TypeError):
            p["service"] = "Unknown"

    # Region
    region_val = ""
    if geo:
        country = geo.get("country_code", "")
        region_val = REGION_MAPPING.get(country, "🌐 Global")

    # Host memory: get persisted first_seen and is_new status
    from app.db.sqlite import get_host_memory
    from datetime import datetime, timedelta

    memory = get_host_memory(ip)
    is_new = False
    first_seen_iso = None

    if memory:
        first_seen_iso = memory["first_seen_iso"]
        try:
            timestamp_str = (
                first_seen_iso.split(".")[0]
                if "." in first_seen_iso
                else first_seen_iso
            )
            first_seen_dt = datetime.strptime(
                timestamp_str.strip(), "%Y-%m-%d %H:%M:%S"
            )
            cutoff_24h = datetime.now() - timedelta(hours=24)
            is_new = first_seen_dt > cutoff_24h
        except (ValueError, AttributeError):
            pass

    from app.db.sqlite import get_host_metadata

    metadata = get_host_metadata(ip) or {}

    data = {
        "ip": ip,
        "hostname": hostname,
        "geo": geo,
        "region": region_val,
        "is_threat": is_threat,
        "threat_info": threat_info,
        "direction": direction,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "is_new": is_new,
        "first_seen": first_seen_iso,
        "metadata": metadata,
    }
    return jsonify(data)


@bp.route("/api/hosts/<path:ip>/metadata", methods=["GET", "POST"])
@throttle(5, 10)
def api_host_metadata(ip):
    """Get or update host metadata."""
    try:
        validate_ip_input(ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    from app.db.sqlite import get_host_metadata, upsert_host_metadata

    if request.method == "GET":
        data = get_host_metadata(ip) or {}
        return jsonify(
            {
                "tags": data.get("tags", []),
                "owner": data.get("owner", ""),
                "device_type": data.get("device_type", ""),
                "criticality": data.get("criticality", ""),
                "notes": data.get("notes", ""),
            }
        )

    payload = request.get_json(silent=True) or {}
    tags = payload.get("tags", [])
    owner = payload.get("owner", "")
    device_type = payload.get("device_type", "")
    criticality = payload.get("criticality", "")
    notes = payload.get("notes", "")

    data = (
        upsert_host_metadata(
            ip,
            tags=tags,
            owner=owner,
            device_type=device_type,
            criticality=criticality,
            notes=notes,
        )
        or {}
    )
    return jsonify(data)


@bp.route("/api/hosts/<path:ip>/timeline")
@throttle(10, 20)
def api_host_timeline(ip):
    """Get lightweight hourly activity timeline for a host."""
    try:
        validate_ip_input(ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    from app.services.netflow.netflow import run_nfdump, parse_csv, get_time_range
    from datetime import datetime, timedelta

    range_key = request.args.get("range", "24h")
    tf = get_time_range(range_key)

    # Query flows where IP is source or destination
    # Get raw flows (not aggregated) so we can group by hour
    src_flows = run_nfdump(["-n", "10000", f"src ip {ip}"], tf)
    dst_flows = run_nfdump(["-n", "10000", f"dst ip {ip}"], tf)

    # Parse CSV flows
    src_rows = parse_csv(src_flows, expected_key=None)  # Raw flows, no aggregation
    dst_rows = parse_csv(dst_flows, expected_key=None)

    # Combine and aggregate by hour
    hourly_data = {}

    def parse_timestamp(ts_str):
        """Parse nfdump timestamp to hour bucket."""
        try:
            # Format: "2023-01-01 12:34:56.789"
            dt = datetime.strptime(ts_str.split(".")[0], "%Y-%m-%d %H:%M:%S")
            # Round to hour
            hour_dt = dt.replace(minute=0, second=0, microsecond=0)
            return hour_dt
        except (ValueError, TypeError):
            return None

    # Process source flows (upload)
    for row in src_rows:
        ts = row.get("ts")
        if not ts:
            continue
        hour_dt = parse_timestamp(ts)
        if not hour_dt:
            continue

        hour_key = hour_dt.strftime("%Y-%m-%d %H:00")
        if hour_key not in hourly_data:
            hourly_data[hour_key] = {"bytes": 0, "flows": 0, "timestamp": hour_dt}

        # Raw flows use 'ibyt' for bytes, aggregated uses 'bytes'
        bytes_val = row.get("ibyt") or row.get("bytes", 0)
        hourly_data[hour_key]["bytes"] += bytes_val
        hourly_data[hour_key]["flows"] += 1

    # Process destination flows (download)
    for row in dst_rows:
        ts = row.get("ts")
        if not ts:
            continue
        hour_dt = parse_timestamp(ts)
        if not hour_dt:
            continue

        hour_key = hour_dt.strftime("%Y-%m-%d %H:00")
        if hour_key not in hourly_data:
            hourly_data[hour_key] = {"bytes": 0, "flows": 0, "timestamp": hour_dt}

        # Raw flows use 'ibyt' for bytes, aggregated uses 'bytes'
        bytes_val = row.get("ibyt") or row.get("bytes", 0)
        hourly_data[hour_key]["bytes"] += bytes_val
        hourly_data[hour_key]["flows"] += 1

    # Sort by timestamp and format for frontend
    sorted_hours = sorted(hourly_data.items(), key=lambda x: x[1]["timestamp"])

    labels = [h[0] for h in sorted_hours]
    bytes_data = [h[1]["bytes"] for h in sorted_hours]
    flows_data = [h[1]["flows"] for h in sorted_hours]

    return jsonify({"labels": labels, "bytes": bytes_data, "flows": flows_data})


# ===== Discovery (Active) =====


@bp.route("/api/discovery/subnets")
def api_discovery_subnets():
    """Get detected local subnets."""
    from app.services.security.discovery import get_local_subnets

    subnets = get_local_subnets()
    return jsonify(subnets)


@bp.route("/api/discovery/scan", methods=["POST"])
@throttle(2, 60)  # Strict throttling for active scanning
def api_discovery_scan():
    """Trigger an active network scan."""
    from app.services.security.discovery import scan_network

    data = request.get_json() or {}
    target = data.get("target")

    if not target:
        return jsonify({"error": "Target CIDR required"}), 400

    result = scan_network(target)

    if "error" in result:
        return jsonify(result), 500

    return jsonify(result)


@bp.route("/api/firewall/logs/blocked")
@throttle(5, 10)
def api_firewall_logs_blocked():
    """Get top blocked IPs."""
    range_key = request.args.get("range", "1h")
    limit = min(int(request.args.get("limit", 20)), 100)
    range_seconds = {
        "15m": 900,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 3600)
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute(
                """
                SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT dst_port) as ports,
                       MAX(country_iso) as country, MAX(is_threat) as is_threat
                FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
                GROUP BY src_ip ORDER BY cnt DESC LIMIT ?
            """,
                (cutoff, limit),
            )

            blocked_ips = []
            for row in cur.fetchall():
                ports_str = row[3] or ""
                ports_list = [int(p) for p in ports_str.split(",") if p.isdigit()][:5]

                ip = row[0]
                geo = lookup_geo(ip)

                blocked_ips.append(
                    {
                        "ip": ip,
                        "count": row[1],
                        "last_seen": datetime.fromtimestamp(row[2]).isoformat()
                        if row[2]
                        else None,
                        "ports_targeted": ports_list,
                        "country": geo.get("country") if geo else None,
                        "country_iso": row[4],
                        "flag": flag_from_iso(row[4]) if row[4] else "",
                        "is_threat": bool(row[5]),
                        "hostname": resolve_ip(ip),
                    }
                )
        finally:
            conn.close()

    return jsonify({"blocked_ips": blocked_ips})


@bp.route("/api/firewall/logs/timeline")
@throttle(5, 10)
def api_firewall_logs_timeline():
    """Get hourly timeline of blocks/passes."""
    range_key = request.args.get("range", "24h")
    range_seconds = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}.get(
        range_key, 86400
    )
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Group by hour
            cur = conn.execute(
                """
                SELECT
                    CAST((timestamp / 3600) AS INTEGER) * 3600 as hour_ts,
                    action,
                    COUNT(*) as cnt
                FROM fw_logs
                WHERE timestamp > ?
                GROUP BY hour_ts, action
                ORDER BY hour_ts
            """,
                (cutoff,),
            )

            hours_data = {}
            for row in cur.fetchall():
                hour_ts = row[0]
                action = row[1]
                count = row[2]

                if hour_ts not in hours_data:
                    hours_data[hour_ts] = {"blocks": 0, "passes": 0}

                if action in ("block", "reject"):
                    hours_data[hour_ts]["blocks"] += count
                elif action == "pass":
                    hours_data[hour_ts]["passes"] += count
        finally:
            conn.close()

    timeline = [
        {
            "hour": datetime.fromtimestamp(ts).isoformat(),
            "hour_ts": ts,
            "blocks": data["blocks"],
            "passes": data["passes"],
        }
        for ts, data in sorted(hours_data.items())
    ]

    return jsonify({"timeline": timeline})


@bp.route("/api/firewall/logs/recent")
@throttle(100, 10)
def api_firewall_logs_recent():
    """Get most recent firewall log entries."""
    range_key = request.args.get("range", "1h")
    limit = min(int(request.args.get("limit", 300)), 1000)
    action_filter = request.args.get("action")
    since_ts = request.args.get("since")

    range_map = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }
    range_seconds = range_map.get(range_key, 3600)

    now = time.time()
    cutoff_range = now - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Build query with optional filters
            where_clauses = []
            params = []

            if since_ts:
                try:
                    since_float = float(since_ts)
                    where_clauses.append("timestamp > ?")
                    params.append(since_float)
                except (ValueError, TypeError):
                    pass  # Ignore invalid since parameter

            if action_filter:
                where_clauses.append("action = ?")
                params.append(action_filter)

            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
            params.append(limit)

            query = f"""
                SELECT timestamp, timestamp_iso, action, direction, interface, src_ip, src_port,
                       dst_ip, dst_port, proto, country_iso, is_threat, rule_label
                FROM fw_logs WHERE {where_sql} ORDER BY timestamp DESC LIMIT ?
            """

            try:
                cur = conn.execute(query, params)
            except sqlite3.OperationalError as e:
                # Self-healing: If column is missing (migration didn't run), add it now
                if "no such column: rule_label" in str(e):
                    add_app_log(
                        "Self-healing: Adding missing rule_label column to fw_logs",
                        "WARN",
                    )
                    conn.execute("ALTER TABLE fw_logs ADD COLUMN rule_label TEXT")
                    conn.commit()
                    # Retry query
                    cur = conn.execute(query, params)
                else:
                    raise

            logs = []
            action_counts = {"block": 0, "reject": 0, "pass": 0}
            unique_src = set()
            unique_dst = set()
            threat_count = 0
            blocks_last_hour = 0
            passes_last_hour = 0
            latest_ts = None

            rows = cur.fetchall()
        finally:
            conn.close()

    # Process rows OUTSIDE the lock to reduce contention
    logs = []
    action_counts = {"block": 0, "reject": 0, "pass": 0}
    unique_src = set()
    unique_dst = set()
    threat_count = 0
    blocks_in_range = 0
    passes_in_range = 0
    latest_ts = None

    for row in rows:
        ts = row[0]
        ts_iso = row[1]
        action = row[2]
        direction = row[3]
        iface = row[4]
        src_ip = row[5]
        src_port = row[6]
        dst_ip = row[7]
        dst_port = row[8]
        proto = row[9]
        country_iso = row[10]
        is_threat = bool(row[11])
        rule_label = row[12] if len(row) > 12 else None

        # Stats
        if action in action_counts:
            action_counts[action] += 1
        if is_threat:
            threat_count += 1
        if ts and action in ("block", "reject") and ts >= cutoff_range:
            blocks_in_range += 1
        if ts and action == "pass" and ts >= cutoff_range:
            passes_in_range += 1
        if src_ip:
            unique_src.add(src_ip)
        if dst_ip:
            unique_dst.add(dst_ip)
        if ts and (latest_ts is None or ts > latest_ts):
            latest_ts = ts

        # Apply human-readable mapping (using pre-imported RULE_LABELS)
        rule_label_display = rule_label
        if rule_label:
            if rule_label in RULE_LABELS:
                rule_label_display = RULE_LABELS[rule_label]
            elif len(rule_label) > 12:
                # Truncate long hashes if not mapped
                rule_label_display = f"{rule_label[:8]}..."

        logs.append(
            {
                "timestamp": ts_iso,
                "timestamp_ts": ts,
                "action": action,
                "direction": direction,
                "interface": iface,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "country_iso": country_iso,
                "flag": flag_from_iso(country_iso) if country_iso else "",
                "is_threat": is_threat,
                "service": PORTS.get(dst_port, "") if dst_port else "",
                "rule_label": rule_label_display,
                "rule_label_full": rule_label,  # Keep full label for tooltip
            }
        )

    stats = {
        "total": len(logs),
        "actions": action_counts,
        "threats": threat_count,
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "blocks_last_hour": blocks_in_range,
        "passes_last_hour": passes_in_range,
        "latest_ts": latest_ts,
    }

    with _syslog_stats_lock:
        receiver_stats = dict(_syslog_stats)
    return jsonify({"logs": logs, "stats": stats, "receiver_stats": receiver_stats})


@bp.route("/api/firewall/syslog/recent")
@throttle(100, 10)
def api_firewall_syslog_recent():
    """Get recent syslog entries from port 515 (OPNsense general syslog)."""
    limit = min(int(request.args.get("limit", 300)), 1000)
    program_filter = request.args.get("program")  # Filter by program name

    try:
        from app.services.syslog.syslog_store import syslog_store
        from app.services.syslog.firewall_listener import get_firewall_syslog_stats

        # Get events from syslog store
        events = syslog_store.get_events(limit=limit)

        # Apply program filter if specified
        if program_filter:
            events = [e for e in events if e.get("program") == program_filter]

        # Get stats
        stats = syslog_store.get_stats()

        # Get receiver stats from authoritative shared health
        deps = state.get_dependency_health()
        syslog_status = deps.get("syslog_515", {})

        receiver_stats = {
            "received": syslog_status.get("received", 0),
            "parsed": syslog_status.get("parsed", 0),
            "errors": syslog_status.get("errors", 0),
            "last_log": syslog_status.get("last_packet_time"),
            "listening": syslog_status.get("listening", False),
        }

        return jsonify(
            {"logs": events, "stats": stats, "receiver_stats": receiver_stats}
        )

    except (sqlite3.Error, ValueError, KeyError, TypeError) as e:
        add_app_log(f"Error in syslog API: {e}", "ERROR")
        return jsonify(
            {"error": str(e), "logs": [], "stats": {}, "receiver_stats": {}}
        ), 500


@bp.route("/api/alerts")
@throttle(5, 10)
@cached_endpoint(_stats_alerts_cache, _lock_alerts, key_params=["range"])
def api_alerts():
    range_key = request.args.get("range", "1h")
    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    sources = get_common_nfdump_data("sources", range_key)[:50]
    dests = get_common_nfdump_data("dests", range_key)[:50]
    ports = get_common_nfdump_data("ports", range_key)

    # 1. Detect anomalies and escalate to alerts (stateful)
    raw_alerts = detect_anomalies(
        ports, sources, threat_set, whitelist, destinations_data=dests
    )

    # 2. Run all other detections
    try:
        protocols_data = get_common_nfdump_data("protos", range_key)[:20]
        flow_data = get_raw_flows(tf, limit=2000)
        run_all_detections(ports, sources, dests, protocols_data, flow_data=flow_data)
    except Exception as e:
        add_app_log(f"Additional detection run failed: {e}", "ERROR")

    # 3. Retrieve QUALIFIED, ACTIVE alerts from history
    from app.services.security.threats import auto_resolve_stale_alerts

    auto_resolve_stale_alerts()

    active_alerts = []
    with threats_module._alert_history_lock:
        active_alerts = list(
            [a for a in threats_module._alert_history if a.get("active", True)]
        )
        active_alerts.sort(key=lambda x: x.get("ts", 0), reverse=True)

    return {
        "alerts": active_alerts,
        "count": len(active_alerts),
        "feed_label": get_feed_label(),
    }


@bp.route("/api/health/baseline-signals")
@throttle(5, 10)
def api_health_baseline_signals():
    """Get baseline-aware health signals for overall health classification.

    Returns signals based on baseline deviations rather than static thresholds.
    This enables environment-specific, adaptive health classification.
    """
    from app.services.shared.baselines import is_abnormal, get_baseline_stats
    from app.services.netflow.netflow import run_nfdump
    from app.services.shared.helpers import get_time_range, is_internal
    from app.config import LONG_LOW_DURATION_THRESHOLD, LONG_LOW_BYTES_THRESHOLD
    import time

    range_key = request.args.get("range", "1h")
    now = time.time()
    tf_range = get_time_range(range_key)

    # Map range keys to hours for normalization
    range_map = {"15m": 0.25, "30m": 0.5, "1h": 1, "6h": 6, "24h": 24, "7d": 168}
    range_hours = range_map.get(range_key, 1)

    signals = []
    signal_details = []

    # Get current metric values
    # 1. Active Flows
    try:
        full_output = run_nfdump(
            ["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-q"], tf_range
        )
        active_flows = 0
        if full_output:
            lines = full_output.strip().split("\n")
            for line in lines:
                if (
                    line
                    and not line.startswith("ts,")
                    and not line.startswith("firstSeen,")
                    and not line.startswith("Date,")
                    and "," in line
                ):
                    parts = line.split(",")
                    if len(parts) > 7:
                        active_flows += 1
    except (ValueError, TypeError, IndexError, OSError):
        active_flows = 0

    # 2. External Connections (sample-based estimate)
    external_connections = 0
    if active_flows > 0:
        try:
            sample_output = run_nfdump(
                ["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", "500"],
                tf_range,
            )
            sample_count = 0
            sample_external = 0
            if sample_output:
                lines = sample_output.strip().split("\n")
                start_idx = 0
                sa_idx = 0
                da_idx = 0
                if lines:
                    line0 = lines[0]
                    if (
                        "ts" in line0
                        or "Date" in line0
                        or "ibyt" in line0
                        or "firstSeen" in line0
                        or "firstseen" in line0
                    ):
                        header = line0.split(",")
                        try:
                            sa_key = "sa" if "sa" in header else "srcAddr"
                            if "srcaddr" in header:
                                sa_key = "srcaddr"
                            da_key = "da" if "da" in header else "dstAddr"
                            if "dstaddr" in header:
                                da_key = "dstaddr"
                            if sa_key in header:
                                sa_idx = header.index(sa_key)
                            if da_key in header:
                                da_idx = header.index(da_key)
                            start_idx = 1
                        except ValueError:
                            pass
                for line in lines[start_idx:]:
                    if (
                        not line
                        or line.startswith("ts,")
                        or line.startswith("firstSeen,")
                        or line.startswith("Date,")
                    ):
                        continue
                    parts = line.split(",")
                    if len(parts) > 7:
                        try:
                            src = (
                                parts[sa_idx]
                                if len(parts) > sa_idx and sa_idx < len(parts)
                                else ""
                            )
                            dst = (
                                parts[da_idx]
                                if len(parts) > da_idx and da_idx < len(parts)
                                else ""
                            )
                            if src and dst:
                                sample_count += 1
                                src_internal = is_internal(src)
                                dst_internal = is_internal(dst)
                                if not (src_internal and dst_internal):
                                    sample_external += 1
                        except (ValueError, TypeError, IndexError):
                            pass
                if sample_count > 0:
                    external_ratio = sample_external / sample_count
                    external_connections = int(active_flows * external_ratio)
        except (ValueError, TypeError, IndexError, KeyError):
            pass

    # 3. Firewall Blocks (24h)
    blocked_events_24h = 0
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cutoff_range = now - (range_hours * 3600)
                cur = conn.execute(
                    """
                    SELECT COUNT(*) FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                """,
                    (cutoff_range,),
                )
                blocked_events_24h = cur.fetchone()[0] or 0
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        blocked_events_24h = 0

    # 4. Anomalies (24h)
    anomalies_24h = 0
    try:
        output_24h = run_nfdump(
            ["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto"], tf_range
        )
        if output_24h:
            lines_24h = output_24h.strip().split("\n")
            start_idx_24h = 0
            sa_idx_24h = 0
            da_idx_24h = 0
            ibyt_idx_24h = 0
            td_idx_24h = 0
            if lines_24h:
                line0_24h = lines_24h[0]
                if (
                    "ts" in line0_24h
                    or "Date" in line0_24h
                    or "ibyt" in line0_24h
                    or "firstSeen" in line0_24h
                    or "firstseen" in line0_24h
                ):
                    header_24h = line0_24h.split(",")
                    try:
                        sa_key_24h = "sa" if "sa" in header_24h else "srcAddr"
                        if "srcaddr" in header_24h:
                            sa_key_24h = "srcaddr"
                        da_key_24h = "da" if "da" in header_24h else "dstAddr"
                        if "dstaddr" in header_24h:
                            da_key_24h = "dstaddr"
                        ibyt_key_24h = "ibyt" if "ibyt" in header_24h else "bytes"
                        if sa_key_24h in header_24h:
                            sa_idx_24h = header_24h.index(sa_key_24h)
                        if da_key_24h in header_24h:
                            da_idx_24h = header_24h.index(da_key_24h)
                        if ibyt_key_24h in header_24h:
                            ibyt_idx_24h = header_24h.index(ibyt_key_24h)
                        if "td" in header_24h:
                            td_idx_24h = header_24h.index("td")
                        elif "duration" in header_24h:
                            td_idx_24h = header_24h.index("duration")
                        start_idx_24h = 1
                    except ValueError:
                        pass
            for line in lines_24h[start_idx_24h:]:
                if (
                    not line
                    or line.startswith("ts,")
                    or line.startswith("firstSeen,")
                    or line.startswith("Date,")
                ):
                    continue
                parts = line.split(",")
                if len(parts) > 7:
                    try:
                        duration = (
                            float(parts[td_idx_24h])
                            if len(parts) > td_idx_24h and td_idx_24h < len(parts)
                            else 0.0
                        )
                        src = (
                            parts[sa_idx_24h]
                            if len(parts) > sa_idx_24h and sa_idx_24h < len(parts)
                            else ""
                        )
                        dst = (
                            parts[da_idx_24h]
                            if len(parts) > da_idx_24h and da_idx_24h < len(parts)
                            else ""
                        )
                        b = (
                            int(parts[ibyt_idx_24h])
                            if len(parts) > ibyt_idx_24h and ibyt_idx_24h < len(parts)
                            else 0
                        )
                        if src and dst:
                            src_internal = is_internal(src)
                            dst_internal = is_internal(dst)
                            is_external = not (src_internal and dst_internal)
                            if (
                                is_external
                                and duration > LONG_LOW_DURATION_THRESHOLD
                                and b < LONG_LOW_BYTES_THRESHOLD
                            ):
                                anomalies_24h += 1
                    except (ValueError, TypeError, IndexError):
                        pass
    except (ValueError, TypeError, IndexError, KeyError):
        anomalies_24h = 0

    # Check baselines for each metric
    # Active Flows
    active_flows_check = is_abnormal("active_flows", active_flows)
    if active_flows_check and active_flows_check["abnormal"]:
        signals.append("active_flows_spike")
        signal_details.append(
            f"active flows spike ({active_flows} vs baseline {active_flows_check['baseline_mean']:.0f})"
        )

    # External Connections
    external_check = is_abnormal("external_connections", external_connections)
    if external_check and external_check["abnormal"]:
        signals.append("external_connections_spike")
        signal_details.append(
            f"external connections spike ({external_connections} vs baseline {external_check['baseline_mean']:.0f})"
        )

    # Firewall Blocks Rate
    blocks_rate = blocked_events_24h / 24.0 if blocked_events_24h > 0 else 0.0
    blocks_check = is_abnormal("firewall_blocks_rate", blocks_rate)
    if blocks_check and "abnormal" in blocks_check:
        record_firewall_blocks_change(blocks_check["abnormal"])
    if blocks_check and blocks_check["abnormal"]:
        signals.append("firewall_blocks_spike")
        signal_details.append(
            f"firewall blocks spike ({blocked_events_24h} in 24h, {blocks_rate:.1f}/hr vs baseline {blocks_check['baseline_mean']:.1f}/hr)"
        )

    # Anomalies Rate
    anomalies_rate = anomalies_24h / 24.0 if anomalies_24h > 0 else 0.0
    anomalies_check = is_abnormal("anomalies_rate", anomalies_rate)
    if anomalies_check and anomalies_check["abnormal"]:
        signals.append("anomalies_spike")
        signal_details.append(
            f"network anomalies spike ({anomalies_24h} in 24h, {anomalies_rate:.1f}/hr vs baseline {anomalies_check['baseline_mean']:.1f}/hr)"
        )

    # Also check if anomalies exist at all (even if not spiking)
    if anomalies_24h > 0:
        signals.append("anomalies_present")
        signal_details.append(
            f"{anomalies_24h} network anomal{'ies' if anomalies_24h > 1 else 'y'}"
        )

    # Get full baseline stats for visualization
    baseline_stats = {}
    for metric in [
        "active_flows",
        "external_connections",
        "firewall_blocks_rate",
        "anomalies_rate",
    ]:
        stats = get_baseline_stats(metric)
        if stats:
            baseline_stats[metric] = {
                "mean": round(stats["mean"], 1),
                "stddev": round(stats["stddev"], 1),
                "min": round(stats["min"], 1),
                "max": round(stats["max"], 1),
                "count": stats["count"],
                "normal_low": round(max(0, stats["mean"] - stats["stddev"]), 1),
                "normal_high": round(stats["mean"] + stats["stddev"], 1),
            }

    return jsonify(
        {
            "signals": signals,
            "signal_details": signal_details,
            "metrics": {
                "active_flows": active_flows,
                "external_connections": external_connections,
                "blocked_events_24h": blocked_events_24h,
                "anomalies_24h": anomalies_24h,
            },
            "baselines_available": {
                "active_flows": get_baseline_stats("active_flows") is not None,
                "external_connections": get_baseline_stats("external_connections")
                is not None,
                "firewall_blocks_rate": get_baseline_stats("firewall_blocks_rate")
                is not None,
                "anomalies_rate": get_baseline_stats("anomalies_rate") is not None,
            },
            "baseline_stats": baseline_stats,
        }
    )


@bp.route("/api/ip_detail/<ip>")
@throttle(5, 10)
def api_ip_detail(ip):
    """Get detailed information about an IP address including traffic patterns, ports, protocols, and geo data."""
    try:
        validate_ip_input(ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    start_threat_thread()

    # Support range parameter (default to 1h for backwards compatibility)
    range_key = request.args.get("range", "1h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 3600)
    dt = datetime.now()
    start_dt = dt - timedelta(seconds=range_seconds)
    tf = f"{start_dt.strftime('%Y/%m/%d.%H:%M:%S')}-{dt.strftime('%Y/%m/%d.%H:%M:%S')}"

    try:
        direction = get_traffic_direction(ip, tf)
        src_ports = parse_csv(
            run_nfdump(
                ["-s", "dstport/bytes/flows", "-n", "10", "-a", f"src ip {ip}"], tf
            ),
            expected_key="dp",
        )
        dst_ports = parse_csv(
            run_nfdump(
                ["-s", "srcport/bytes/flows", "-n", "10", "-a", f"dst ip {ip}"], tf
            ),
            expected_key="sp",
        )
        protocols = parse_csv(
            run_nfdump(["-s", "proto/bytes/packets", "-n", "5", "-a", f"ip {ip}"], tf),
            expected_key="proto",
        )
    except (subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as e:
        # If nfdump fails, return partial data
        direction = {"upload": 0, "download": 0}
        src_ports = []
        dst_ports = []
        protocols = []
        add_app_log(f"nfdump query failed for IP {ip}: {e}", "WARN")

    # Enrich
    for p in protocols:
        try:
            proto = int(p["key"])
            p["proto_name"] = PROTOS.get(proto, f"Proto-{p['key']}")
        except (ValueError, TypeError):
            p["proto_name"] = p["key"]

    geo = lookup_geo(ip)

    # Threat Intelligence lookup (optional, graceful degradation if no API keys)
    threat_intel = lookup_threat_intelligence(ip)

    # Traffic pattern anomaly detection
    anomalies = detect_ip_anomalies(ip, tf, direction, src_ports, dst_ports, protocols)

    # Generate alerts for high-severity anomalies
    generate_ip_anomaly_alerts(ip, anomalies, geo)

    # Find related IPs (simplified: IPs that appear in flows with this IP)
    # This finds IPs that directly communicate with this IP (as source or destination)
    related_ips = []
    try:
        # Get flows involving this IP
        convs_output = run_nfdump(["-a", f"ip {ip}", "-n", "500", "-o", "csv"], tf)
        lines = convs_output.strip().split("\n")
        if len(lines) > 0:
            # Robust header detection
            header_idx = -1
            for i, line in enumerate(lines):
                line_clean = line.strip().lower()
                if line_clean.startswith("ts,") or line_clean.startswith("firstseen,"):
                    header_idx = i
                    break

            if header_idx != -1:
                header_line = lines[header_idx].lower()
                start_row_idx = header_idx + 1
            else:
                header_line = lines[0].lower()
                start_row_idx = 1

            header = [c.strip() for c in header_line.split(",")]
            try:
                sa_idx = (
                    header.index("sa")
                    if "sa" in header
                    else (header.index("srcaddr") if "srcaddr" in header else 3)
                )
                da_idx = (
                    header.index("da")
                    if "da" in header
                    else (header.index("dstaddr") if "dstaddr" in header else 5)
                )
                ibyt_idx = (
                    header.index("ibyt")
                    if "ibyt" in header
                    else (header.index("bytes") if "bytes" in header else 12)
                )
            except ValueError:
                # Default fallbacks
                sa_idx, da_idx, ibyt_idx = 3, 5, 8  # 1.7 default
                if "firstseen" not in header:
                    sa_idx, da_idx, ibyt_idx = 3, 4, 12  # 1.6 default

            # Track IPs that communicate with this IP
            related_ip_stats = defaultdict(lambda: {"bytes": 0, "count": 0, "type": ""})

            for line in lines[start_row_idx:]:
                line = line.strip()
                if not line or line.startswith("ts,") or line.startswith("firstseen,"):
                    continue
                parts = line.split(",")
                if len(parts) > max(sa_idx, da_idx, ibyt_idx):
                    try:
                        src = parts[sa_idx].strip()
                        dst = parts[da_idx].strip()
                        bytes_val = (
                            int(float(parts[ibyt_idx]))
                            if parts[ibyt_idx].strip()
                            else 0
                        )

                        if src == ip and dst != ip:
                            # This IP is source - track destination as related
                            related_ip_stats[dst]["bytes"] += bytes_val
                            related_ip_stats[dst]["count"] += 1
                            related_ip_stats[dst]["type"] = "destination"
                        elif dst == ip and src != ip:
                            # This IP is destination - track source as related
                            related_ip_stats[src]["bytes"] += bytes_val
                            related_ip_stats[src]["count"] += 1
                            related_ip_stats[src]["type"] = "source"
                    except (ValueError, IndexError):
                        pass

            # Get top related IPs (limit to 10)
            related_ips = sorted(
                [
                    {
                        "ip": ip_addr,
                        "bytes": data["bytes"],
                        "count": data["count"],
                        "type": data["type"],
                    }
                    for ip_addr, data in related_ip_stats.items()
                ],
                key=lambda x: x["bytes"],
                reverse=True,
            )[:10]

            # Enrich related IPs with geo data
            for r_ip in related_ips:
                r_geo = lookup_geo(r_ip["ip"])
                r_ip["country"] = (
                    r_geo.get("country", "Unknown") if r_geo else "Unknown"
                )
                r_ip["country_code"] = r_geo.get("country_code", "") if r_geo else ""
    except (subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as e:
        add_app_log(f"Related IPs discovery failed for IP {ip}: {e}", "WARN")

    data = {
        "ip": ip,
        "hostname": resolve_ip(ip),
        "region": get_region(ip, geo.get("country_iso") if geo else None),
        "internal": is_internal(ip),
        "geo": geo,
        "direction": direction,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "protocols": protocols,
        "threat": False,
        "related_ips": related_ips,
        "threat_intel": threat_intel,
        "anomalies": anomalies,
    }
    return jsonify(data)


@bp.route("/api/test_alert")
def api_test_alert():
    alert = {
        "severity": "critical",
        "msg": "TEST ALERT triggered from UI",
        "feed": "local",
    }
    send_notifications([alert])
    return jsonify({"status": "ok", "sent": True})


@bp.route("/api/threat_refresh", methods=["POST"])
def api_threat_refresh():
    fetch_threat_feed()
    return jsonify({"status": "ok", "threat_status": threats_module._threat_status})


@bp.route("/api/ollama/chat", methods=["POST"])
@throttle(10, 60)  # 10 requests per minute
def api_ollama_chat():
    """Chat endpoint that proxies requests to local Ollama instance."""
    try:
        data = request.get_json()
        message = data.get("message", "").strip()
        model = data.get(
            "model", "deepseek-coder-v2:16b"
        )  # Default model, can be overridden
        stream = data.get("stream", False)

        if not message:
            return jsonify({"error": "Message is required"}), 400

        # Ollama API endpoint (default: localhost:11434)
        ollama_base = os.getenv("OLLAMA_URL", "http://localhost:11434")
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace("/api/chat", "")
        ollama_url = f"{ollama_base}/api/chat"

        # Prepare request to Ollama
        ollama_payload = {
            "model": model,
            "messages": [{"role": "user", "content": message}],
            "stream": stream,
        }

        # Make request to Ollama
        timeout = 120 if stream else 60  # Longer timeout for streaming
        response = requests.post(
            ollama_url, json=ollama_payload, timeout=timeout, stream=stream
        )

        if response.status_code != 200:
            return jsonify(
                {
                    "error": f"Ollama API error: {response.status_code}",
                    "details": response.text[:200],
                }
            ), response.status_code

        if stream:
            # For streaming, return Server-Sent Events
            def generate():
                for line in response.iter_lines():
                    if line:
                        yield f"data: {line.decode('utf-8')}\n\n"
                yield "data: [DONE]\n\n"

            return Response(
                generate(),
                mimetype="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
        else:
            # For non-streaming, return JSON response
            return jsonify(response.json())

    except requests.exceptions.ConnectionError:
        return jsonify(
            {
                "error": f"Cannot connect to Ollama at {ollama_url}. Make sure Ollama is running and accessible."
            }
        ), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request to Ollama timed out"}), 504
    except Exception as e:
        add_app_log(f"Ollama chat error: {e}", "ERROR")
        return jsonify({"error": "Internal server error", "details": str(e)[:200]}), 500


@bp.route("/api/ollama/threat-analysis", methods=["POST"])
@throttle(5, 60)  # 5 requests per minute for intensive analysis
def api_ollama_threat_analysis():
    """Advanced threat analysis endpoint with enhanced context."""
    try:
        data = request.get_json()
        query = data.get("query", "").strip()
        analysis_type = data.get(
            "type", "general"
        )  # general, forensics, investigation, mitigation

        if not query:
            return jsonify({"error": "Query is required"}), 400

        # Gather comprehensive threat intelligence context
        from app.services.security.threats import get_threat_info, load_threatlist
        from app.services.netflow.netflow import get_common_nfdump_data
        from datetime import datetime, timedelta

        # Enhanced context collection
        context_data = {
            "timestamp": datetime.now().isoformat(),
            "analysis_type": analysis_type,
            "threat_intel": {
                "total_threats": len(load_threatlist()),
                "recent_hits": [],  # Would be populated from actual threat hits
                "categories": [],  # Would be populated from threat categories
            },
            "network_summary": {
                "top_sources": get_common_nfdump_data("sources", "1h")[:10],
                "top_destinations": get_common_nfdump_data("destinations", "1h")[:10],
                "protocols": get_common_nfdump_data("protos", "1h")[:10],
            },
            "security_metrics": {
                "current_score": 0,  # Would be populated from security score
                "active_alerts": 0,  # Would be populated from alerts
                "blocked_threats": 0,  # Would be populated from firewall blocks
            },
        }

        # Build specialized prompt based on analysis type
        system_prompts = {
            "general": """You are a senior network security analyst AI assistant. You have access to real-time threat intelligence, network traffic data, and security metrics. 
            Provide detailed security analysis, threat assessment, and actionable recommendations. Focus on:
            1. Threat severity and potential impact
            2. Immediate investigation steps
            3. Recommended containment actions
            4. Long-term mitigation strategies
            5. Compliance implications if relevant""",
            "forensics": """You are a digital forensics expert. Analyze the provided network data for evidence of security incidents. 
            Focus on:
            1. Timeline reconstruction
            2. Attack pattern identification
            3. Evidence preservation recommendations
            4. Attribution indicators
            5. Lateral movement detection""",
            "investigation": """You are a cybersecurity incident response investigator. Provide step-by-step investigation guidance.
            Focus on:
            1. Immediate triage priorities
            2. Evidence collection procedures
            3. Containment and eradication steps
            4. Recovery recommendations
            5. Post-incident improvement actions""",
            "mitigation": """You are a security architect focused on threat mitigation. Provide actionable security improvements.
            Focus on:
            1. Immediate blocking recommendations
            2. Rule and policy changes
            3. Network segmentation suggestions
            4. Monitoring enhancements
            5. Long-term hardening strategies""",
        }

        system_prompt = system_prompts.get(analysis_type, system_prompts["general"])

        # Format context for LLM
        context_text = f"""
## THREAT ANALYSIS CONTEXT
Analysis Type: {analysis_type.upper()}
Timestamp: {context_data["timestamp"]}

### Current Threat Intelligence
- Total Known Threat IPs: {context_data["threat_intel"]["total_threats"]}

### Network Traffic Summary (Last Hour)
- Top Sources: {[s["key"] for s in context_data["network_summary"]["top_sources"][:5]]}
- Top Destinations: {[d["key"] for d in context_data["network_summary"]["top_destinations"][:5]]}
- Top Protocols: {[p["key"] for p in context_data["network_summary"]["protocols"][:5]]}

### Security Posture
- Security Score: {context_data["security_metrics"]["current_score"]}/100
- Active Alerts: {context_data["security_metrics"]["active_alerts"]}
- Threats Blocked: {context_data["security_metrics"]["blocked_threats"]}

{system_prompt}

ANALYSIS REQUEST: {query}

Provide a comprehensive analysis with specific, actionable recommendations."""

        # Ollama API endpoint (default: localhost:11434)
        ollama_base = os.getenv("OLLAMA_URL", "http://localhost:11434")
        ollama_base = ollama_base.replace("/api/chat", "")
        ollama_url = f"{ollama_base}/api/chat"

        ollama_payload = {
            "model": data.get("model", "deepseek-coder-v2:16b"),
            "messages": [{"role": "user", "content": context_text}],
            "stream": False,
        }

        response = requests.post(
            ollama_url,
            json=ollama_payload,
            timeout=90,  # Longer timeout for complex analysis
        )

        if response.status_code != 200:
            return jsonify(
                {
                    "error": f"Ollama API error: {response.status_code}",
                    "details": response.text[:200],
                }
            ), response.status_code

        result = response.json()

        # Add metadata to response
        result["analysis_metadata"] = {
            "type": analysis_type,
            "context_timestamp": context_data["timestamp"],
            "threats_analyzed": context_data["threat_intel"]["total_threats"],
        }

        return jsonify(result)

    except requests.exceptions.ConnectionError:
        return jsonify(
            {
                "error": f"Cannot connect to Ollama. Make sure Ollama is running and accessible."
            }
        ), 503
    except requests.exceptions.Timeout:
        return jsonify(
            {"error": "Threat analysis timed out - try a more specific query"}
        ), 504
    except Exception as e:
        return jsonify({"error": f"Analysis error: {str(e)}"}), 500


@bp.route("/api/forensics/timeline", methods=["POST"])
@throttle(5, 60)
def api_forensics_timeline():
    """Generate detailed incident timeline with network forensics data."""
    try:
        data = request.get_json()
        target_ip = data.get("target_ip", "").strip()
        time_range = data.get("time_range", "24h")
        include_context = data.get("include_context", True)

        if not target_ip:
            return jsonify({"error": "Target IP is required"}), 400

        # Validate IP format
        import re

        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if not re.match(ip_pattern, target_ip):
            return jsonify({"error": "Invalid IP address format"}), 400

        from app.services.netflow.netflow import run_nfdump, get_time_range
        from app.services.security.threats import get_threat_info, load_threatlist
        from datetime import datetime, timedelta

        # Generate timeline data
        tf = get_time_range(time_range)

        # Get all flows involving target IP
        nfdump_cmd = [f"host {target_ip}", "-o", "csv", "-t", tf]

        output = run_nfdump(nfdump_cmd)

        if not output or not output.strip():
            return jsonify(
                {
                    "error": "No network traffic found for target IP in specified time range",
                    "target_ip": target_ip,
                    "time_range": time_range,
                }
            ), 404

        # Parse timeline data
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return jsonify({"error": "Insufficient data for timeline analysis"}), 404

        header_line = lines[0]
        header = [c.strip().lower() for c in header_line.split(",")]

        try:
            # Map actual nfdump columns to expected names (case-insensitive) - robust mappings
            ts_idx = (
                header.index("ts")
                if "ts" in header
                else (header.index("firstseen") if "firstseen" in header else -1)
            )
            te_idx = (
                header.index("duration")
                if "duration" in header
                else (header.index("td") if "td" in header else -1)
            )
            sa_idx = (
                header.index("sa")
                if "sa" in header
                else (header.index("srcaddr") if "srcaddr" in header else -1)
            )
            da_idx = (
                header.index("da")
                if "da" in header
                else (header.index("dstaddr") if "dstaddr" in header else -1)
            )
            sp_idx = (
                header.index("sp")
                if "sp" in header
                else (header.index("srcport") if "srcport" in header else -1)
            )
            dp_idx = (
                header.index("dp")
                if "dp" in header
                else (header.index("dstport") if "dstport" in header else -1)
            )
            pr_idx = (
                header.index("proto")
                if "proto" in header
                else (header.index("pr") if "pr" in header else -1)
            )
            ibyt_idx = (
                header.index("ibyt")
                if "ibyt" in header
                else (header.index("bytes") if "bytes" in header else -1)
            )
            ipkt_idx = (
                header.index("ipkt")
                if "ipkt" in header
                else (header.index("packets") if "packets" in header else -1)
            )

            if -1 in [ts_idx, sa_idx, da_idx, pr_idx, ibyt_idx]:
                # Relaxing requirements slightly to avoid crashing if minor columns missing
                pass
            if sa_idx == -1 or da_idx == -1:
                raise ValueError(
                    f"Missing required IP columns. Available columns: {header}"
                )

        except ValueError as e:
            return jsonify(
                {"error": f"Required columns not found in NetFlow data: {e}"}
            ), 500

        timeline_events = []
        total_bytes = 0
        total_packets = 0
        unique_ports = set()
        unique_protocols = set()

        # Process each flow
        for line in lines[1:]:
            if not line or line.startswith("ts,"):
                continue

            parts = line.split(",")
            if len(parts) <= max(
                ts_idx,
                te_idx,
                sa_idx,
                da_idx,
                sp_idx,
                dp_idx,
                pr_idx,
                ibyt_idx,
                ipkt_idx,
            ):
                continue

            try:
                start_time = parts[ts_idx]
                end_time = (
                    parts[te_idx] if te_idx >= 0 and len(parts) > te_idx else start_time
                )
                src_ip = parts[sa_idx]
                dst_ip = parts[da_idx]
                src_port = parts[sp_idx]
                dst_port = parts[dp_idx]
                protocol = parts[pr_idx]
                flags = ""  # Flags not available in this format
                bytes_xfer = (
                    int(parts[ibyt_idx])
                    if ibyt_idx >= 0 and len(parts) > ibyt_idx and parts[ibyt_idx]
                    else 0
                )
                packets = (
                    int(parts[ipkt_idx])
                    if ipkt_idx >= 0 and len(parts) > ipkt_idx and parts[ipkt_idx]
                    else 0
                )

                # Determine direction
                direction = "outbound" if src_ip == target_ip else "inbound"

                # Check for suspicious patterns
                suspicious = False
                suspicious_indicators = []

                # Check for large data transfers
                if bytes_xfer > 10000000:  # > 10MB
                    suspicious = True
                    suspicious_indicators.append("Large data transfer")

                # Check for remote access ports
                try:
                    dst_port_int = int(dst_port)
                    if dst_port_int in [22, 23, 3389, 5900]:
                        suspicious = True
                        suspicious_indicators.append("Remote access port")
                except (ValueError, TypeError):
                    pass

                # Check for unusual protocols
                if protocol in ["1", "ICMP"] and packets > 100:
                    suspicious = True
                    suspicious_indicators.append("High ICMP volume")

                timeline_events.append(
                    {
                        "timestamp": start_time,
                        "end_timestamp": end_time,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "direction": direction,
                        "bytes": bytes_xfer,
                        "packets": packets,
                        "flags": flags,
                        "suspicious": suspicious,
                        "indicators": suspicious_indicators,
                    }
                )

                total_bytes += bytes_xfer
                total_packets += packets
                unique_ports.add(dst_port if direction == "outbound" else src_port)
                unique_protocols.add(protocol)

            except (ValueError, IndexError) as e:
                continue  # Skip malformed lines

        # Sort timeline by timestamp
        timeline_events.sort(key=lambda x: x["timestamp"])

        # Get threat intelligence for target IP
        threat_info = None
        if include_context:
            try:
                threat_info = get_threat_info(target_ip)
            except Exception:
                pass

        # Generate summary statistics
        summary = {
            "target_ip": target_ip,
            "time_range": time_range,
            "total_events": len(timeline_events),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "unique_ports": len(unique_ports),
            "unique_protocols": len(unique_protocols),
            "suspicious_events": len([e for e in timeline_events if e["suspicious"]]),
            "first_seen": timeline_events[0]["timestamp"] if timeline_events else None,
            "last_seen": timeline_events[-1]["timestamp"] if timeline_events else None,
            "threat_intel": threat_info,
        }

        return jsonify(
            {
                "summary": summary,
                "timeline": timeline_events,
                "analysis_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "data_source": "netflow",
                    "time_range_processed": time_range,
                },
            }
        )

    except Exception as e:
        return jsonify({"error": f"Timeline analysis failed: {str(e)}"}), 500


@bp.route("/api/forensics/session", methods=["POST"])
@throttle(3, 60)
def api_forensics_session():
    """Reconstruct communication session between two endpoints."""
    try:
        data = request.get_json()
        src_ip = data.get("src_ip", "").strip()
        dst_ip = data.get("dst_ip", "").strip()
        time_range = data.get("time_range", "1h")

        if not src_ip or not dst_ip:
            return jsonify(
                {"error": "Both source and destination IPs are required"}
            ), 400

        try:
            validate_ip_input(src_ip)
            validate_ip_input(dst_ip)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        # Validate IP formats
        import re

        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if not re.match(ip_pattern, src_ip) or not re.match(ip_pattern, dst_ip):
            return jsonify({"error": "Invalid IP address format"}), 400

        from app.services.netflow.netflow import run_nfdump, get_time_range
        from datetime import datetime

        # Get session data
        tf = get_time_range(time_range)

        # Get flows between the two IPs (limit 5000 for performance)
        nfdump_cmd = [
            f"host {src_ip} and host {dst_ip}",
            "-o",
            "csv",
            "-t",
            tf,
            "-n",
            "5000",
        ]

        output = run_nfdump(nfdump_cmd)

        if not output or not output.strip():
            return jsonify(
                {
                    "error": "No communication found between specified IPs",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "time_range": time_range,
                }
            ), 404

        # Parse session data
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({"error": "Insufficient data for session analysis"}), 404

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith("ts,") or line_clean.startswith("firstseen,"):
                header_idx = i
                break

        if header_idx != -1:
            header_line = lines[header_idx]
            start_idx = header_idx + 1
        else:
            header_line = lines[0]
            start_idx = 1 if "," in header_line else 0

        header = [c.strip().lower() for c in header_line.split(",")]

        # Find column indices
        try:
            # Check for common variants in both 1.6 and 1.7
            ts_idx = (
                header.index("ts")
                if "ts" in header
                else (header.index("firstseen") if "firstseen" in header else 0)
            )
            te_idx = (
                header.index("te")
                if "te" in header
                else (header.index("duration") if "duration" in header else 1)
            )
            sa_idx = (
                header.index("sa")
                if "sa" in header
                else (header.index("srcaddr") if "srcaddr" in header else 3)
            )
            da_idx = (
                header.index("da")
                if "da" in header
                else (header.index("dstaddr") if "dstaddr" in header else 5)
            )
            sp_idx = (
                header.index("sp")
                if "sp" in header
                else (header.index("srcport") if "srcport" in header else 4)
            )
            dp_idx = (
                header.index("dp")
                if "dp" in header
                else (header.index("dstport") if "dstport" in header else 6)
            )
            pr_idx = (
                header.index("proto")
                if "proto" in header
                else (header.index("pr") if "pr" in header else 2)
            )
            ibyt_idx = (
                header.index("ibyt")
                if "ibyt" in header
                else (header.index("bytes") if "bytes" in header else 8)
            )
            ipkt_idx = (
                header.index("ipkt")
                if "ipkt" in header
                else (header.index("packets") if "packets" in header else 7)
            )

            # Duration special case (sometimes index 1 is Duration in seconds, index 2 is Proto)
            # In -o csv 1.6: ts=0, te=1, td=2 ...
            # In -o csv 1.7: firstseen=0, duration=1, proto=2 ...
            # We'll handle this in the loop

        except (ValueError, IndexError) as e:
            return jsonify(
                {"error": f"Required columns not found in nfdump output: {header}"}
            ), 500

        session_flows = []
        total_bytes = 0
        total_packets = 0
        ports_used = set()

        first_timestamp = None
        last_timestamp = None

        max_idx = max(
            ts_idx, te_idx, sa_idx, da_idx, sp_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx
        )

        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith("ts,") or line.startswith("firstseen,"):
                continue

            parts = line.split(",")
            if len(parts) <= max_idx:
                continue

            try:
                start_time = parts[ts_idx].strip()
                end_time = parts[te_idx].strip() if te_idx >= 0 else start_time
                src_port = parts[sp_idx].strip()
                dst_port = parts[dp_idx].strip()
                protocol = parts[pr_idx].strip()
                bytes_xfer = int(float(parts[ibyt_idx])) if parts[ibyt_idx] else 0
                packets = int(float(parts[ipkt_idx])) if parts[ipkt_idx] else 0

                session_flows.append(
                    {
                        "timestamp": start_time,
                        "end_timestamp": end_time,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "bytes": bytes_xfer,
                        "packets": packets,
                    }
                )

                total_bytes += bytes_xfer
                total_packets += packets
                ports_used.add(f"{src_port}->{dst_port}")

                if not first_timestamp:
                    first_timestamp = start_time
                last_timestamp = end_time

            except (ValueError, IndexError):
                continue

        # Calculate session duration
        if first_timestamp and last_timestamp:
            try:
                start_dt = datetime.strptime(first_timestamp, "%Y-%m-%d %H:%M:%S")
                end_dt = datetime.strptime(last_timestamp, "%Y-%m-%d %H:%M:%S")
                session_duration = (end_dt - start_dt).total_seconds()
            except (ValueError, TypeError):
                session_duration = 0

        # Analyze session patterns
        session_analysis = {
            "communication_pattern": "continuous"
            if len(session_flows) > 5
            else "sporadic",
            "data_volume_profile": "heavy" if total_bytes > 10000000 else "light",
            "port_diversity": len(ports_used),
            "protocol_consistency": len(set(f["protocol"] for f in session_flows)) == 1,
        }

        # Generate session summary
        summary = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "time_range": time_range,
            "total_flows": len(session_flows),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "session_duration_seconds": session_duration,
            "unique_port_combinations": len(ports_used),
            "first_seen": first_timestamp,
            "last_seen": last_timestamp,
            "analysis": session_analysis,
        }

        return jsonify(
            {
                "summary": summary,
                "flows": session_flows,
                "session_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "data_source": "netflow",
                    "time_range_processed": time_range,
                },
            }
        )

    except Exception as e:
        return jsonify({"error": f"Session reconstruction failed: {str(e)}"}), 500


@bp.route("/api/forensics/evidence", methods=["POST"])
def api_forensics_evidence():
    """Generate evidence collection report for incident response."""
    try:
        data = request.get_json()
        incident_type = data.get(
            "incident_type", "general"
        )  # malware, data_exfiltration, dos, scan, general
        target_ips = data.get("target_ips", [])
        time_range = data.get("time_range", "24h")
        preserve_data = data.get("preserve_data", True)

        if not target_ips:
            return jsonify(
                {"error": "Target IPs are required for evidence collection"}
            ), 400

        try:
            for ip in target_ips:
                validate_ip_input(ip)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        from app.services.netflow.netflow import run_nfdump, get_time_range
        from app.services.security.threats import get_threat_info, load_threatlist
        from datetime import datetime, timedelta

        tf = get_time_range(time_range)
        collection_timestamp = datetime.now().isoformat()

        evidence_report = {
            "incident_metadata": {
                "incident_type": incident_type,
                "collection_timestamp": collection_timestamp,
                "time_range": time_range,
                "target_ips": target_ips,
                "preservation_requested": preserve_data,
            },
            "evidence_items": [],
        }

        # Collect evidence for each target IP
        for target_ip in target_ips:
            # NetFlow evidence
            nfdump_cmd = [f"host {target_ip}", "-o", "csv", "-t", tf]

            output = run_nfdump(nfdump_cmd)

            if output and output.strip():
                # Count total flows
                lines = output.strip().split("\n")
                flow_count = len(
                    [l for l in lines[1:] if l and not l.startswith("ts,")]
                )

                evidence_report["evidence_items"].append(
                    {
                        "type": "netflow_records",
                        "target": target_ip,
                        "description": f"Network flow records for {target_ip}",
                        "record_count": flow_count,
                        "time_range": time_range,
                        "data_hash": hashlib.sha256(output.encode("utf-8")).hexdigest()
                        if output
                        else None,
                        "collection_method": "nfdump",
                        "preserved": preserve_data,
                    }
                )

            # Threat intelligence evidence
            try:
                threat_info = get_threat_info(target_ip)
                if threat_info and any(threat_info.values()):
                    evidence_report["evidence_items"].append(
                        {
                            "type": "threat_intelligence",
                            "target": target_ip,
                            "description": f"Threat intelligence data for {target_ip}",
                            "threat_data": threat_info,
                            "collection_timestamp": collection_timestamp,
                            "preserved": True,
                        }
                    )
            except Exception:
                pass

            # DNS resolution evidence
            try:
                from app.services.shared.dns import resolve_ip

                dns_info = resolve_ip(target_ip)
                if dns_info:
                    evidence_report["evidence_items"].append(
                        {
                            "type": "dns_resolution",
                            "target": target_ip,
                            "description": f"DNS resolution records for {target_ip}",
                            "dns_data": dns_info,
                            "collection_timestamp": collection_timestamp,
                            "preserved": True,
                        }
                    )
            except Exception:
                pass

        # Generate chain of custody summary
        evidence_report["chain_of_custody"] = {
            "collector": "PHOBOS-NET Automated System",
            "collection_start": collection_timestamp,
            "collection_method": "automated",
            "integrity_check": "hash_verification",
            "preservation_status": "active" if preserve_data else "temporary",
        }

        # Add incident-specific evidence recommendations
        recommendations = {
            "malware": [
                "Preserve full packet captures if available",
                "Check for C2 communication patterns",
                "Analyze data exfiltration attempts",
                "Review endpoint logs for malware artifacts",
            ],
            "data_exfiltration": [
                "Identify large data transfers",
                "Check for unusual destination IPs",
                "Analyze encryption protocols used",
                "Review user access logs",
            ],
            "dos": [
                "Document attack source and volume",
                "Preserve traffic samples during attack",
                "Analyze attack patterns and timing",
                "Review network device logs",
            ],
            "scan": [
                "Document scanning patterns and tools",
                "Identify targeted services and ports",
                "Analyze scan frequency and duration",
                "Review firewall logs for blocked attempts",
            ],
            "general": [
                "Preserve all available network logs",
                "Document timeline of events",
                "Collect system and application logs",
                "Interview relevant personnel",
            ],
        }

        evidence_report["recommendations"] = recommendations.get(
            incident_type, recommendations["general"]
        )

        return jsonify(evidence_report)

    except Exception as e:
        return jsonify({"error": f"Evidence collection failed: {str(e)}"}), 500


@bp.route("/api/ollama/models", methods=["GET"])
@throttle(5, 60)
def api_ollama_models():
    """Get list of available Ollama models."""
    try:
        # Ollama API base URL (default: localhost:11434)
        ollama_base = os.getenv("OLLAMA_URL", "http://localhost:11434")
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace("/api/chat", "")
        response = requests.get(f"{ollama_base}/api/tags", timeout=10)

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch models"}), response.status_code

        data = response.json()
        models = [model.get("name", "") for model in data.get("models", [])]
        return jsonify({"models": models})

    except requests.exceptions.ConnectionError as e:
        ollama_base = os.getenv("OLLAMA_URL", "http://localhost:11434")
        add_app_log(f"Ollama connection failed to {ollama_base}: {e}", "WARN")

        # Simple auto-fallback for local Docker development
        if "localhost" in ollama_base:
            try:
                fallback_url = ollama_base.replace("localhost", "host.docker.internal")
                add_app_log(f"Attempting Ollama fallback to {fallback_url}...", "INFO")
                response = requests.get(f"{fallback_url}/api/tags", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    models = [model.get("name", "") for model in data.get("models", [])]
                    return jsonify({"models": models})
            except Exception:
                pass

        return jsonify({"error": "Cannot connect to Ollama", "models": []}), 503
    except Exception as e:
        add_app_log(f"Ollama models error: {e}", "ERROR")
        return jsonify({"error": str(e), "models": []}), 500


@bp.route("/api/stats/threats")
@throttle(5, 10)
def api_threats():
    """Get threat detections with category, geo info, and firewall block status"""
    range_key = request.args.get("range", "1h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 3600)
    cutoff = time.time() - range_seconds

    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    threat_set = threat_set - whitelist

    # Get blocked IPs from firewall logs
    blocked_ips = {}
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute(
                    """
                    SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_blocked
                    FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                    GROUP BY src_ip
                """,
                    (cutoff,),
                )
                for row in cur.fetchall():
                    blocked_ips[row[0]] = {"count": row[1], "last_blocked": row[2]}
            finally:
                conn.close()
    except Exception:
        pass  # Syslog may not be configured yet

    # Get sources/destinations and find threat matches
    sources = get_common_nfdump_data("sources", range_key)[:50]
    destinations = get_common_nfdump_data("destinations", range_key)[:50]

    hits = []
    seen = set()

    for item in sources + destinations:
        ip = item.get("key", "")
        if ip in threat_set and ip not in seen:
            seen.add(ip)
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            block_info = blocked_ips.get(ip, {})
            hits.append(
                {
                    "ip": ip,
                    "category": info.get("category", "UNKNOWN"),
                    "feed": info.get("feed", "unknown"),
                    "bytes": item.get("bytes", 0),
                    "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                    "flows": item.get("flows", 0),
                    "country": geo.get("country_code", "--"),
                    "city": geo.get("city", ""),
                    "hits": item.get("flows", 1),
                    "blocked": block_info.get("count", 0) > 0,
                    "block_count": block_info.get("count", 0),
                    "last_blocked": datetime.fromtimestamp(
                        block_info["last_blocked"]
                    ).isoformat()
                    if block_info.get("last_blocked")
                    else None,
                }
            )

    # Sort by bytes descending
    hits.sort(key=lambda x: x["bytes"], reverse=True)

    # Summary stats
    total_blocked = sum(1 for h in hits if h["blocked"])

    return jsonify(
        {
            "hits": hits[:20],
            "total_threats": len(hits),
            "total_blocked": total_blocked,
            "feed_ips": threats_module._threat_status.get("size", 0),
            "threat_status": threats_module._threat_status,
        }
    )


@bp.route("/api/stats/malicious_ports")
@throttle(5, 10)
def api_malicious_ports():
    """Get top malicious ports - combining threat traffic + firewall blocks"""
    range_key = request.args.get("range", "1h")

    # Map range to seconds for firewall query
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 3600)

    # Suspicious ports to highlight
    SUSPICIOUS_PORTS = {
        22: "SSH",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        11211: "Memcached",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        4444: "Metasploit",
        5555: "Android ADB",
        6666: "IRC",
        31337: "Back Orifice",
    }

    port_data = {}

    # Get blocked ports from firewall syslog
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Using range_seconds calculated above
            cutoff = int(time.time()) - range_seconds

            # Get blocked ports with counts
            cur.execute(
                """
                SELECT dst_port, COUNT(*) as hits, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND dst_port > 0
                GROUP BY dst_port
                ORDER BY hits DESC
                LIMIT 50
            """,
                (cutoff,),
            )

            for row in cur.fetchall():
                port = row["dst_port"]
                service = SUSPICIOUS_PORTS.get(port, "Unknown")
                port_data[port] = {
                    "port": port,
                    "service": service,
                    "blocked": row["hits"],
                    "unique_attackers": row["unique_ips"],
                    "netflow_bytes": 0,
                    "netflow_flows": 0,
                    "suspicious": port in SUSPICIOUS_PORTS,
                }
            conn.close()
    except Exception as e:
        pass  # Syslog not available, continue with NetFlow only

    # Merge with threat traffic from NetFlow
    # Get NetFlow data for ports that were blocked (more efficient than querying by threat IP)
    try:
        tf = get_time_range(range_key)

        # If we have blocked ports, get NetFlow stats for those specific ports
        if port_data:
            # Build filter for blocked ports (limit to top 20 to avoid huge query)
            blocked_ports = sorted(
                port_data.keys(), key=lambda p: port_data[p]["blocked"], reverse=True
            )[:20]

            if blocked_ports:
                # Query NetFlow for traffic on these ports from ANY source (not just blocked)
                # Blocked traffic won't appear in NetFlow, but we can show traffic that did get through
                # Use the same approach as regular ports endpoint for consistency
                try:
                    # Get all port stats and filter for our blocked ports
                    from app.services.netflow.netflow import get_common_nfdump_data

                    all_ports_data = get_common_nfdump_data("ports", range_key)

                    # Match ports and update traffic data
                    for port_item in all_ports_data:
                        try:
                            port_num = int(port_item.get("key", 0))
                            if port_num in port_data:
                                port_data[port_num]["netflow_bytes"] = int(
                                    port_item.get("bytes", 0)
                                )
                                port_data[port_num]["netflow_flows"] = int(
                                    port_item.get("flows", 0)
                                )
                        except (ValueError, KeyError):
                            continue
                except (subprocess.TimeoutExpired, ValueError, KeyError) as e:
                    # Log but continue - syslog data is still valuable
                    add_app_log(f"NetFlow query for port traffic failed: {e}", "WARN")

        # Also try to get data from threat IPs (if threat list exists)
        threat_set = load_threatlist()
        if threat_set:
            # Get top threat IPs by bytes (limit to top 10 to prevent timeout)
            output = run_nfdump(["-o", "csv", "-n", "30", "-s", "ip/bytes"], tf)

            lines = output.strip().split("\n")
            if len(lines) > 1:
                header = [c.strip().lower() for c in lines[0].split(",")]
                ip_idx = next(
                    (i for i, h in enumerate(header) if "ip" in h and "addr" in h), None
                )
                byt_idx = next(
                    (i for i, h in enumerate(header) if h in ("ibyt", "bytes")), None
                )

                if ip_idx is not None:
                    # Collect top threat IPs (limit to 10 to prevent timeout)
                    threat_ips = []
                    for line in lines[1:11]:  # Limit to top 10 threat IPs
                        parts = line.split(",")
                        if len(parts) > max(ip_idx, byt_idx or 0):
                            ip = parts[ip_idx].strip()
                            if ip in threat_set:
                                try:
                                    bytes_val = (
                                        int(parts[byt_idx].strip()) if byt_idx else 0
                                    )
                                    threat_ips.append((ip, bytes_val))
                                except (ValueError, IndexError):
                                    pass

                    # Process threat IPs (limit to 5 to prevent timeout)
                    for ip, _ in threat_ips[:5]:
                        try:
                            port_output = run_nfdump(
                                [
                                    "-o",
                                    "csv",
                                    "-n",
                                    "3",
                                    "-s",
                                    "port/bytes",
                                    f"src ip {ip} or dst ip {ip}",
                                ],
                                tf,
                            )
                            port_lines = port_output.strip().split("\n")

                            if len(port_lines) > 1:
                                p_header = [
                                    c.strip().lower() for c in port_lines[0].split(",")
                                ]
                                p_idx = next(
                                    (i for i, h in enumerate(p_header) if h == "port"),
                                    None,
                                )
                                p_byt_idx = next(
                                    (
                                        i
                                        for i, h in enumerate(p_header)
                                        if h in ("ibyt", "bytes")
                                    ),
                                    None,
                                )
                                p_fl_idx = next(
                                    (
                                        i
                                        for i, h in enumerate(p_header)
                                        if h in ("fl", "flows")
                                    ),
                                    None,
                                )

                                if p_idx is not None:
                                    for pline in port_lines[1:]:
                                        pparts = pline.split(",")
                                        try:
                                            if len(pparts) > max(
                                                p_idx, p_byt_idx or 0, p_fl_idx or 0
                                            ):
                                                port = int(pparts[p_idx].strip())
                                                bytes_val = (
                                                    int(pparts[p_byt_idx].strip())
                                                    if p_byt_idx
                                                    else 0
                                                )
                                                flows_val = (
                                                    int(pparts[p_fl_idx].strip())
                                                    if p_fl_idx
                                                    else 0
                                                )

                                                if port not in port_data:
                                                    port_data[port] = {
                                                        "port": port,
                                                        "service": SUSPICIOUS_PORTS.get(
                                                            port, "Unknown"
                                                        ),
                                                        "blocked": 0,
                                                        "unique_attackers": 0,
                                                        "netflow_bytes": 0,
                                                        "netflow_flows": 0,
                                                        "suspicious": port
                                                        in SUSPICIOUS_PORTS,
                                                    }
                                                port_data[port]["netflow_bytes"] += (
                                                    bytes_val
                                                )
                                                port_data[port]["netflow_flows"] += (
                                                    flows_val
                                                )
                                        except (ValueError, IndexError):
                                            pass
                        except (subprocess.TimeoutExpired, ValueError, KeyError):
                            # Continue with next IP if this one fails
                            continue
    except (subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as e:
        # Log error but don't fail completely - return what we have from syslog
        add_app_log(f"Failed to fetch threat port data: {e}", "WARN")

    # Common port to service name mapping (fallback if socket.getservbyport fails)
    COMMON_PORTS = {
        20: "FTP-Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
        11211: "Memcached",
        1900: "UPnP",
        6881: "BitTorrent",
        4444: "Metasploit",
        5555: "Android ADB",
        6666: "IRC",
        6667: "IRC",
        31337: "Back Orifice",
    }

    # Update service names for all ports using optimized resolver
    for port in port_data:
        if port_data[port]["service"] == "Unknown":
            service_name = resolve_service_name(port, "6")

            # If TCP resolution failed (returns port number), try UDP
            if service_name == str(port):
                udp_service = resolve_service_name(port, "17")
                if udp_service != str(port):
                    service_name = udp_service
                else:
                    # Both failed, use fallback
                    service_name = COMMON_PORTS.get(port, f"Port {port}")

            port_data[port]["service"] = service_name

    # Convert to list and sort by total activity (blocked + flows)
    ports = list(port_data.values())
    for p in ports:
        p["total_score"] = (
            p["blocked"] * 10 + p["netflow_flows"]
        )  # Weight blocks higher
        # Ensure netflow_bytes and netflow_flows are integers
        p["netflow_bytes"] = int(p.get("netflow_bytes", 0))
        p["netflow_flows"] = int(p.get("netflow_flows", 0))
        # Set bytes_fmt only if there's actual data
        p["bytes_fmt"] = (
            fmt_bytes(p["netflow_bytes"]) if p["netflow_bytes"] > 0 else None
        )

    ports.sort(key=lambda x: x["total_score"], reverse=True)

    return jsonify(
        {
            "ports": ports[:15],  # Limit to top 15 (for scrollable view)
            "total": len(ports),
            "has_syslog": any(p["blocked"] > 0 for p in ports),
        }
    )


@bp.route("/api/stats/feeds")
@throttle(5, 10)
def api_feed_status():
    """Get per-feed health status (multi-worker aware)"""
    # Use authoritative shared health state
    deps = state.get_dependency_health()
    tf_health = deps.get("threat_feeds", {})
    feeds_status = tf_health.get("feeds_status", {})

    feeds = []
    # If shared state is empty, try fallback to local state (e.g. at startup)
    if not feeds_status and threats_module._feed_status:
        feeds_status = threats_module._feed_status

    for name, info in feeds_status.items():
        if not isinstance(info, dict):
            continue
        last_ok = info.get("last_ok", 0)
        feeds.append(
            {
                "name": name,
                "category": info.get("category", "UNKNOWN"),
                "status": info.get("status", "unknown"),
                "ips": info.get("ips", 0),
                "latency_ms": info.get("latency_ms", 0),
                "error": info.get("error"),
                "last_ok_ago": format_time_ago(last_ok) if last_ok else "never",
            }
        )

    # Sort by status (ok first), then by ips
    feeds.sort(key=lambda x: (0 if x["status"] == "ok" else 1, -x["ips"]))

    # Get summary stats
    total_ips = tf_health.get("records_count", 0)
    last_ok_ts = tf_health.get("last_ok", 0)

    # Fallback for summary
    if total_ips == 0 and threats_module._threat_status.get("size", 0) > 0:
        total_ips = threats_module._threat_status.get("size", 0)
    if last_ok_ts == 0 and threats_module._threat_status.get("last_ok", 0) > 0:
        last_ok_ts = threats_module._threat_status.get("last_ok", 0)

    return jsonify(
        {
            "feeds": feeds,
            "summary": {
                "total": len(feeds),
                "ok": sum(1 for f in feeds if f["status"] == "ok"),
                "error": sum(1 for f in feeds if f["status"] == "error"),
                "total_ips": total_ips,
                "last_refresh": format_time_ago(last_ok_ts) if last_ok_ts else "never",
            },
        }
    )


@bp.route("/api/security/score")
@throttle(5, 10)
def api_security_score():
    """Get current security score"""
    range_key = request.args.get("range", "1h")
    return jsonify(calculate_security_score(range_key))


@bp.route("/api/security/alerts/history")
@throttle(5, 10)
def api_alert_history():
    """Get alert history for selected time range."""
    range_key = request.args.get("range", "24h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 86400)

    now = time.time()
    cutoff = now - range_seconds

    # Auto-resolve stale alerts before querying
    threats_module.auto_resolve_stale_alerts()

    with threats_module._alert_history_lock:
        recent = [
            a.copy() for a in threats_module._alert_history if a.get("ts", 0) > cutoff
        ]

    # Sort by timestamp descending
    recent.sort(key=lambda x: x.get("ts", 0), reverse=True)

    # Format timestamps
    for alert in recent:
        ts = alert.get("ts", 0)
        alert["time_ago"] = format_time_ago(ts)
        alert["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    # Group by hour for chart (count distinct alerts per hour, not occurrences)
    hourly = defaultdict(int)
    for alert in recent:
        hour = time.strftime("%H:00", time.localtime(alert.get("ts", 0)))
        hourly[hour] += 1

    # Count ACTIVE alerts only (the key metric for dashboards)
    active_alerts = [a for a in recent if a.get("active", True)]
    active_count = len(active_alerts)

    # By severity counts for ACTIVE alerts only
    by_severity_active = {
        "critical": sum(1 for a in active_alerts if a.get("severity") == "critical"),
        "high": sum(1 for a in active_alerts if a.get("severity") == "high"),
        "medium": sum(1 for a in active_alerts if a.get("severity") == "medium"),
        "low": sum(1 for a in active_alerts if a.get("severity") == "low"),
    }

    return jsonify(
        {
            "alerts": recent[:100],
            "total": len(recent),  # Total distinct alerts in 24h (including resolved)
            "active_count": active_count,  # KEY METRIC: Currently active alerts
            "by_severity": by_severity_active,  # Severity breakdown of ACTIVE alerts only
            "hourly": dict(hourly),
            "time_scope": "24h",
        }
    )


@bp.route("/api/security/signals")
@throttle(10, 5)
def api_signals():
    """Get network health signals (NOT alerts).

    SEMANTICS:
    - Signals are informational network health indicators
    - They do NOT count toward active_alerts
    - They do NOT affect overall health state
    - Examples: TCP reset rates, SYN-only flow percentages, ICMP levels

    Returns:
        signals: List of recent signals
        count: Number of signals
    """
    signals = threats_module.get_signal_history(max_age_seconds=3600)

    # Format timestamps
    for signal in signals:
        ts = signal.get("ts", 0)
        signal["time_ago"] = format_time_ago(ts)
        signal["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    return jsonify({"signals": signals, "count": len(signals), "time_scope": "1h"})


@bp.route("/api/security/threats/export")
def api_export_threats():
    """Export detected threats as JSON or CSV"""
    fmt = request.args.get("format", "json")

    # Get recent threats
    now = time.time()
    threats = []
    for ip, timeline in threats_module._threat_timeline.items():
        if now - timeline["last_seen"] < 86400:  # Last 24h
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            threats.append(
                {
                    "ip": ip,
                    "category": info.get("category", "UNKNOWN"),
                    "feed": info.get("feed", "unknown"),
                    "mitre_technique": info.get("mitre_technique", ""),
                    "mitre_tactic": info.get("mitre_tactic", ""),
                    "country": geo.get("country_code", "--"),
                    "city": geo.get("city", ""),
                    "first_seen": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timeline["first_seen"])
                    ),
                    "last_seen": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(timeline["last_seen"])
                    ),
                    "hit_count": timeline["hit_count"],
                }
            )

    if fmt == "csv":
        import io
        import csv

        output = io.StringIO()
        if threats:
            writer = csv.DictWriter(output, fieldnames=threats[0].keys())
            writer.writeheader()
            writer.writerows(threats)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=threats.csv"},
        )

    return jsonify(
        {
            "threats": threats,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(threats),
        }
    )


@bp.route("/api/security/attack-timeline")
@throttle(5, 10)
@cached_endpoint(_stats_attack_timeline_cache, _lock_attack_timeline)
def api_attack_timeline():
    """Get attack timeline data for visualization with configurable time range."""
    range_key = request.args.get("range", "24h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 86400)
    now = time.time()
    cutoff = now - range_seconds

    with threats_module._alert_history_lock:
        recent = []
        for a in threats_module._alert_history:
            try:
                ts = a.get("ts", 0)
                # Handle ISO string timestamps if they exist
                if isinstance(ts, str):
                    try:
                        # Convert ISO format to unix timestamp
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        ts = dt.timestamp()
                    except (ValueError, TypeError):
                        continue

                if ts > cutoff:
                    recent.append(a)
            except Exception:
                continue

    # Determine bucket size based on range
    if range_key == "1h":
        bucket_size = 300  # 5-minute buckets for 1 hour (12 buckets)
        bucket_label_format = "%H:%M"
    elif range_key == "6h":
        bucket_size = 1800  # 30-minute buckets for 6 hours (12 buckets)
        bucket_label_format = "%H:%M"
    elif range_key == "24h":
        bucket_size = 3600  # 1-hour buckets for 24 hours (24 buckets)
        bucket_label_format = "%H:00"
    elif range_key == "7d":
        bucket_size = 86400  # 1-day buckets for 7 days (7 buckets)
        bucket_label_format = "%m/%d"
    else:
        bucket_size = 3600
        bucket_label_format = "%H:00"

    num_buckets = int(range_seconds / bucket_size)

    # Get firewall block counts from syslog (if available)
    fw_buckets = {}
    total_blocks_24h = 0
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()

            # Fetch 24h total for the summary box
            cutoff_24h_int = int(now - 86400)
            cur.execute(
                "SELECT COUNT(*) FROM fw_logs WHERE action = 'block' AND timestamp >= ?",
                (cutoff_24h_int,),
            )
            total_blocks_24h = cur.fetchone()[0] or 0

            cutoff_int = int(cutoff)

            if range_key == "7d":
                # Daily buckets for 7 days
                cur.execute(
                    """
                    SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as day,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY day
                """,
                    (cutoff_int,),
                )
                for row in cur.fetchall():
                    day_str = time.strftime("%m/%d", time.strptime(row[0], "%Y-%m-%d"))
                    fw_buckets[day_str] = {
                        "blocks": row[1],
                        "threat_blocks": row[2] or 0,
                    }
            elif range_key == "24h":
                # Hourly buckets for 24h
                cur.execute(
                    """
                    SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) as hour,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY hour
                """,
                    (cutoff_int,),
                )
                for row in cur.fetchall():
                    fw_buckets[row[0] + ":00"] = {
                        "blocks": row[1],
                        "threat_blocks": row[2] or 0,
                    }
            else:
                # For 1h and 6h, fetch all blocks and group by bucket
                cur.execute(
                    """
                    SELECT timestamp, is_threat
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                """,
                    (cutoff_int,),
                )
                for row in cur.fetchall():
                    bucket_start = int(row[0] / bucket_size) * bucket_size
                    bucket_label = time.strftime(
                        bucket_label_format, time.localtime(bucket_start)
                    )
                    if bucket_label not in fw_buckets:
                        fw_buckets[bucket_label] = {"blocks": 0, "threat_blocks": 0}
                    fw_buckets[bucket_label]["blocks"] += 1
                    if row[1]:
                        fw_buckets[bucket_label]["threat_blocks"] += 1
            conn.close()
    except Exception:
        pass

    # Build timeline buckets
    # Align bucket boundaries to epoch (same as fw_buckets) so labels match
    aligned_now = (
        int(now / bucket_size) * bucket_size + bucket_size
    )  # Next bucket boundary
    timeline = []
    for i in range(num_buckets):
        bucket_start = aligned_now - ((num_buckets - i) * bucket_size)
        bucket_end = bucket_start + bucket_size
        bucket_label = time.strftime(bucket_label_format, time.localtime(bucket_start))

        # Filter alerts for this bucket
        bucket_alerts = [
            a for a in recent if bucket_start <= a.get("ts", 0) < bucket_end
        ]

        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for a in bucket_alerts:
            by_type[a.get("type", "unknown")] += 1
            by_severity[a.get("severity", "low")] += 1

        # Add firewall block data
        fw_data = fw_buckets.get(bucket_label, {"blocks": 0, "threat_blocks": 0})

        timeline.append(
            {
                "hour": bucket_label,  # Keep 'hour' key for compatibility, but contains appropriate label
                "timestamp": bucket_start,
                "total": len(bucket_alerts),
                "by_type": dict(by_type),
                "by_severity": dict(by_severity),
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "medium": by_severity.get("medium", 0),
                "low": by_severity.get("low", 0),
                "fw_blocks": fw_data["blocks"],
                "fw_threat_blocks": fw_data["threat_blocks"],
            }
        )

    # INTEGRATION: Calculate Blocklist Match Rate (sampled from nfdump)
    tf = get_time_range(range_key)
    # Adjust sample size based on range to prevent timeouts
    sample_size = 5000 if range_key in ["1h", "6h"] else 2500
    nfdump_output = run_nfdump(["-n", str(sample_size)], tf)

    total_sampled_flows = 0
    matched_sampled_flows = 0
    flow_buckets = defaultdict(int)
    match_buckets = defaultdict(int)

    threat_set = load_threatlist()

    if nfdump_output:
        lines = nfdump_output.strip().split("\n")
        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith("ts,") or line_clean.startswith("firstseen,"):
                header_idx = i
                break

        if header_idx != -1:
            header_line = lines[header_idx].lower()
            start_row_idx = header_idx + 1
            header = [c.strip() for c in header_line.split(",")]
            try:
                # Robust header detection for nfdump 1.6 and 1.7+
                ts_idx = (
                    header.index("ts")
                    if "ts" in header
                    else (header.index("firstseen") if "firstseen" in header else 0)
                )
                sa_idx = (
                    header.index("sa")
                    if "sa" in header
                    else (header.index("srcaddr") if "srcaddr" in header else 3)
                )
                da_idx = (
                    header.index("da")
                    if "da" in header
                    else (header.index("dstaddr") if "dstaddr" in header else 5)
                )

                for line in lines[start_row_idx:]:
                    line = line.strip()
                    if (
                        not line
                        or line.startswith("ts,")
                        or line.startswith("firstseen,")
                    ):
                        continue
                    parts = line.split(",")
                    if len(parts) > max(ts_idx, sa_idx, da_idx):
                        total_sampled_flows += 1
                        try:
                            # Use faster slicing if possible, but nfdump is usually consistent
                            dt_str = parts[ts_idx].strip()
                            if len(dt_str) >= 19:
                                # Standard nfdump timestamp: YYYY-MM-DD HH:MM:SS
                                # Fast parse avoiding strptime where possible
                                try:
                                    # YYYY-MM-DD HH:MM:SS
                                    dt = datetime(
                                        int(dt_str[0:4]),
                                        int(dt_str[5:7]),
                                        int(dt_str[8:10]),
                                        int(dt_str[11:13]),
                                        int(dt_str[14:16]),
                                        int(dt_str[17:19]),
                                    )
                                    flow_ts = dt.timestamp()
                                except (ValueError, IndexError):
                                    # Fallback to strptime if format varies
                                    dt = datetime.strptime(
                                        dt_str[:19], "%Y-%m-%d %H:%M:%S"
                                    )
                                    flow_ts = dt.timestamp()

                                bucket_start = int(flow_ts / bucket_size) * bucket_size
                                bucket_label = time.strftime(
                                    bucket_label_format, time.localtime(bucket_start)
                                )
                                flow_buckets[bucket_label] += 1
                                if (
                                    parts[sa_idx].strip() in threat_set
                                    or parts[da_idx].strip() in threat_set
                                ):
                                    matched_sampled_flows += 1
                                    match_buckets[bucket_label] += 1
                        except (ValueError, IndexError, TypeError):
                            continue
            except (ValueError, IndexError):
                pass

    # Add match rate to timeline items
    for item in timeline:
        label = item["hour"]
        f_hits = flow_buckets.get(label, 0)
        m_hits = match_buckets.get(label, 0)
        item["match_rate"] = round((m_hits / f_hits * 100), 2) if f_hits > 0 else 0

    avg_match_rate = round(
        (matched_sampled_flows / max(total_sampled_flows, 1)) * 100, 2
    )
    # Estimate total matches based on avg rate and total flows if we have them (or just return the sampled count)
    total_matches = matched_sampled_flows  # For now, return sampled matches

    # Calculate rates as averages and peaks per hour based on the selected range
    total_threat_blocks = sum(t["fw_threat_blocks"] for t in timeline)
    total_all_blocks = sum(t["fw_blocks"] for t in timeline)

    # Calculate range duration in hours for normalization
    range_hours = range_seconds / 3600.0

    # Average rates (Total / Hours)
    avg_threat_rate = round(total_threat_blocks / max(range_hours, 0.01), 1)
    avg_block_rate = round(total_all_blocks / max(range_hours, 0.01), 1)

    # Peak rates normalized to /hr
    rate_multiplier = 3600.0 / bucket_size
    peak_threat_rate = round(
        max((t["fw_threat_blocks"] for t in timeline), default=0) * rate_multiplier, 1
    )
    peak_block_rate = round(
        max((t["fw_blocks"] for t in timeline), default=0) * rate_multiplier, 1
    )

    # Always fetch 24h alerts for the internal total_24h field
    cutoff_24h = now - 86400
    with threats_module._alert_history_lock:
        alerts_24h = sum(
            1 for a in threats_module._alert_history if a.get("ts", 0) > cutoff_24h
        )

    # Peak bucket
    peak = max(timeline, key=lambda x: x["total"]) if timeline else None

    return {
        "timeline": timeline,
        "avg_threat_rate": avg_threat_rate,
        "peak_threat_rate": peak_threat_rate,
        "avg_block_rate": avg_block_rate,
        "peak_block_rate": peak_block_rate,
        "avg_match_rate": avg_match_rate,
        "total_threats": total_threat_blocks,
        "total_matches": total_matches,
        "period_total": total_all_blocks,
        "period_label": range_key,
        "alerts_24h": alerts_24h,
        "blocks_24h": total_blocks_24h,
        "total_range_alerts": len(recent),
        "total_24h": alerts_24h,  # Keep for compatibility
        "peak_hour": peak["hour"] if peak and peak["total"] > 0 else None,
        "peak_count": peak["total"] if peak else 0,
        "has_fw_data": total_all_blocks > 0,
    }


@bp.route("/api/security/mitre-heatmap")
@throttle(5, 10)
def api_mitre_heatmap():
    """Get MITRE ATT&CK technique coverage from alerts."""
    range_key = request.args.get("range", "24h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 86400)

    now = time.time()
    cutoff = now - range_seconds

    with threats_module._alert_history_lock:
        recent = [a for a in threats_module._alert_history if a.get("ts", 0) > cutoff]

    # Count by MITRE technique
    techniques = defaultdict(
        lambda: {"count": 0, "alerts": [], "tactic": "", "name": ""}
    )

    for alert in recent:
        mitre = alert.get("mitre", "")
        if mitre:
            techniques[mitre]["count"] += 1
            if len(techniques[mitre]["alerts"]) < 5:
                techniques[mitre]["alerts"].append(
                    {
                        "type": alert.get("type"),
                        "msg": alert.get("msg", "")[:50],
                        "severity": alert.get("severity"),
                    }
                )

    # Enrich with MITRE info
    mitre_info = {
        "T1046": {"tactic": "Discovery", "name": "Network Service Discovery"},
        "T1110": {"tactic": "Credential Access", "name": "Brute Force"},
        "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel"},
        "T1071": {
            "tactic": "Command and Control",
            "name": "Application Layer Protocol",
        },
        "T1071.004": {"tactic": "Command and Control", "name": "DNS"},
        "T1021": {"tactic": "Lateral Movement", "name": "Remote Services"},
        "T1095": {
            "tactic": "Command and Control",
            "name": "Non-Application Layer Protocol",
        },
        "T1029": {"tactic": "Exfiltration", "name": "Scheduled Transfer"},
        "T1190": {
            "tactic": "Initial Access",
            "name": "Exploit Public-Facing Application",
        },
        "T1105": {"tactic": "Command and Control", "name": "Ingress Tool Transfer"},
        "T1595": {"tactic": "Reconnaissance", "name": "Active Scanning"},
        "T1090": {"tactic": "Command and Control", "name": "Proxy"},
        "T1584": {
            "tactic": "Resource Development",
            "name": "Compromise Infrastructure",
        },
        "T1583": {"tactic": "Resource Development", "name": "Acquire Infrastructure"},
    }

    heatmap = []
    for tech_id, data in techniques.items():
        info = mitre_info.get(tech_id, {"tactic": "Unknown", "name": tech_id})
        heatmap.append(
            {
                "id": tech_id,
                "tactic": info["tactic"],
                "name": info["name"],
                "count": data["count"],
                "alerts": data["alerts"],
            }
        )

    # Sort by count descending
    heatmap.sort(key=lambda x: x["count"], reverse=True)

    # Group by tactic for visualization
    by_tactic = defaultdict(list)
    for item in heatmap:
        by_tactic[item["tactic"]].append(item)

    return jsonify(
        {
            "techniques": heatmap,
            "by_tactic": dict(by_tactic),
            "total_techniques": len(heatmap),
            "total_detections": sum(t["count"] for t in heatmap),
            "time_scope": range_key,
        }
    )


@bp.route("/api/security/protocol-anomalies")
@throttle(5, 10)
def api_protocol_anomalies():
    """Get protocol anomaly data for Security Center."""
    from app.config import PROTOS

    range_key = request.args.get("range", "1h")
    protocols_data = get_common_nfdump_data("protos", range_key)[:20]

    anomalies = []
    for proto in protocols_data:
        proto_num = proto.get("key") or proto.get("proto")
        proto_bytes = proto.get("bytes", 0)

        # Convert protocol number to name
        try:
            proto_name = PROTOS.get(int(proto_num), f"Proto {proto_num}")
        except (ValueError, TypeError):
            proto_name = str(proto_num)

        baseline = threats_module._protocol_baseline.get(proto_num, {})
        avg = baseline.get("total_bytes", proto_bytes) / max(
            baseline.get("samples", 1), 1
        )

        deviation = (proto_bytes / avg) if avg > 0 else 1

        anomalies.append(
            {
                "protocol": proto_name,
                "bytes": proto_bytes,
                "bytes_fmt": fmt_bytes(proto_bytes),
                "avg_bytes": avg,
                "avg_fmt": fmt_bytes(avg),
                "deviation": round(deviation, 2),
                "is_anomaly": deviation > 2.0
                and proto_bytes > 5 * 1024 * 1024,  # 2x+ and 5MB+
                "flows": proto.get("flows", 0),
            }
        )

    # Sort anomalies first, then by deviation
    anomalies.sort(key=lambda x: (not x["is_anomaly"], -x["deviation"]))

    total_samples = sum(
        b.get("samples", 0) for b in threats_module._protocol_baseline.values()
    )
    status = "warming" if total_samples < 10 else "active"

    return jsonify(
        {
            "protocols": anomalies,
            "anomaly_count": sum(1 for a in anomalies if a["is_anomaly"]),
            "baseline_samples": total_samples,
            "status": status,
        }
    )


@bp.route("/api/security/run-detection")
@throttle(2, 10)
def api_run_detection():
    """Manually trigger all detection algorithms."""
    range_key = request.args.get("range", "1h")

    try:
        ports_data = get_common_nfdump_data("ports", range_key)[:50]
        sources_data = get_common_nfdump_data("sources", range_key)[:50]
        destinations_data = get_common_nfdump_data("destinations", range_key)[:50]
        protocols_data = get_common_nfdump_data("protos", range_key)[:20]

        # Fetch raw flow data for advanced detections
        tf = get_time_range(range_key)
        flow_data = get_raw_flows(tf, limit=2000)

        # Run all detections
        new_alerts = run_all_detections(
            ports_data,
            sources_data,
            destinations_data,
            protocols_data,
            flow_data=flow_data,
        )

        return jsonify(
            {"status": "ok", "new_alerts": len(new_alerts), "alerts": new_alerts[:20]}
        )
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@bp.route("/api/security/threats/by_country")
@throttle(5, 10)
def api_threats_by_country():
    """Get detections (threats + blocks) grouped by country for a time range."""
    range_key = request.args.get("range", "24h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 86400)

    now = time.time()
    cutoff = now - range_seconds

    country_stats = defaultdict(
        lambda: {"count": 0, "ips": [], "categories": defaultdict(int), "blocked": 0}
    )

    # Get blocked IPs by country from syslog
    blocked_by_country = {}
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT country_iso, COUNT(*) as blocks, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND country_iso IS NOT NULL
                GROUP BY country_iso
            """,
                (int(cutoff),),
            )
            for row in cur.fetchall():
                if row[0]:
                    blocked_by_country[row[0]] = {
                        "blocks": row[1],
                        "unique_ips": row[2],
                    }
            conn.close()
    except (sqlite3.Error, OSError):
        pass

    for ip, timeline in threats_module._threat_timeline.items():
        if now - timeline["last_seen"] < range_seconds:
            geo = lookup_geo(ip) or {}
            country = geo.get("country_iso", "XX")
            country_name = geo.get("country", "Unknown")

            country_stats[country]["count"] += 1
            country_stats[country]["name"] = country_name
            if len(country_stats[country]["ips"]) < 5:
                country_stats[country]["ips"].append(ip)

            info = get_threat_info(ip)
            country_stats[country]["categories"][info.get("category", "UNKNOWN")] += 1

    # Merge with firewall block data
    for code, block_data in blocked_by_country.items():
        if code not in country_stats:
            # Try to get full name from our shared mapping
            from app.services.shared.geoip import _COUNTRY_NAMES

            country_stats[code]["name"] = _COUNTRY_NAMES.get(code, code)
            country_stats[code]["blocked_only"] = True
        country_stats[code]["blocked"] = block_data["blocks"]
        country_stats[code]["blocked_ips"] = block_data["unique_ips"]

    # Convert to list and sort
    result = []
    for code, data in country_stats.items():
        result.append(
            {
                "country_code": code,
                "country_name": data.get("name", "Unknown"),
                "threat_count": data["count"],
                "blocked": data.get("blocked", 0),
                "blocked_ips": data.get("blocked_ips", 0),
                "sample_ips": data["ips"],
                "categories": dict(data["categories"]),
                "blocked_only": data.get("blocked_only", False),
            }
        )

    result.sort(key=lambda x: (x["threat_count"] + x["blocked"]), reverse=True)
    total_blocked = sum(r["blocked"] for r in result)

    return jsonify(
        {
            "countries": result[:20],
            "total_countries": len(result),
            "total_blocked": total_blocked,
            "has_fw_data": total_blocked > 0,
            # FIXED-SCOPE: This endpoint always uses 24h of threat data
            "time_scope": "24h",
        }
    )


@bp.route("/api/security/threat_velocity")
@throttle(5, 10)
def api_threat_velocity():
    """Get threat detection velocity (threats per hour)"""
    now = time.time()
    hour_ago = now - 3600
    two_hours_ago = now - 7200
    day_ago = now - 86400

    # Count threats in different time windows
    current_hour = 0
    last_hour = 0
    total_24h = 0
    hourly_counts = defaultdict(int)

    with threats_module._alert_history_lock:
        for alert in threats_module._alert_history:
            ts = alert.get("ts", 0)
            if ts > day_ago:
                total_24h += 1
                hour_bucket = int((now - ts) // 3600)
                hourly_counts[hour_bucket] += 1

                if ts > hour_ago:
                    current_hour += 1
                elif ts > two_hours_ago:
                    last_hour += 1

    # Calculate trend (% change from last hour)
    if last_hour > 0:
        trend = int(((current_hour - last_hour) / last_hour) * 100)
    elif current_hour > 0:
        trend = 100
    else:
        trend = 0

    # Find peak hour
    peak = max(hourly_counts.values()) if hourly_counts else 0

    return jsonify(
        {
            "current": current_hour,
            "trend": trend,
            "total_24h": total_24h,
            "peak": peak,
            "hourly": dict(hourly_counts),
        }
    )


@bp.route("/api/security/top_threat_ips")
@throttle(5, 10)
@cached_endpoint(_stats_top_threats_cache, _lock_top_threats, key_params=["range"])
def api_top_threat_ips():
    """Get top threat IPs by hit count for selected time range."""
    range_key = request.args.get("range", "24h")
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
    }.get(range_key, 86400)

    now = time.time()
    cutoff = now - range_seconds

    # Get active threats safely
    active_threats = get_active_threats(cutoff)

    # Sort simplified list first (avoid expensive lookups on entire list)
    # Convert dict items to list of (ip, data) tuples
    sorted_items = sorted(
        active_threats.items(), key=lambda x: x[1].get("hit_count", 0), reverse=True
    )

    # Process only top 50 for detailed info (Performance Optimization)
    top_items = sorted_items[:50]

    threat_ips = []
    for ip, timeline in top_items:
        # Now do the expensive lookups only for the top N items
        info = get_threat_info(ip)
        geo = lookup_geo(ip) or {}
        threat_ips.append(
            {
                "ip": ip,
                "hits": timeline.get("hit_count", 1),
                "first_seen": timeline.get("first_seen"),
                "last_seen": timeline.get("last_seen"),
                "category": info.get("category", "UNKNOWN"),
                "feed": info.get("feed", "unknown"),
                "country": geo.get("country_code", "--"),
                "country_name": geo.get("country", "Unknown"),
                "flag": geo.get("flag", ""),
                "mitre": info.get("mitre_technique", ""),
            }
        )

    return jsonify(
        {
            "ips": threat_ips[:20],  # Return top 20
            "total": len(active_threats),
        }
    )


@bp.route("/api/security/risk_index")
@throttle(5, 10)
def api_risk_index():
    """Calculate Network Risk Index based on traffic patterns and threats"""
    # Gather risk factors
    risk_factors = []
    risk_score = 0

    # Factor 1: Active threats (0-30 points)
    active_threats = get_active_threats(0)  # Get all
    threat_count = len(active_threats)
    if threat_count == 0:
        risk_factors.append(
            {"factor": "Active Threats", "value": "None", "impact": "low", "points": 0}
        )
    elif threat_count <= 5:
        risk_score += 10
        risk_factors.append(
            {
                "factor": "Active Threats",
                "value": f"{threat_count} IPs",
                "impact": "medium",
                "points": 10,
            }
        )
    elif threat_count <= 20:
        risk_score += 20
        risk_factors.append(
            {
                "factor": "Active Threats",
                "value": f"{threat_count} IPs",
                "impact": "high",
                "points": 20,
            }
        )
    else:
        risk_score += 30
        risk_factors.append(
            {
                "factor": "Active Threats",
                "value": f"{threat_count} IPs",
                "impact": "critical",
                "points": 30,
            }
        )

    # Factor 2: Threat velocity (0-20 points)
    # Count threats seen in the last hour
    # Count threats seen in the last hour
    one_hour_ago = time.time() - 3600

    # Use get_active_threats with cutoff for O(N) filtering in one pass
    recent_active = get_active_threats(one_hour_ago)
    hourly_threats = len(recent_active)
    if hourly_threats == 0:
        risk_factors.append(
            {"factor": "Threat Velocity", "value": "0/hr", "impact": "low", "points": 0}
        )
    elif hourly_threats <= 5:
        risk_score += 5
        risk_factors.append(
            {
                "factor": "Threat Velocity",
                "value": f"{hourly_threats}/hr",
                "impact": "medium",
                "points": 5,
            }
        )
    elif hourly_threats <= 20:
        risk_score += 10
        risk_factors.append(
            {
                "factor": "Threat Velocity",
                "value": f"{hourly_threats}/hr",
                "impact": "high",
                "points": 10,
            }
        )
    else:
        risk_score += 20
        risk_factors.append(
            {
                "factor": "Threat Velocity",
                "value": f"{hourly_threats}/hr",
                "impact": "critical",
                "points": 20,
            }
        )

    # Factor 3: Feed coverage (0-15 points for poor coverage)
    if threats_module._feed_status:
        ok_feeds = sum(
            1 for f in threats_module._feed_status.values() if f.get("status") == "ok"
        )
        total_feeds = len(threats_module._feed_status)
        if total_feeds > 0:
            coverage = ok_feeds / total_feeds
            if coverage >= 0.9:
                risk_factors.append(
                    {
                        "factor": "Feed Coverage",
                        "value": f"{ok_feeds}/{total_feeds}",
                        "impact": "low",
                        "points": 0,
                    }
                )
            elif coverage >= 0.7:
                risk_score += 5
                risk_factors.append(
                    {
                        "factor": "Feed Coverage",
                        "value": f"{ok_feeds}/{total_feeds}",
                        "impact": "medium",
                        "points": 5,
                    }
                )
            else:
                risk_score += 15
                risk_factors.append(
                    {
                        "factor": "Feed Coverage",
                        "value": f"{ok_feeds}/{total_feeds}",
                        "impact": "high",
                        "points": 15,
                    }
                )

    # Factor 4: Suspicious port activity (0-20 points)
    suspicious_ports = {22, 23, 3389, 445, 135, 137, 138, 139, 1433, 3306, 5432}
    # Check if any suspicious ports have high traffic (simplified check)
    suspicious_activity = False
    for port in suspicious_ports:
        if port in [22, 3389]:  # Common admin ports - flag if from unusual sources
            suspicious_activity = True
            break
    if suspicious_activity:
        risk_score += 10
        risk_factors.append(
            {
                "factor": "Suspicious Ports",
                "value": "Detected",
                "impact": "medium",
                "points": 10,
            }
        )
    else:
        risk_factors.append(
            {
                "factor": "Suspicious Ports",
                "value": "Normal",
                "impact": "low",
                "points": 0,
            }
        )

    # Factor 5: External exposure (0-15 points)
    # Only penalize if significant external traffic is detected (> 50 MB)
    try:
        sources_data = get_common_nfdump_data("sources", "1h")
        external_bytes = sum(
            s.get("bytes", 0)
            for s in sources_data
            if not s.get("internal", False) and not is_internal(s.get("key", ""))
        )

        if external_bytes > 50 * 1024 * 1024:  # > 50 MB
            risk_score += 5
            risk_factors.append(
                {
                    "factor": "External Exposure",
                    "value": "> 50MB",
                    "impact": "medium",
                    "points": 5,
                }
            )
        else:
            risk_factors.append(
                {
                    "factor": "External Exposure",
                    "value": "Low",
                    "impact": "low",
                    "points": 0,
                }
            )
    except Exception:
        # Fallback if calculation fails
        risk_factors.append(
            {
                "factor": "External Exposure",
                "value": "Unknown",
                "impact": "low",
                "points": 0,
            }
        )

    # Calculate risk level
    if risk_score <= 15:
        risk_level = "LOW"
        risk_color = "green"
    elif risk_score <= 35:
        risk_level = "MODERATE"
        risk_color = "yellow"
    elif risk_score <= 55:
        risk_level = "ELEVATED"
        risk_color = "orange"
    elif risk_score <= 75:
        risk_level = "HIGH"
        risk_color = "red"
    else:
        risk_level = "CRITICAL"
        risk_color = "red"

    return jsonify(
        {
            "score": risk_score,
            "max_score": 100,
            "level": risk_level,
            "color": risk_color,
            "factors": risk_factors,
        }
    )


@bp.route("/api/security/watchlist", methods=["GET"])
@throttle(5, 10)
def api_get_watchlist():
    """Get current watchlist"""
    watchlist = load_watchlist()
    items = []
    for ip in watchlist:
        geo = lookup_geo(ip) or {}
        items.append(
            {
                "ip": ip,
                "country": geo.get("country_code", "--"),
                "city": geo.get("city", ""),
            }
        )
    return jsonify({"watchlist": items, "count": len(items)})


@bp.route("/api/security/watchlist", methods=["POST"])
def api_add_watchlist():
    """Add IP to watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400

    success = add_to_watchlist(ip)
    return jsonify({"success": success, "ip": ip})


@bp.route("/api/security/watchlist", methods=["DELETE"])
def api_remove_watchlist():
    """Remove IP from watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400

    success = remove_from_watchlist(ip)
    return jsonify({"success": success, "ip": ip})


@bp.route("/api/security/block", methods=["POST"])
def api_security_block():
    """Block IP via security webhook (stub - not yet implemented).

    This endpoint is a placeholder for future integration with firewall
    or security automation systems. Currently returns a message indicating
    the feature is not configured.
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    action = data.get("action", "block")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    # Stub: Return informational response
    # In future, this could integrate with pfSense API, iptables, etc.
    return jsonify(
        {
            "success": False,
            "message": "Security webhook not configured. To enable IP blocking, configure a webhook endpoint.",
            "ip": ip,
            "action": action,
        }
    )


@bp.route("/api/alerts_history")
def api_alerts_history():
    return jsonify(list(threats_module._alert_history))


@bp.route("/api/alerts_export")
def api_alerts_export():
    return jsonify(list(threats_module._alert_history))


@bp.route("/api/forensics/flow-search")
def api_forensics_flow_search():
    """Advanced flow search with multi-criteria filtering for forensics investigation."""
    range_val = request.args.get("range", "1h")
    src_ip = request.args.get("src_ip", "")
    dst_ip = request.args.get("dst_ip", "")

    try:
        validate_ip_input(src_ip)
        validate_ip_input(dst_ip)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    port = request.args.get("port", "")
    protocol = request.args.get("protocol", "")
    country = request.args.get("country", "")

    # Build nfdump filter
    filters = []
    if src_ip:
        filters.append(f"src ip {src_ip}")
    if dst_ip:
        filters.append(f"dst ip {dst_ip}")
    if port:
        filters.append(f"(src port {port} or dst port {port})")
    if protocol:
        proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
        proto_num = proto_map.get(protocol.lower(), protocol)
        filters.append(f"proto {proto_num}")

    filter_str = " and ".join(filters) if filters else ""
    tf = get_time_range(range_val)

    try:
        # Build nfdump command with filters
        # Note: run_nfdump automatically adds -o csv
        nfdump_args = ["-s", "bytes", "-n", "100"]
        if filter_str:
            nfdump_args.extend(["-A", filter_str])

        output = run_nfdump(nfdump_args, tf)

        flows = []
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({"flows": [], "count": 0})

        try:
            # Robust mapping for nfdump csv outputs
            header = lines[0].split(",")
            ts_idx = (
                header.index("ts")
                if "ts" in header
                else (header.index("firstseen") if "firstseen" in header else 0)
            )
            sa_idx = (
                header.index("sa")
                if "sa" in header
                else (header.index("srcaddr") if "srcaddr" in header else 3)
            )
            da_idx = (
                header.index("da")
                if "da" in header
                else (header.index("dstaddr") if "dstaddr" in header else 5)
            )
            dp_idx = (
                header.index("dp")
                if "dp" in header
                else (header.index("dstport") if "dstport" in header else 6)
            )
            pr_idx = (
                header.index("proto")
                if "proto" in header
                else (header.index("pr") if "pr" in header else 2)
            )
            ibyt_idx = (
                header.index("ibyt")
                if "ibyt" in header
                else (header.index("bytes") if "bytes" in header else 8)
            )
            ipkt_idx = (
                header.index("ipkt")
                if "ipkt" in header
                else (header.index("packets") if "packets" in header else 7)
            )
        except ValueError:
            # Fallback indices (based on mock/nfdump std)
            sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx = 3, 4, 6, 7, 12, 11

        seen_flows = set()
        for line in lines[1:]:
            if not line or line.startswith("ts,"):
                continue
            parts = line.split(",")
            if len(parts) > max(sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx):
                try:
                    src = parts[sa_idx].strip()
                    dst = parts[da_idx].strip()
                    dst_port = parts[dp_idx].strip()
                    proto = parts[pr_idx].strip()

                    # Deduplicate flows
                    flow_key = (src, dst, proto, dst_port)
                    if flow_key in seen_flows:
                        continue
                    seen_flows.add(flow_key)

                    bytes_val = (
                        int(parts[ibyt_idx])
                        if len(parts) > ibyt_idx and parts[ibyt_idx].strip().isdigit()
                        else 0
                    )
                    packets_val = (
                        int(parts[ipkt_idx])
                        if len(parts) > ipkt_idx and parts[ipkt_idx].strip().isdigit()
                        else 0
                    )
                    port_val = int(dst_port) if dst_port.isdigit() else 0

                    # Map protocol number to name if needed
                    proto_name = proto
                    if proto.isdigit():
                        proto_name = PROTOS.get(int(proto), proto)

                    flows.append(
                        {
                            "src": src,
                            "dst": dst,
                            "proto": proto_name,
                            "port": port_val,
                            "bytes": bytes_val,
                            "packets": packets_val,
                        }
                    )
                except (ValueError, IndexError):
                    continue

        # Sort by bytes descending
        flows.sort(key=lambda x: x.get("bytes", 0), reverse=True)
        flows = flows[:100]  # Limit to top 100

        # Apply country filter if specified
        if country:
            city_db = load_city_db()
            if city_db:
                filtered_flows = []
                for flow in flows:
                    try:
                        src_rec = city_db.get(flow["src"])
                        dst_rec = city_db.get(flow["dst"])
                        src_country = (
                            src_rec.get("country", {}).get("iso_code")
                            if src_rec
                            else None
                        )
                        dst_country = (
                            dst_rec.get("country", {}).get("iso_code")
                            if dst_rec
                            else None
                        )
                        if (src_country == country.upper()) or (
                            dst_country == country.upper()
                        ):
                            filtered_flows.append(flow)
                    except (KeyError, TypeError, AttributeError):
                        pass
                flows = filtered_flows

        return jsonify({"flows": flows, "count": len(flows)})

    except Exception as e:
        add_app_log(f"Flow search error: {e}", "ERROR")
        import traceback

        traceback.print_exc()
        return jsonify({"flows": [], "count": 0, "error": str(e)})


@bp.route("/api/forensics/alert-correlation")
def api_forensics_alert_correlation():
    """Correlate alerts to identify attack chains and multi-stage attacks."""
    try:
        range_val = request.args.get("range", "24h")
        range_seconds = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}.get(
            range_val, 86400
        )
        now = time.time()
        cutoff = now - range_seconds

        def _parse_ts(val):
            """Safely convert timestamps to float seconds since epoch."""
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                # Try plain float first
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
                # Try common datetime string formats
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return datetime.strptime(val, fmt).timestamp()
                    except (ValueError, TypeError):
                        continue
            return None

        # Get alerts from history filtered by time range
        with threats_module._alert_history_lock:
            alerts = [
                a
                for a in threats_module._alert_history
                if a.get("ts", 0) > cutoff or a.get("timestamp", 0) > cutoff
            ]

        # Group alerts by IP and time proximity (within 1 hour)
        chains = {}
        time_threshold = 3600  # 1 hour in seconds

        for alert in sorted(
            alerts,
            key=lambda x: _parse_ts(x.get("timestamp", 0) or x.get("ts", 0)) or 0,
        ):
            ip = alert.get("ip") or alert.get("source_ip")
            if not ip:
                continue

            # Ensure timestamp is float
            timestamp = _parse_ts(alert.get("timestamp", 0) or alert.get("ts", 0))
            if timestamp is None:
                continue

            # Find if this IP has an existing chain within time threshold
            found_chain = False

            # Optimization: Direct lookup instead of iteration
            if ip in chains:
                chain_data = chains[ip]
                last_alert = chain_data["alerts"][-1]
                last_alert_time = _parse_ts(
                    last_alert.get("timestamp", 0) or last_alert.get("ts", 0)
                )
                if (
                    last_alert_time is not None
                    and timestamp - last_alert_time <= time_threshold
                ):
                    chain_data["alerts"].append(alert)
                    chain_data["end_time"] = timestamp
                    found_chain = True

            # Create new chain if not found (or time gap too large - overwrites old chain logic preserved for now to avoid logic drift)
            if not found_chain:
                # If we are overwriting, we effectively split the chain and keep the latest segment.
                # Ideally we should store a list of chains, but for now let's just be robust.
                chains[ip] = {
                    "ip": ip,
                    "alerts": [alert],
                    "start_time": timestamp,
                    "end_time": timestamp,
                }

        # Filter chains with multiple alerts and format response
        result_chains = []
        for ip, chain_data in chains.items():
            if (
                len(chain_data["alerts"]) > 1
            ):  # Only chains with multiple related alerts
                formatted_alerts = []
                for idx, a in enumerate(chain_data["alerts"]):
                    ts_val = _parse_ts(a.get("timestamp", 0) or a.get("ts", 0))
                    if ts_val is None:
                        time_str = "recent"
                        ts_val = 0
                    else:
                        time_str = datetime.fromtimestamp(ts_val).strftime("%H:%M:%S")

                    formatted_alerts.append(
                        {
                            "id": f"{a.get('type', 'alert')}_{ts_val}_{idx}",
                            "type": a.get("type", "unknown"),
                            "message": a.get("msg", "Alert"),
                            "time": time_str,
                        }
                    )

                result_chains.append(
                    {
                        "ip": ip,
                        "alerts": formatted_alerts,
                        "timespan": f"{len(chain_data['alerts'])} alerts over {int((chain_data['end_time'] - chain_data['start_time']) / 60)}min",
                    }
                )

        return jsonify({"chains": result_chains, "count": len(result_chains)})
    except Exception as e:
        add_app_log(f"Error in alert correlation: {e}", "ERROR")
        return jsonify({"chains": [], "count": 0, "error": str(e)}), 500


# ===== Configuration Settings =====


@bp.route("/api/stats/blocklist_rate")
@throttle(5, 10)
def api_stats_blocklist_rate():
    """Blocklist match rate statistics (sparkline data)."""
    range_key = request.args.get("range", "1h")
    now = time.time()

    # Check if we have threat data
    threat_set = load_threatlist()
    threat_count = len(threat_set)

    # Determine bucket interval based on range
    # Target approx 15-20 buckets
    # 1h = 3600s / 15 = ~240s (4 min)
    range_seconds = {
        "15m": 900,
        "30m": 1800,
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
    }.get(range_key, 3600)
    bucket_size = max(60, range_seconds // 15)

    # Initialize buckets
    num_buckets = range_seconds // bucket_size
    # End time is now, start time is now - range
    start_ts = now - range_seconds
    buckets = {i: 0 for i in range(num_buckets + 1)}

    # Fetch recent flows
    tf = get_time_range(range_key)
    # Using a higher limit to get decent stats
    output = run_nfdump(["-n", "5000"], tf)

    match_counts = defaultdict(int)
    total_matches = 0

    try:
        lines = output.strip().split("\n")
        header = lines[0].split(",")
        try:
            ts_idx = (
                header.index("ts")
                if "ts" in header
                else (header.index("firstseen") if "firstseen" in header else 0)
            )
            sa_idx = (
                header.index("sa")
                if "sa" in header
                else (header.index("srcaddr") if "srcaddr" in header else 3)
            )
            da_idx = (
                header.index("da")
                if "da" in header
                else (header.index("dstaddr") if "dstaddr" in header else 4)
            )
        except (ValueError, IndexError):
            # Safe fallbacks if index not found or header malformed
            ts_idx, sa_idx, da_idx = 0, 3, 4

        for line in lines[1:]:
            if not line or line.startswith("ts,"):
                continue
            parts = line.split(",")
            if len(parts) > max(ts_idx, sa_idx, da_idx):
                try:
                    src = parts[sa_idx]
                    dst = parts[da_idx]

                    if src in threat_set or dst in threat_set:
                        total_matches += 1

                        # Parse timestamp to bucket
                        ts_str = parts[ts_idx]
                        # Expected format: YYYY-MM-DD HH:MM:SS.mmm
                        try:
                            # Strip millis
                            ts_clean = ts_str.split(".")[0]
                            dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
                            ts_val = dt.timestamp()

                            if ts_val >= start_ts:
                                b_idx = int((ts_val - start_ts) // bucket_size)
                                if b_idx in buckets:
                                    buckets[b_idx] += 1
                        except (ValueError, IndexError, KeyError):
                            # Fallback if parsing fails: ignore time distribution
                            pass
                except (ValueError, IndexError, KeyError):
                    pass

        # Generate series
        series = []
        for i in range(num_buckets + 1):
            t = start_ts + (i * bucket_size)
            series.append({"ts": int(t * 1000), "rate": buckets[i], "blocked": 0})

        current_rate = series[-1]["rate"] if series else 0

    except Exception:
        series = []
        current_rate = 0
        total_matches = 0

    # Overlay firewall block data onto series
    total_blocked = 0
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff = int(start_ts)
            cur.execute(
                """
                SELECT timestamp, COUNT(*) as cnt
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ?
                GROUP BY CAST(timestamp / ? AS INTEGER)
                ORDER BY timestamp
            """,
                (cutoff, bucket_size),
            )

            for row in cur.fetchall():
                ts_val = row[0]
                cnt = row[1]
                total_blocked += cnt
                b_idx = int((ts_val - start_ts) // bucket_size)
                if 0 <= b_idx < len(series):
                    series[b_idx]["blocked"] = series[b_idx].get("blocked", 0) + cnt
            conn.close()
    except (sqlite3.Error, OSError):
        pass

    return jsonify(
        {
            "series": series,
            "current_rate": current_rate,
            "total_matches": total_matches,
            "total_blocked": total_blocked,
            "threat_count": threat_count,
            "has_fw_data": total_blocked > 0,
        }
    )
