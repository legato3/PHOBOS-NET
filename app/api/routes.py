"""Flask routes for PROX_NFDUMP application.

This module contains all API routes extracted from netflow-dashboard.py.
Routes are organized in a single Flask Blueprint.
"""
from flask import Blueprint, render_template, jsonify, request, Response, stream_with_context, current_app
import time
import os
import json
import socket
import socket as socket_module  # For socket.timeout in syslog receiver
import threading
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor
import sqlite3

# Import from service modules (already extracted)
from app.services.netflow import get_common_nfdump_data, run_nfdump, parse_csv, get_traffic_direction
from app.services.threats import (
    fetch_threat_feed, get_threat_info, update_threat_timeline, get_threat_timeline,
    load_watchlist, add_to_watchlist, remove_from_watchlist,
    detect_anomalies, run_all_detections,
    load_threatlist, get_feed_label, send_notifications,
    lookup_threat_intelligence, detect_ip_anomalies, generate_ip_anomaly_alerts
)
from app.services.stats import calculate_security_score
from app.services.metrics import track_performance, track_error, get_performance_metrics, get_performance_lock
from app.services.snmp import get_snmp_data, start_snmp_thread
from app.services.cpu import calculate_cpu_percent_from_stat
from app.core.threads import start_threat_thread, start_trends_thread, start_agg_thread
from app.utils.helpers import is_internal, get_region, fmt_bytes, get_time_range, flag_from_iso, load_list, check_disk_space, format_duration
from app.core.state import (
    _shutdown_event,
    _lock_summary, _lock_sources, _lock_dests, _lock_ports, _lock_protocols,
    _lock_alerts, _lock_flags, _lock_asns, _lock_durations, _lock_bandwidth,
    _lock_flows, _lock_countries, _lock_worldmap, _lock_compromised, _cache_lock, _mock_lock,
    _throttle_lock, _common_data_lock, _cpu_stat_lock,
    _stats_summary_cache, _stats_sources_cache, _stats_dests_cache,
    _stats_ports_cache, _stats_protocols_cache, _stats_alerts_cache,
    _stats_flags_cache, _stats_asns_cache, _stats_durations_cache,
    _stats_pkts_cache, _stats_countries_cache, _stats_talkers_cache,
    _stats_services_cache, _stats_hourly_cache, _stats_flow_stats_cache,
    _stats_proto_mix_cache, _stats_net_health_cache, _stats_compromised_cache, _server_health_cache,
    _mock_data_cache, _bandwidth_cache, _bandwidth_history_cache,
    _flows_cache, _common_data_cache,
    _request_times,
    _metric_nfdump_calls, _metric_stats_cache_hits, _metric_bw_cache_hits,
    _metric_conv_cache_hits, _metric_flow_cache_hits, _metric_http_429,
    _cpu_stat_prev,
    _threat_thread_started, _trends_thread_started, _agg_thread_started,
    _syslog_thread_started, _snmp_thread_started,
    _syslog_stats, _syslog_stats_lock, _syslog_buffer, _syslog_buffer_lock,
    _syslog_buffer_size,
    _snmp_cache, _snmp_cache_lock, _snmp_prev_sample, _snmp_backoff,
    _has_nfdump,
    _dns_resolver_executor,
    _flow_history, _flow_history_lock, _flow_history_ttl,
)
# Import threats module to access threat state
import app.services.threats as threats_module
import app.core.state as state
from app.utils.config_helpers import load_notify_cfg, save_notify_cfg, load_thresholds, save_thresholds, load_config, save_config
from app.utils.formatters import format_time_ago, format_uptime
from app.utils.geoip import lookup_geo, load_city_db
import app.utils.geoip as geoip_module
from app.utils.dns import resolve_ip
import app.utils.dns as dns_module
from app.utils.decorators import throttle
from app.db.sqlite import _get_firewall_block_stats, _firewall_db_connect, _firewall_db_init, _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket, _trends_db_lock, _firewall_db_lock, _trends_db_connect
from app.config import (
    FIREWALL_DB_PATH, TRENDS_DB_PATH, PORTS, PROTOS, SUSPICIOUS_PORTS,
    NOTIFY_CFG_PATH, THRESHOLDS_CFG_PATH, CONFIG_PATH, THREAT_WHITELIST,
    LONG_LOW_DURATION_THRESHOLD, LONG_LOW_BYTES_THRESHOLD
)

# Create Blueprint
bp = Blueprint('routes', __name__)

# Routes extracted from netflow-dashboard.py
# Changed @app.route() to @bp.route()

@bp.route("/")
def index():
    start_threat_thread()
    start_trends_thread()
    start_agg_thread()
    return render_template("index.html")


@bp.route("/wallboard")
@bp.route("/noc")
def wallboard():
    """NOC/Wallboard view - read-only, large typography, optimized for distance viewing."""
    return render_template("wallboard.html")


@bp.route("/api/stats/summary")
@throttle(5, 10)
def api_stats_summary():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_summary:
        if _stats_summary_cache["data"] and _stats_summary_cache.get("key") == range_key and _stats_summary_cache.get("win") == win:
            return jsonify(_stats_summary_cache["data"])

    # Reuse common data cache instead of running separate nfdump query
    # Using top 100 sources (from cache) is more accurate than top 20 for totals
    sources = get_common_nfdump_data("sources", range_key)
    tot_b = sum(i["bytes"] for i in sources)
    tot_f = sum(i["flows"] for i in sources)
    tot_p = sum(i["packets"] for i in sources)
    data = {
        "totals": {
            "bytes": tot_b,
            "flows": tot_f,
            "packets": tot_p,
            "bytes_fmt": fmt_bytes(tot_b),
            "avg_packet_size": int(tot_b/tot_p) if tot_p > 0 else 0
        },
        "notify": load_notify_cfg(),
        "threat_status": threats_module._threat_status
    }
    with _lock_summary:
        _stats_summary_cache["data"] = data
        _stats_summary_cache["ts"] = now
        _stats_summary_cache["key"] = range_key
        _stats_summary_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/sources")
@throttle(5, 10)
def api_stats_sources():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    # Cache key must include limit if we cache at this level.
    # However, the current cache logic inside this function ignores 'limit' in the key check.
    # To support variable limits correctly without rewriting the whole caching layer for this demo,
    # we can bypass the function-level cache if limit > 10, or just use the common data cache (which has 100).
    # Since get_common_nfdump_data returns 100, we can just slice from that.

    # We will skip the function-level cache check if limit > 10 for now to ensure fresh data,
    # OR we can update the cache key. Let's update the cache key.

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)

    with _lock_sources:
        if _stats_sources_cache["data"] and _stats_sources_cache.get("key") == cache_key_local and _stats_sources_cache.get("win") == win:
            return jsonify(_stats_sources_cache["data"])

    # Use shared data (top 100)
    full_sources = get_common_nfdump_data("sources", range_key)

    # Return top N
    sources = full_sources[:limit]

    # Enrich
    for i in sources:
        i["hostname"] = resolve_ip(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["region"] = get_region(i["key"], i.get("country_iso"))
        i["threat"] = False

    data = {"sources": sources}
    with _lock_sources:
        _stats_sources_cache["data"] = data
        _stats_sources_cache["ts"] = now
        _stats_sources_cache["key"] = cache_key_local
        _stats_sources_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/destinations")
@throttle(5, 10)
def api_stats_destinations():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_dests:
        if _stats_dests_cache["data"] and _stats_dests_cache.get("key") == cache_key_local and _stats_dests_cache.get("win") == win:
            return jsonify(_stats_dests_cache["data"])

    # Use shared data (top 100)
    full_dests = get_common_nfdump_data("dests", range_key)
    dests = full_dests[:limit]

    for i in dests:
        i["hostname"] = resolve_ip(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["region"] = get_region(i["key"], i.get("country_iso"))
        i["threat"] = False

    data = {"destinations": dests}
    with _lock_dests:
        _stats_dests_cache["data"] = data
        _stats_dests_cache["ts"] = now
        _stats_dests_cache["key"] = cache_key_local
        _stats_dests_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/ports")
@throttle(5, 10)
def api_stats_ports():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_ports:
        if _stats_ports_cache["data"] and _stats_ports_cache.get("key") == cache_key_local and _stats_ports_cache.get("win") == win:
            return jsonify(_stats_ports_cache["data"])

    # Use shared data (top 100, sorted by bytes)
    full_ports = get_common_nfdump_data("ports", range_key)
    ports = full_ports[:limit]

    for i in ports:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            port = int(i["key"])
            i["service"] = PORTS.get(port, "Unknown")
            i["suspicious"] = port in SUSPICIOUS_PORTS
        except Exception:
            i["service"] = "Unknown"
            i["suspicious"] = False

    data = {"ports": ports}
    with _lock_ports:
        _stats_ports_cache["data"] = data
        _stats_ports_cache["ts"] = now
        _stats_ports_cache["key"] = cache_key_local
        _stats_ports_cache["win"] = win
    return jsonify(data)


@bp.route("/api/stats/protocols")
@throttle(5, 10)
def api_stats_protocols():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_protocols:
        if _stats_protocols_cache["data"] and _stats_protocols_cache["key"] == range_key and _stats_protocols_cache.get("win") == win:
            return jsonify(_stats_protocols_cache["data"])

    # Reuse common data cache (fetches 20, we use top 10)
    protos_raw = get_common_nfdump_data("protos", range_key)[:10]

    for i in protos_raw:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            proto = int(i["key"]) if i["key"].isdigit() else 0
            i["proto_name"] = PROTOS.get(proto, i["key"])
        except Exception:
            i["proto_name"] = i["key"]

    data = {"protocols": protos_raw}
    with _lock_protocols:
        _stats_protocols_cache["data"] = data
        _stats_protocols_cache["ts"] = now
        _stats_protocols_cache["key"] = range_key
        _stats_protocols_cache["win"] = win
    return jsonify(data)


@bp.route("/api/stats/flags")
@throttle(5, 10)
def api_stats_flags():
    # New Feature: TCP Flags
    # Parse raw flows using nfdump
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_flags:
        if _stats_flags_cache["data"] and _stats_flags_cache["key"] == range_key and _stats_flags_cache.get("win") == win:
            return jsonify(_stats_flags_cache["data"])

    tf = get_time_range(range_key)

    # Get raw flows (limit 1000)
    # Note: run_nfdump automatically adds -o csv
    output = run_nfdump(["-n", "1000"], tf)

    try:
        rows = []
        lines = output.strip().split("\n")
        # Identify 'flg' column index
        header = lines[0].split(',')
        try:
            flg_idx = header.index('flg')
        except ValueError:
            # Fallback for mock or unknown
            flg_idx = 8

        for line in lines[1:]:
            parts = line.split(',')
            if len(parts) > flg_idx:
                rows.append(parts[flg_idx])

        # Simple aggregation
        counts = Counter(rows)
        clean_counts = Counter()
        for f, c in counts.items():
            clean = f.replace('.','').strip()
            if not clean: clean = "None"
            clean_counts[clean] += c

        top = [{"flag": k, "count": v} for k,v in clean_counts.most_common(5)]
        data = {"flags": top}
        with _lock_flags:
            _stats_flags_cache["data"] = data
            _stats_flags_cache["ts"] = now
            _stats_flags_cache["key"] = range_key
            _stats_flags_cache["win"] = win
        return jsonify(data)
    except Exception as e:
        return jsonify({"flags": []})


@bp.route("/api/stats/asns")
@throttle(5, 10)
def api_stats_asns():
    # New Feature: Top ASNs
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_asns:
        if _stats_asns_cache["data"] and _stats_asns_cache["key"] == range_key and _stats_asns_cache.get("win") == win:
            return jsonify(_stats_asns_cache["data"])

    # Reuse common data cache (fetches 100 sources, better than 50 for aggregation)
    sources = get_common_nfdump_data("sources", range_key)

    asn_counts = Counter()

    for i in sources:
        geo = lookup_geo(i["key"])
        org = geo.get('asn_org', 'Unknown') if geo else 'Unknown'
        if org == 'Unknown' and is_internal(i["key"]):
            org = "Internal Network"
        asn_counts[org] += i["bytes"]

    top = [{"asn": k, "bytes": v, "bytes_fmt": fmt_bytes(v)} for k,v in asn_counts.most_common(10)]
    data = {"asns": top}
    with _lock_asns:
        _stats_asns_cache["data"] = data
        _stats_asns_cache["ts"] = now
        _stats_asns_cache["key"] = range_key
        _stats_asns_cache["win"] = win
    return jsonify(data)


@bp.route("/api/stats/durations")
@throttle(5, 10)
def api_stats_durations():
    # New Feature: Longest Duration Flows
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_durations:
        if _stats_durations_cache["data"] and _stats_durations_cache["key"] == range_key and _stats_durations_cache.get("win") == win:
            return jsonify(_stats_durations_cache["data"])

    tf = get_time_range(range_key)

    output = run_nfdump(["-n", "100"], tf) # Get recent flows

    try:
        rows = []
        lines = output.strip().split("\n")
        header = lines[0].split(',')
        # Map indices
        try:
            ts_idx = header.index('ts')
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            pr_idx = header.index('proto')
            td_idx = header.index('td')
            ibyt_idx = header.index('ibyt')
        except:
            # Fallback indices
            sa_idx, da_idx, pr_idx, td_idx, ibyt_idx = 3, 4, 7, 2, 12

        seen_flows = set()  # Deduplicate flows
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue  # Skip empty lines and headers
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, td_idx):
                try:
                    # Create unique key for deduplication
                    flow_key = (parts[sa_idx], parts[da_idx], parts[pr_idx], parts[td_idx])
                    if flow_key in seen_flows: continue
                    seen_flows.add(flow_key)

                    rows.append({
                        "src": parts[sa_idx], "dst": parts[da_idx],
                        "proto": parts[pr_idx],
                        "duration": float(parts[td_idx]),
                        "bytes": int(parts[ibyt_idx]) if len(parts) > ibyt_idx else 0
                    })
                except: pass

        # Sort by duration
        sorted_flows = sorted(rows, key=lambda x: x['duration'], reverse=True)[:10]
        max_dur = sorted_flows[0]['duration'] if sorted_flows else 1

        # Calculate stats
        all_durations = [r['duration'] for r in rows if r['duration'] > 0]
        avg_duration = sum(all_durations) / len(all_durations) if all_durations else 0
        total_bytes = sum(r['bytes'] for r in rows)

        for f in sorted_flows:
            f['bytes_fmt'] = fmt_bytes(f['bytes'])
            # Format duration nicely
            dur = f['duration']
            if dur >= 3600:
                hours = int(dur // 3600)
                mins = int((dur % 3600) // 60)
                f['duration_fmt'] = f"{hours}h {mins}m"
            elif dur >= 60:
                mins = int(dur // 60)
                secs = int(dur % 60)
                f['duration_fmt'] = f"{mins}m {secs}s"
            else:
                f['duration_fmt'] = f"{dur:.2f}s"
            # Add percentage for bar width
            f['pct'] = round(dur / max_dur * 100, 1) if max_dur > 0 else 0
            # Map protocol name
            proto_val = f.get('proto', '')
            if proto_val.isdigit():
                f['proto_name'] = PROTOS.get(int(proto_val), proto_val)
            else:
                f['proto_name'] = proto_val
            # Resolve hostnames
            f['src_hostname'] = resolve_ip(f['src'])
            f['dst_hostname'] = resolve_ip(f['dst'])

        data = {
            "durations": sorted_flows,
            "stats": {
                "avg_duration": round(avg_duration, 2),
                "avg_duration_fmt": f"{avg_duration:.1f}s" if avg_duration < 60 else f"{avg_duration/60:.1f}m",
                "total_flows": len(rows),
                "total_bytes": total_bytes,
                "total_bytes_fmt": fmt_bytes(total_bytes),
                "max_duration": max_dur,
                "max_duration_fmt": f"{max_dur:.1f}s" if max_dur < 60 else f"{max_dur/60:.1f}m"
            }
        }
        with _lock_durations:
            _stats_durations_cache["data"] = data
            _stats_durations_cache["ts"] = now
            _stats_durations_cache["key"] = range_key
            _stats_durations_cache["win"] = win
        return jsonify(data)
    except Exception as e:
        return jsonify({"durations": []})


@bp.route("/api/stats/packet_sizes")
@throttle(5, 10)
def api_stats_packet_sizes():
    # New Feature: Packet Size Distribution
    range_key = request.args.get('range', '1h')
    now = time.time()
    with _cache_lock:
        if _stats_pkts_cache["data"] and _stats_pkts_cache["key"] == range_key and now - _stats_pkts_cache["ts"] < 60:
            return jsonify(_stats_pkts_cache["data"])

    tf = get_time_range(range_key)
    # Get raw flows (limit 2000 for better stats)
    tf = get_time_range(range_key)
    # Get raw flows (limit 2000 for better stats)
    output = run_nfdump(["-n", "2000"], tf)

    # Buckets
    dist = {
        "Tiny (<64B)": 0,
        "Small (64-511B)": 0,
        "Medium (512-1023B)": 0,
        "Large (1024-1513B)": 0,
        "Jumbo (>1513B)": 0
    }

    # NFDump CSV usually has no header, or specific columns: ts,td,pr,sa,sp,da,dp,ipkt,ibyt,fl
    # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx, fl_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9

    try:
        lines = output.strip().split("\n")
        # Check if first line looks like a header
        if lines and 'ibyt' in lines[0]:
             header = lines[0].split(',')
             try:
                 ibyt_idx = header.index('ibyt')
                 ipkt_idx = header.index('ipkt')
             except:
                 pass
             start_idx = 1
        else:
             start_idx = 0

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(ibyt_idx, ipkt_idx):
                try:
                    b = int(parts[ibyt_idx])
                    p = int(parts[ipkt_idx])
                    if p > 0:
                        avg = b / p
                        if avg < 64: dist["Tiny (<64B)"] += 1
                        elif avg < 512: dist["Small (64-511B)"] += 1
                        elif avg < 1024: dist["Medium (512-1023B)"] += 1
                        elif avg <= 1514: dist["Large (1024-1513B)"] += 1
                        else: dist["Jumbo (>1513B)"] += 1
                except: pass

        data = {
            "labels": list(dist.keys()),
            "data": list(dist.values())
        }
        with _cache_lock:
            _stats_pkts_cache["data"] = data
            _stats_pkts_cache["ts"] = now
            _stats_pkts_cache["key"] = range_key
        return jsonify(data)
    except Exception:
        return jsonify({"labels":[], "data":[]})



@bp.route("/api/stats/countries")
@throttle(5, 10)
def api_stats_countries():
    """Top countries by bytes using top sources and destinations (cached per 60s window)."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_countries:
        if _stats_countries_cache["data"] and _stats_countries_cache["key"] == range_key and _stats_countries_cache.get("win") == win:
            return jsonify(_stats_countries_cache["data"])

    # Reuse shared data to avoid extra nfdump
    sources = get_common_nfdump_data("sources", range_key)[:100]
    dests = get_common_nfdump_data("dests", range_key)[:100]

    country_bytes = {}
    for item in sources + dests:
        ip = item.get("key")
        b = item.get("bytes", 0)
        geo = lookup_geo(ip) or {}
        iso = geo.get('country_iso') or '??'
        name = geo.get('country') or 'Unknown'
        if iso not in country_bytes:
            country_bytes[iso] = {"name": name, "iso": iso, "bytes": 0, "flows": 0}
        country_bytes[iso]["bytes"] += b
        country_bytes[iso]["flows"] += 1

    # Sort by bytes and get top entries
    sorted_countries = sorted(country_bytes.values(), key=lambda x: x["bytes"], reverse=True)
    top = sorted_countries[:15]

    # Format for chart (backwards compatible)
    labels = [f"{c['name']} ({c['iso']})" if c['iso'] != '??' else 'Unknown' for c in top]
    bytes_vals = [c['bytes'] for c in top]

    # Enhanced data for world map
    map_data = []
    total_bytes = sum(c['bytes'] for c in sorted_countries)
    for c in sorted_countries:
        if c['iso'] != '??':
            map_data.append({
                "iso": c['iso'],
                "name": c['name'],
                "bytes": c['bytes'],
                "bytes_fmt": fmt_bytes(c['bytes']),
                "flows": c['flows'],
                "pct": round((c['bytes'] / total_bytes * 100), 1) if total_bytes > 0 else 0
            })

    data = {
        "labels": labels,
        "bytes": bytes_vals,
        "bytes_fmt": [fmt_bytes(v) for v in bytes_vals],
        "map_data": map_data,
        "total_bytes": total_bytes,
        "total_bytes_fmt": fmt_bytes(total_bytes),
        "country_count": len([c for c in sorted_countries if c['iso'] != '??'])
    }
    with _lock_countries:
        _stats_countries_cache["data"] = data
        _stats_countries_cache["ts"] = now
        _stats_countries_cache["key"] = range_key
        _stats_countries_cache["win"] = win
    return jsonify(data)


# World Map cache
_worldmap_cache = {"data": None, "ts": 0, "key": None, "win": None}
_lock_worldmap = threading.Lock()


@bp.route("/api/stats/worldmap")
@throttle(5, 10)
def api_stats_worldmap():
    """Geographic data for world map visualization with sources, destinations, and threats."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_worldmap:
        if _worldmap_cache["data"] and _worldmap_cache["key"] == range_key and _worldmap_cache.get("win") == win:
            return jsonify(_worldmap_cache["data"])

    try:
        # Get sources and destinations with geo data
        sources = get_common_nfdump_data("sources", range_key)[:50]
        dests = get_common_nfdump_data("dests", range_key)[:50]

        # Get threat IPs from the loaded threat list
        start_threat_thread()
        threat_set = load_threatlist()

        source_points = []
        dest_points = []
        threat_points = []

        # Country aggregations
        source_countries = {}
        dest_countries = {}
        threat_countries = {}
        
        # PERFORMANCE: Cache geo lookups to avoid duplicate lookups when IP appears in both sources and dests
        geo_cache = {}

        for item in sources:
            ip = item.get("key")
            if is_internal(ip):
                continue
            # PERFORMANCE: Use cached geo lookup if already fetched
            if ip not in geo_cache:
                geo_cache[ip] = lookup_geo(ip) or {}
            geo = geo_cache[ip]
            if geo.get('lat') and geo.get('lng'):
                point = {
                    "ip": ip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "bytes": item.get("bytes", 0),
                    "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city'),
                    "is_threat": ip in threat_set
                }
                source_points.append(point)

                # Aggregate by country
                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in source_countries:
                        source_countries[iso] = {"name": geo.get('country'), "bytes": 0, "count": 0}
                    source_countries[iso]["bytes"] += item.get("bytes", 0)
                    source_countries[iso]["count"] += 1

        for item in dests:
            ip = item.get("key")
            if is_internal(ip):
                continue
            # PERFORMANCE: Reuse cached geo lookup if already fetched for sources
            if ip not in geo_cache:
                geo_cache[ip] = lookup_geo(ip) or {}
            geo = geo_cache[ip]
            if geo.get('lat') and geo.get('lng'):
                point = {
                    "ip": ip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "bytes": item.get("bytes", 0),
                    "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city'),
                    "is_threat": ip in threat_set
                }
                dest_points.append(point)

                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in dest_countries:
                        dest_countries[iso] = {"name": geo.get('country'), "bytes": 0, "count": 0}
                    dest_countries[iso]["bytes"] += item.get("bytes", 0)
                    dest_countries[iso]["count"] += 1

        # Threat points with geo
        # PERFORMANCE: Reuse geo cache if threat IP was already looked up
        for tip in list(threat_set)[:100]:
            if tip not in geo_cache:
                geo_cache[tip] = lookup_geo(tip) or {}
            geo = geo_cache[tip]
            if geo.get('lat') and geo.get('lng'):
                threat_points.append({
                    "ip": tip,
                    "lat": geo['lat'],
                    "lng": geo['lng'],
                    "country": geo.get('country', 'Unknown'),
                    "country_iso": geo.get('country_iso', '??'),
                    "city": geo.get('city')
                })

                iso = geo.get('country_iso', '??')
                if iso != '??':
                    if iso not in threat_countries:
                        threat_countries[iso] = {"name": geo.get('country'), "count": 0}
                    threat_countries[iso]["count"] += 1

        # Get blocked IPs from syslog with geo data
        blocked_points = []
        blocked_countries = {}
        try:
            db_path = FIREWALL_DB_PATH
            if os.path.exists(db_path):
                range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
                cutoff = int(time.time()) - range_seconds
                conn = sqlite3.connect(db_path, timeout=5)
                cur = conn.cursor()
                cur.execute("""
                    SELECT src_ip, COUNT(*) as cnt, country_iso, is_threat
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY src_ip
                    ORDER BY cnt DESC
                    LIMIT 50
                """, (cutoff,))
                for row in cur.fetchall():
                    ip = row[0]
                    cnt = row[1]
                    country_iso = row[2]
                    is_threat = row[3]
                    geo = lookup_geo(ip) or {}
                    if geo.get('lat') and geo.get('lng'):
                        blocked_points.append({
                            "ip": ip,
                            "lat": geo['lat'],
                            "lng": geo['lng'],
                            "country": geo.get('country', 'Unknown'),
                            "country_iso": geo.get('country_iso', country_iso or '??'),
                            "city": geo.get('city'),
                            "block_count": cnt,
                            "is_threat": bool(is_threat)
                        })
                        iso = geo.get('country_iso', '??')
                        if iso != '??':
                            if iso not in blocked_countries:
                                blocked_countries[iso] = {"name": geo.get('country'), "count": 0, "blocks": 0}
                            blocked_countries[iso]["count"] += 1
                            blocked_countries[iso]["blocks"] += cnt
                conn.close()
        except:
            pass

        # Calculate totals for percentage calculations
        total_source_bytes = sum(v["bytes"] for v in source_countries.values())
        total_dest_bytes = sum(v["bytes"] for v in dest_countries.values())

        # Build country lists with percentages
        source_countries_list = []
        for k, v in sorted(source_countries.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]:
            pct = round((v["bytes"] / total_source_bytes * 100), 1) if total_source_bytes > 0 else 0
            source_countries_list.append({
                "iso": k,
                **v,
                "bytes_fmt": fmt_bytes(v["bytes"]),
                "pct": pct
            })

        dest_countries_list = []
        for k, v in sorted(dest_countries.items(), key=lambda x: x[1]["bytes"], reverse=True)[:15]:
            pct = round((v["bytes"] / total_dest_bytes * 100), 1) if total_dest_bytes > 0 else 0
            dest_countries_list.append({
                "iso": k,
                **v,
                "bytes_fmt": fmt_bytes(v["bytes"]),
                "pct": pct
            })

        data = {
            "sources": source_points[:30],
            "destinations": dest_points[:30],
            "threats": threat_points[:30],
            "blocked": blocked_points[:30],
            "source_countries": source_countries_list,
            "dest_countries": dest_countries_list,
            "threat_countries": [{"iso": k, **v} for k, v in sorted(threat_countries.items(), key=lambda x: x[1]["count"], reverse=True)[:10]],
            "blocked_countries": [{"iso": k, **v} for k, v in sorted(blocked_countries.items(), key=lambda x: x[1]["blocks"], reverse=True)[:10]],
            "summary": {
                "total_sources": len(source_points),
                "total_destinations": len(dest_points),
                "total_threats": len(threat_points),
                "total_blocked": len(blocked_points),
                "countries_reached": len(set(list(source_countries.keys()) + list(dest_countries.keys()))),
                "total_source_bytes": total_source_bytes,
                "total_source_bytes_fmt": fmt_bytes(total_source_bytes),
                "total_dest_bytes": total_dest_bytes,
                "total_dest_bytes_fmt": fmt_bytes(total_dest_bytes)
            }
        }
    except Exception as e:
        # Log error but return empty data structure to prevent API failure
        import traceback
        traceback.print_exc()
        data = {
            "sources": [],
            "destinations": [],
            "threats": [],
            "blocked": [],
            "source_countries": [],
            "dest_countries": [],
            "threat_countries": [],
            "blocked_countries": [],
            "summary": {
                "total_sources": 0,
                "total_destinations": 0,
                "total_threats": 0,
                "total_blocked": 0,
                "countries_reached": 0
            }
        }

    with _lock_worldmap:
        _worldmap_cache["data"] = data
        _worldmap_cache["ts"] = now
        _worldmap_cache["key"] = range_key
        _worldmap_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/talkers")
@throttle(5, 10)
def api_stats_talkers():
    """Top talker pairs (src→dst) by bytes."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_talkers_cache["data"] and _stats_talkers_cache["key"] == range_key and _stats_talkers_cache.get("win") == win:
            return jsonify(_stats_talkers_cache["data"])

    tf = get_time_range(range_key)
    # Sort by bytes (already sorted by nfdump, but we limits)
    # nfdump -O bytes -n 100 returns top 100 flows sorted by bytes
    output = run_nfdump(["-O", "bytes", "-n", "50"], None)

    flows = []
    # NFDump CSV indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8

    try:
        lines = output.strip().split("\n")
        # Header check skip logic
        start_idx = 0
        if lines:
            line0 = lines[0]
            if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                header = line0.split(',')
                # Map headers to indices if possible, else rely on defaults
                try:
                    # check for common variances
                    sa_key = 'sa' if 'sa' in header else 'srcAddr'
                    da_key = 'da' if 'da' in header else 'dstAddr'
                    ibyt_key = 'ibyt' if 'ibyt' in header else 'bytes'

                    if sa_key in header: sa_idx = header.index(sa_key)
                    if da_key in header: da_idx = header.index(da_key)
                    if ibyt_key in header: ibyt_idx = header.index(ibyt_key)
                    start_idx = 1
                except:
                    pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstSeen,'): continue
            parts = line.split(',')
            if len(parts) > 8:
                try:
                    ts_str = parts[ts_idx]
                    duration = float(parts[td_idx])
                    proto_val = parts[pr_idx]
                    src = parts[sa_idx]
                    src_port = parts[sp_idx]
                    dst = parts[da_idx]
                    dst_port = parts[dp_idx]
                    pkts = int(parts[ipkt_idx])
                    b = int(parts[ibyt_idx])

                    # Calculate Age
                    # ts format often: 2026-01-13 19:42:15.000
                    try:
                        # strip fractional seconds for parsing if needed, or simple str parse
                        # fast simplified parsing
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except:
                        age_sec = 0

                    # Enrich with Geo
                    src_geo = lookup_geo(src) or {}
                    dst_geo = lookup_geo(dst) or {}

                    # Resolve Service Name
                    try:
                        svc = socket.getservbyport(int(dst_port), 'tcp' if '6' in proto_val else 'udp')
                    except:
                        svc = dst_port

                    flows.append({
                        "ts": ts_str,
                        "age": format_duration(age_sec) + " ago" if age_sec < 3600 else ts_str.split(' ')[1],
                        "duration": f"{duration:.2f}s",
                        "proto": proto_val,
                        "proto_name": { "6": "TCP", "17": "UDP", "1": "ICMP" }.get(proto_val, proto_val),
                        "src": src,
                        "src_port": src_port,
                        "src_flag": src_geo.get('flag', ''),
                        "src_country": src_geo.get('country', ''),
                        "dst": dst,
                        "dst_port": dst_port,
                        "dst_flag": dst_geo.get('flag', ''),
                        "dst_country": dst_geo.get('country', ''),
                        "service": svc,
                        "bytes": b,
                        "bytes_fmt": fmt_bytes(b),
                        "packets": pkts
                    })
                except Exception:
                    pass

    except Exception as e:
        print(f"Error parsing talkers: {e}")
        pass

    with _cache_lock:
        _stats_talkers_cache["data"] = {"flows": flows}
        _stats_talkers_cache["ts"] = now
        _stats_talkers_cache["key"] = range_key
        _stats_talkers_cache["win"] = win
    return jsonify({"flows": flows})



@bp.route("/api/stats/services")
@throttle(5, 10)
def api_stats_services():
    """Top services by bytes (aggregated by service name)."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_services_cache["data"] and _stats_services_cache["key"] == range_key and _stats_services_cache.get("win") == win:
            return jsonify(_stats_services_cache["data"])

    # Reuse ports data
    ports_data = get_common_nfdump_data("ports", range_key)

    # Aggregate by service name
    service_bytes = Counter()
    service_flows = Counter()
    for item in ports_data:
        port_str = item.get("key", "")
        try:
            port = int(port_str)
            service = PORTS.get(port, f"Port {port}")
        except:
            service = port_str
        service_bytes[service] += item.get("bytes", 0)
        service_flows[service] += item.get("flows", 0)

    # Get top 10 by bytes
    top = service_bytes.most_common(10)
    services = []
    max_bytes = top[0][1] if top else 1
    for svc, b in top:
        services.append({
            "service": svc,
            "bytes": b,
            "bytes_fmt": fmt_bytes(b),
            "flows": service_flows.get(svc, 0),
            "pct": round(b / max_bytes * 100, 1)
        })

    data = {"services": services, "maxBytes": max_bytes}
    with _cache_lock:
        _stats_services_cache["data"] = data
        _stats_services_cache["ts"] = now
        _stats_services_cache["key"] = range_key
        _stats_services_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/hourly")
@throttle(5, 10)
def api_stats_hourly():
    """Traffic distribution by hour (last 24 hours)."""
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_hourly_cache["data"] and _stats_hourly_cache.get("win") == win:
            return jsonify(_stats_hourly_cache["data"])

    # Always use 24h range for hourly stats
    tf = get_time_range("24h")
    output = run_nfdump(["-n", "5000"], tf)

    # Initialize hourly buckets (0-23)
    hourly_bytes = {h: 0 for h in range(24)}
    hourly_flows = {h: 0 for h in range(24)}

    # NFDump CSV usually has no header
    # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, ibyt_idx = 0, 8

    try:
        lines = output.strip().split("\n")
        # Check if first line looks like a header
        if lines and 'ibyt' in lines[0]:
            header = lines[0].split(',')
            try:
                ts_idx = header.index('ts')
                ibyt_idx = header.index('ibyt')
            except:
                pass
            start_idx = 1
        else:
            start_idx = 0

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            if len(parts) > max(ts_idx, ibyt_idx):
                try:
                    # Parse timestamp (format: YYYY-MM-DD HH:MM:SS.mmm)
                    ts_str = parts[ts_idx]
                    if ' ' in ts_str:
                        time_part = ts_str.split(' ')[1]
                        hour = int(time_part.split(':')[0])
                    else:
                        hour = datetime.now().hour
                    b = int(parts[ibyt_idx])
                    hourly_bytes[hour] += b
                    hourly_flows[hour] += 1
                except: pass

        # Find peak hour
        peak_hour = max(hourly_bytes, key=hourly_bytes.get)
        peak_bytes = hourly_bytes[peak_hour]

        # Create labels (0:00, 1:00, etc)
        labels = [f"{h}:00" for h in range(24)]
        bytes_data = [hourly_bytes[h] for h in range(24)]
        flows_data = [hourly_flows[h] for h in range(24)]

        data = {
            "labels": labels,
            "bytes": bytes_data,
            "flows": flows_data,
            "bytes_fmt": [fmt_bytes(b) for b in bytes_data],
            "peak_hour": peak_hour,
            "peak_bytes": peak_bytes,
            "peak_bytes_fmt": fmt_bytes(peak_bytes),
            "total_bytes": sum(bytes_data),
            "total_bytes_fmt": fmt_bytes(sum(bytes_data))
        }
    except:
        data = {"labels": [], "bytes": [], "flows": [], "bytes_fmt": [], "peak_hour": 0, "peak_bytes": 0, "peak_bytes_fmt": "0 B", "total_bytes": 0, "total_bytes_fmt": "0 B"}

    with _cache_lock:
        _stats_hourly_cache["data"] = data
        _stats_hourly_cache["ts"] = now
        _stats_hourly_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/flow_stats")
@throttle(5, 10)
def api_stats_flow_stats():
    """Flow statistics - averages, totals, distributions."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_flow_stats_cache["data"] and _stats_flow_stats_cache["key"] == range_key and _stats_flow_stats_cache.get("win") == win:
            return jsonify(_stats_flow_stats_cache["data"])

    tf = get_time_range(range_key)
    output = run_nfdump(["-n", "2000"], tf)

    try:
        durations = []
        bytes_list = []
        packets_list = []
        lines = output.strip().split("\n")

        # NFDump CSV usually has no header
        # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
        td_idx, ipkt_idx, ibyt_idx = 1, 7, 8
        start_idx = 0

        # Check if first line looks like a header
        if lines and ('td' in lines[0] or 'duration' in lines[0]):
            header = lines[0].split(',')
            try:
                # Try 1.7+ standard tags
                if 'td' in header: td_idx = header.index('td')
                elif 'duration' in header: td_idx = header.index('duration')

                if 'ibyt' in header: ibyt_idx = header.index('ibyt')
                elif 'bytes' in header: ibyt_idx = header.index('bytes')

                if 'ipkt' in header: ipkt_idx = header.index('ipkt')
                elif 'packets' in header: ipkt_idx = header.index('packets')

                start_idx = 1
            except:
                pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(td_idx, ibyt_idx, ipkt_idx):
                try:
                    durations.append(float(parts[td_idx]))
                    bytes_list.append(int(parts[ibyt_idx]))
                    packets_list.append(int(parts[ipkt_idx]))
                except: pass

        total_flows = len(durations)
        total_bytes = sum(bytes_list)
        total_packets = sum(packets_list)

        avg_duration = sum(durations) / total_flows if total_flows > 0 else 0
        avg_bytes = total_bytes / total_flows if total_flows > 0 else 0
        avg_packets = total_packets / total_flows if total_flows > 0 else 0

        # Duration distribution
        short_flows = sum(1 for d in durations if d < 1)  # < 1s
        medium_flows = sum(1 for d in durations if 1 <= d < 60)  # 1s - 1m
        long_flows = sum(1 for d in durations if d >= 60)  # > 1m

        data = {
            "total_flows": total_flows,
            "total_bytes": total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes),
            "total_packets": total_packets,
            "avg_duration": round(avg_duration, 2),
            "avg_duration_fmt": f"{avg_duration:.1f}s" if avg_duration < 60 else f"{avg_duration/60:.1f}m",
            "avg_bytes": round(avg_bytes),
            "avg_bytes_fmt": fmt_bytes(avg_bytes),
            "avg_packets": round(avg_packets, 1),
            "duration_dist": {
                "short": short_flows,
                "medium": medium_flows,
                "long": long_flows
            },
            "bytes_per_packet": round(total_bytes / total_packets) if total_packets > 0 else 0
        }
    except:
        data = {"total_flows": 0, "total_bytes": 0, "total_bytes_fmt": "0 B", "avg_duration": 0, "avg_duration_fmt": "0s"}

    with _cache_lock:
        _stats_flow_stats_cache["data"] = data
        _stats_flow_stats_cache["ts"] = now
        _stats_flow_stats_cache["key"] = range_key
        _stats_flow_stats_cache["win"] = win
    return jsonify(data)



@bp.route("/api/stats/proto_mix")
@throttle(5, 10)
def api_stats_proto_mix():
    """Protocol mix for pie chart visualization."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_proto_mix_cache["data"] and _stats_proto_mix_cache["key"] == range_key and _stats_proto_mix_cache.get("win") == win:
            return jsonify(_stats_proto_mix_cache["data"])

    try:
        # Reuse protocols data
        protos_data = get_common_nfdump_data("protos", range_key)

        if not protos_data:
            # Return empty but valid structure
            return jsonify({
                "labels": [],
                "bytes": [],
                "bytes_fmt": [],
                "flows": [],
                "percentages": [],
                "colors": [],
                "total_bytes": 0,
                "total_bytes_fmt": "0 B"
            })

        labels = []
        bytes_data = []
        flows_data = []
        colors = ['#00f3ff', '#bc13fe', '#00ff88', '#ffff00', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']

        for i, p in enumerate(protos_data[:8]):  # Top 8 protocols
            proto_val = p.get('key', '')
            if not proto_val:
                continue

            # Convert protocol number to name
            if proto_val.isdigit():
                name = PROTOS.get(int(proto_val), f"Proto {proto_val}")
            else:
                name = proto_val.upper()

            labels.append(name)
            bytes_data.append(p.get('bytes', 0))
            flows_data.append(p.get('flows', 0))

        total_bytes = sum(bytes_data)
        percentages = [round(b / total_bytes * 100, 1) if total_bytes > 0 else 0 for b in bytes_data]

        data = {
            "labels": labels,
            "bytes": bytes_data,
            "bytes_fmt": [fmt_bytes(b) for b in bytes_data],
            "flows": flows_data,
            "percentages": percentages,
            "colors": colors[:len(labels)],
            "total_bytes": total_bytes,
            "total_bytes_fmt": fmt_bytes(total_bytes)
        }

        with _cache_lock:
            _stats_proto_mix_cache["data"] = data
            _stats_proto_mix_cache["ts"] = now
            _stats_proto_mix_cache["key"] = range_key
            _stats_proto_mix_cache["win"] = win
        return jsonify(data)

    except Exception as e:
        print(f"Error in proto_mix: {e}")
        import traceback
        traceback.print_exc()
        # Return empty but valid structure on error
        return jsonify({
            "labels": [],
            "bytes": [],
            "bytes_fmt": [],
            "flows": [],
            "percentages": [],
            "colors": [],
            "total_bytes": 0,
            "total_bytes_fmt": "0 B"
        })



@bp.route("/api/stats/net_health")
@throttle(5, 10)
def api_stats_net_health():
    """Network health indicators based on traffic patterns."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_net_health_cache["data"] and _stats_net_health_cache["key"] == range_key and _stats_net_health_cache.get("win") == win:
            return jsonify(_stats_net_health_cache["data"])

    tf = get_time_range(range_key)
    output = run_nfdump(["-n", "1000"], tf)

    indicators = []
    health_score = 100

    try:
        lines = output.strip().split("\n")
        if len(lines) < 2:
            raise ValueError("No flow data available")

        # Dynamic column detection
        header_line = lines[0].lower()
        header = [c.strip() for c in header_line.split(',')]

        try:
            # Try to find columns dynamically
            flg_idx = header.index('flg') if 'flg' in header else header.index('flags') if 'flags' in header else -1
            pr_idx = header.index('pr') if 'pr' in header else header.index('proto') if 'proto' in header else -1
            ibyt_idx = header.index('ibyt') if 'ibyt' in header else header.index('byt') if 'byt' in header else header.index('bytes') if 'bytes' in header else -1

            if pr_idx == -1 or ibyt_idx == -1:
                raise ValueError(f"Required columns not found. Header: {header}")
        except Exception as e:
            print(f"Column detection error: {e}")
            # Use fallback indices
            flg_idx, pr_idx, ibyt_idx = 10, 7, 12

        total_flows = 0
        rst_count = 0
        syn_only = 0
        icmp_count = 0
        small_flows = 0

        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            total_flows += 1
            if len(parts) > max(flg_idx, pr_idx, ibyt_idx):
                try:
                    flags = parts[flg_idx].upper()
                    proto = parts[pr_idx]
                    b = int(parts[ibyt_idx])

                    if 'R' in flags: rst_count += 1
                    if flags == 'S' or flags == '.S': syn_only += 1
                    if proto == '1' or proto.upper() == 'ICMP': icmp_count += 1
                    if b < 100: small_flows += 1
                except: pass

        if total_flows > 0:
            rst_pct = rst_count / total_flows * 100
            syn_pct = syn_only / total_flows * 100
            icmp_pct = icmp_count / total_flows * 100
            small_pct = small_flows / total_flows * 100

            # TCP Resets indicator
            if rst_pct < 5:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "good", "icon": "✅"})
            elif rst_pct < 15:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 10
            else:
                indicators.append({"name": "TCP Resets", "value": f"{rst_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 25

            # SYN-only (potential scans)
            if syn_pct < 2:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "good", "icon": "✅"})
            elif syn_pct < 10:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 10
            else:
                indicators.append({"name": "SYN-Only Flows", "value": f"{syn_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 20

            # ICMP traffic
            if icmp_pct < 5:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "good", "icon": "✅"})
            elif icmp_pct < 15:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 5
            else:
                indicators.append({"name": "ICMP Traffic", "value": f"{icmp_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 15

            # Small flows (potential anomaly)
            if small_pct < 20:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "good", "icon": "✅"})
            elif small_pct < 40:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "warn", "icon": "⚠️"})
                health_score -= 5
            else:
                indicators.append({"name": "Tiny Flows", "value": f"{small_pct:.1f}%", "status": "bad", "icon": "❌"})
                health_score -= 10

        health_score = max(0, min(100, health_score))

        if health_score >= 80:
            status = "healthy"
            status_icon = "💚"
        elif health_score >= 60:
            status = "fair"
            status_icon = "💛"
        else:
            status = "poor"
            status_icon = "❤️"

        # Add firewall protection status from syslog
        fw_stats = _get_firewall_block_stats()
        blocks_1h = fw_stats.get('blocks_per_hour', 0)
        syslog_active = fw_stats.get('blocks', 0) > 0 or fw_stats.get('unique_ips', 0) > 0

        if blocks_1h > 0:
            indicators.append({
                "name": "Firewall Active",
                "value": f"{int(blocks_1h)} blocks/hr",
                "status": "good",
                "icon": "🔥"
            })
            # Bonus points for active firewall protection
            health_score = min(100, health_score + 5)
        elif syslog_active:
            indicators.append({
                "name": "Firewall Active",
                "value": "0 blocks",
                "status": "good",
                "icon": "✅"
            })

        # Add threat blocking info if available
        if fw_stats.get('threats_blocked', 0) > 0:
            indicators.append({
                "name": "Threats Blocked",
                "value": str(fw_stats['threats_blocked']),
                "status": "good",
                "icon": "🛡️"
            })

        data = {
            "indicators": indicators,
            "health_score": health_score,
            "status": status,
            "status_icon": status_icon,
            "total_flows": total_flows,
            "firewall_active": syslog_active,
            "blocks_1h": int(blocks_1h)
        }
    except Exception as e:
        print(f"Error in net_health: {e}")
        import traceback
        traceback.print_exc()
        # Return degraded but informative status
        data = {
            "indicators": [{"name": "Data Unavailable", "value": "Check nfdump", "status": "warn", "icon": "⚠️"}],
            "health_score": 0,
            "status": "degraded",
            "status_icon": "⚠️",
            "total_flows": 0,
            "firewall_active": False,
            "blocks_1h": 0
        }

    with _cache_lock:
        _stats_net_health_cache["data"] = data
        _stats_net_health_cache["ts"] = now
        _stats_net_health_cache["key"] = range_key
        _stats_net_health_cache["win"] = win
    return jsonify(data)


# ===== Trends (5-minute rollups stored in SQLite) =====


@bp.route("/api/firewall/logs/stats")
@throttle(5, 10)
def api_firewall_logs_stats():
    """Get firewall log statistics."""
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Total blocks and passes
            cur = conn.execute("""
                SELECT action, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? GROUP BY action
            """, (cutoff,))
            counts = {row[0]: row[1] for row in cur.fetchall()}

            blocks = counts.get('block', 0) + counts.get('reject', 0)
            passes = counts.get('pass', 0)

            # Unique blocked IPs
            cur = conn.execute("""
                SELECT COUNT(DISTINCT src_ip) FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """, (cutoff,))
            unique_blocked = cur.fetchone()[0] or 0

            # Top blocked ports
            cur = conn.execute("""
                SELECT dst_port, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject') AND dst_port > 0
                GROUP BY dst_port ORDER BY cnt DESC LIMIT 10
            """, (cutoff,))
            top_ports = [{"port": row[0], "count": row[1], "service": PORTS.get(row[0], "Unknown")} for row in cur.fetchall()]

            # Top blocked countries
            cur = conn.execute("""
                SELECT country_iso, COUNT(*) as cnt FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject') AND country_iso IS NOT NULL
                GROUP BY country_iso ORDER BY cnt DESC LIMIT 10
            """, (cutoff,))
            top_countries = [{"iso": row[0], "count": row[1]} for row in cur.fetchall()]

            # Threat matches
            cur = conn.execute("""
                SELECT COUNT(*) FROM fw_logs
                WHERE timestamp > ? AND is_threat = 1
            """, (cutoff,))
            threat_hits = cur.fetchone()[0] or 0

        finally:
            conn.close()

    hours = range_seconds / 3600
    with _syslog_stats_lock:
        receiver_stats = dict(_syslog_stats)
    data = {
        "blocks_total": blocks,
        "blocks_per_hour": round(blocks / hours, 1) if hours > 0 else 0,
        "passes_total": passes,
        "unique_blocked_ips": unique_blocked,
        "top_blocked_ports": top_ports,
        "top_blocked_countries": top_countries,
        "threat_hits": threat_hits,
        "receiver_stats": receiver_stats
    }
    return jsonify(data)



@bp.route("/api/firewall/stats/overview")
@throttle(5, 10)
def api_firewall_stats_overview():
    """Get high-signal firewall stat box metrics for at-a-glance situational awareness."""
    now = time.time()
    cutoff_24h = now - 86400  # 24 hours
    cutoff_7d = now - (7 * 86400)  # 7 days lookback for "new" IPs
    
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # 1. Blocked Events (24h)
            cur = conn.execute("""
                SELECT COUNT(*) FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """, (cutoff_24h,))
            blocked_events_24h = cur.fetchone()[0] or 0
            
            # 2. Unique Blocked Sources (24h)
            cur = conn.execute("""
                SELECT COUNT(DISTINCT src_ip) FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """, (cutoff_24h,))
            unique_blocked_sources = cur.fetchone()[0] or 0
            
            # 3. New Blocked IPs (blocked in 24h but not in previous 7 days)
            # Get IPs blocked in last 24h
            cur = conn.execute("""
                SELECT DISTINCT src_ip FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
            """, (cutoff_24h,))
            recent_blocked_ips = set(row[0] for row in cur.fetchall() if row[0])
            
            # Get IPs blocked in previous 7 days (before last 24h)
            cur = conn.execute("""
                SELECT DISTINCT src_ip FROM fw_logs
                WHERE timestamp > ? AND timestamp <= ? AND action IN ('block', 'reject')
            """, (cutoff_7d, cutoff_24h))
            previous_blocked_ips = set(row[0] for row in cur.fetchall() if row[0])
            
            # New IPs = recent - previous
            new_blocked_ips = len(recent_blocked_ips - previous_blocked_ips)
            
            # 4. Top Block Reason / Rule
            # Get the most common rule_id and enrich it with context (interface, direction, port)
            cur = conn.execute("""
                SELECT 
                    COALESCE(rule_id, 'default') as rule_or_reason,
                    COUNT(*) as cnt
                FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
                GROUP BY rule_or_reason
                ORDER BY cnt DESC
                LIMIT 1
            """, (cutoff_24h,))
            top_rule_row = cur.fetchone()
            raw_reason = top_rule_row[0] if top_rule_row and top_rule_row[0] else "N/A"
            top_block_count = top_rule_row[1] if top_rule_row else 0
            
            # Get context for the top rule to make it more descriptive
            if raw_reason and raw_reason != "N/A" and raw_reason != "default":
                # Get the most common characteristics for this rule
                cur = conn.execute("""
                    SELECT 
                        interface,
                        direction,
                        dst_port,
                        proto,
                        COUNT(*) as cnt
                    FROM fw_logs
                    WHERE timestamp > ? 
                        AND action IN ('block', 'reject')
                        AND COALESCE(rule_id, 'default') = ?
                    GROUP BY interface, direction, dst_port, proto
                    ORDER BY cnt DESC
                    LIMIT 1
                """, (cutoff_24h, raw_reason))
                context_row = cur.fetchone()
                
                if context_row:
                    interface, direction, dst_port, proto, _ = context_row
                    context_parts = []
                    
                    # Add interface context (e.g., "WAN", "LAN")
                    if interface:
                        context_parts.append(interface.upper())
                    
                    # Add direction context
                    if direction:
                        dir_arrow = "→" if direction == "out" else "←"
                        context_parts.append(dir_arrow)
                    
                    # Add port context if available
                    if dst_port and dst_port > 0:
                        port_name = PORTS.get(dst_port, None)
                        if port_name:
                            context_parts.append(f"{port_name} ({dst_port})")
                        else:
                            context_parts.append(f"Port {dst_port}")
                    
                    # Add protocol if available
                    if proto:
                        context_parts.append(proto.upper())
                    
                    # Build descriptive label
                    if raw_reason.isdigit():
                        context_str = " • ".join(context_parts) if context_parts else ""
                        if context_str:
                            top_block_reason = f"Rule #{raw_reason} ({context_str})"
                        else:
                            top_block_reason = f"Rule #{raw_reason}"
                    else:
                        top_block_reason = raw_reason
                else:
                    # No context found, just format the rule ID
                    if raw_reason.isdigit():
                        top_block_reason = f"Rule #{raw_reason}"
                    else:
                        top_block_reason = raw_reason
            else:
                # Default or N/A case
                top_block_reason = "Default Block"
            
        finally:
            conn.close()
    
    # Update baseline for firewall blocks rate (blocks per hour)
    from app.utils.baselines import update_baseline, calculate_trend
    blocks_rate = blocked_events_24h / 24.0 if blocked_events_24h > 0 else 0.0
    update_baseline('firewall_blocks_rate', blocks_rate)
    
    # Calculate trend for blocked events (using rate for comparison)
    blocked_trend = calculate_trend('firewall_blocks_rate', blocks_rate)
    
    return jsonify({
        "blocked_events_24h": blocked_events_24h,
        "unique_blocked_sources": unique_blocked_sources,
        "new_blocked_ips": new_blocked_ips,
        "top_block_reason": top_block_reason,
        "top_block_count": top_block_count,
        "trends": {
            "blocked_events": blocked_trend
        }
    })


@bp.route("/api/firewall/logs/blocked")
@throttle(5, 10)
def api_firewall_logs_blocked():
    """Get top blocked IPs."""
    range_key = request.args.get('range', '1h')
    limit = min(int(request.args.get('limit', 20)), 100)
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            cur = conn.execute("""
                SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT dst_port) as ports,
                       MAX(country_iso) as country, MAX(is_threat) as is_threat
                FROM fw_logs
                WHERE timestamp > ? AND action IN ('block', 'reject')
                GROUP BY src_ip ORDER BY cnt DESC LIMIT ?
            """, (cutoff, limit))

            blocked_ips = []
            for row in cur.fetchall():
                ports_str = row[3] or ""
                ports_list = [int(p) for p in ports_str.split(',') if p.isdigit()][:5]

                ip = row[0]
                geo = lookup_geo(ip)

                blocked_ips.append({
                    "ip": ip,
                    "count": row[1],
                    "last_seen": datetime.fromtimestamp(row[2]).isoformat() if row[2] else None,
                    "ports_targeted": ports_list,
                    "country": geo.get('country') if geo else None,
                    "country_iso": row[4],
                    "flag": flag_from_iso(row[4]) if row[4] else "",
                    "is_threat": bool(row[5]),
                    "hostname": resolve_ip(ip)
                })
        finally:
            conn.close()

    return jsonify({"blocked_ips": blocked_ips})



@bp.route("/api/firewall/logs/timeline")
@throttle(5, 10)
def api_firewall_logs_timeline():
    """Get hourly timeline of blocks/passes."""
    range_key = request.args.get('range', '24h')
    range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 86400)
    cutoff = time.time() - range_seconds

    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            # Group by hour
            cur = conn.execute("""
                SELECT
                    CAST((timestamp / 3600) AS INTEGER) * 3600 as hour_ts,
                    action,
                    COUNT(*) as cnt
                FROM fw_logs
                WHERE timestamp > ?
                GROUP BY hour_ts, action
                ORDER BY hour_ts
            """, (cutoff,))

            hours_data = {}
            for row in cur.fetchall():
                hour_ts = row[0]
                action = row[1]
                count = row[2]

                if hour_ts not in hours_data:
                    hours_data[hour_ts] = {"blocks": 0, "passes": 0}

                if action in ('block', 'reject'):
                    hours_data[hour_ts]["blocks"] += count
                elif action == 'pass':
                    hours_data[hour_ts]["passes"] += count
        finally:
            conn.close()

    timeline = [
        {
            "hour": datetime.fromtimestamp(ts).isoformat(),
            "hour_ts": ts,
            "blocks": data["blocks"],
            "passes": data["passes"]
        }
        for ts, data in sorted(hours_data.items())
    ]

    return jsonify({"timeline": timeline})



@bp.route("/api/firewall/logs/recent")
@throttle(5, 10)
def api_firewall_logs_recent():
    """Get most recent firewall log entries (up to 1000)."""
    limit = min(int(request.args.get('limit', 1000)), 1000)
    action_filter = request.args.get('action')  # 'block', 'pass', or None for all
    since_ts = request.args.get('since')  # Optional: only return logs newer than this timestamp
    now = time.time()
    cutoff_1h = now - 3600

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

            cur = conn.execute(f"""
                SELECT timestamp, timestamp_iso, action, direction, interface, src_ip, src_port,
                       dst_ip, dst_port, proto, country_iso, is_threat
                FROM fw_logs WHERE {where_sql} ORDER BY timestamp DESC LIMIT ?
            """, params)

            logs = []
            action_counts = {"block": 0, "reject": 0, "pass": 0}
            unique_src = set()
            unique_dst = set()
            threat_count = 0
            blocks_last_hour = 0
            passes_last_hour = 0
            latest_ts = None

            for row in cur.fetchall():
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

                # Stats
                if action in action_counts:
                    action_counts[action] += 1
                if is_threat:
                    threat_count += 1
                if ts and action in ('block', 'reject') and ts >= cutoff_1h:
                    blocks_last_hour += 1
                if ts and action == 'pass' and ts >= cutoff_1h:
                    passes_last_hour += 1
                if src_ip:
                    unique_src.add(src_ip)
                if dst_ip:
                    unique_dst.add(dst_ip)
                if ts and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts

                logs.append({
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
                    "service": PORTS.get(dst_port, "") if dst_port else ""
                })
        finally:
            conn.close()

    stats = {
        "total": len(logs),
        "actions": action_counts,
        "threats": threat_count,
        "unique_src": len(unique_src),
        "unique_dst": len(unique_dst),
        "blocks_last_hour": blocks_last_hour,
        "passes_last_hour": passes_last_hour,
        "latest_ts": latest_ts
    }

    with _syslog_stats_lock:
        receiver_stats = dict(_syslog_stats)
    return jsonify({"logs": logs, "stats": stats, "receiver_stats": receiver_stats})



@bp.route("/api/alerts")
@throttle(5, 10)
def api_alerts():
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)
    with _lock_alerts:
        if _stats_alerts_cache["data"] and _stats_alerts_cache["key"] == range_key and _stats_alerts_cache.get("win") == win:
            return jsonify(_stats_alerts_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)

    # Run analysis (using shared data)
    # Alerts logic uses top sources/dests/ports for comprehensive IP coverage
    sources = get_common_nfdump_data("sources", range_key)[:50]
    dests = get_common_nfdump_data("dests", range_key)[:50]
    ports = get_common_nfdump_data("ports", range_key)

    alerts = detect_anomalies(ports, sources, threat_set, whitelist, destinations_data=dests)
    send_notifications([a for a in alerts if a.get("severity") in ("critical","high")])

    data = {
        "alerts": alerts, # Not limited to 10
        "feed_label": get_feed_label()
    }
    with _lock_alerts:
        _stats_alerts_cache["data"] = data
        _stats_alerts_cache["ts"] = now
        _stats_alerts_cache["key"] = range_key
        _stats_alerts_cache["win"] = win
    return jsonify(data)



@bp.route("/api/bandwidth")
@throttle(10,20)
def api_bandwidth():
    range_key = request.args.get('range', '1h')
    now_ts = time.time()

    # Determine bucket count based on range (5-min buckets)
    # 1h = 12 buckets
    # 30m = 6 buckets
    # 15m = 3 buckets
    bucket_count = 12
    if range_key == '30m': bucket_count = 6
    elif range_key == '15m': bucket_count = 3
    elif range_key == '6h': bucket_count = 72
    elif range_key == '24h': bucket_count = 288
    elif range_key == '7d': bucket_count = 7*24*12

    # Separate cache key for different ranges?
    # Current _bandwidth_cache is global. If we switch range, we overwrite.
    # That's acceptable for single-user, but we should probably key it.

    cache_key = f"bw_{range_key}"

    # Check cache with range key validation
    with _lock_bandwidth:
        if _bandwidth_cache.get("data") and _bandwidth_cache.get("key") == cache_key and now_ts - _bandwidth_cache.get("ts", 0) < 5:
            global _metric_bw_cache_hits
            _metric_bw_cache_hits += 1
            return jsonify(_bandwidth_cache["data"])

    now = datetime.now()
    labels, bw, flows = [], [], []

    # Use trends DB for completed buckets; compute only incomplete current if needed
    _trends_db_init()
    current_bucket_end = _get_bucket_end(now)

    try:
        # Fetch required completed buckets from DB in one query
        end_needed = current_bucket_end  # may include current incomplete bucket
        start_needed = end_needed - timedelta(minutes=5*bucket_count)
        start_ts = int((start_needed).timestamp())
        end_ts = int((end_needed).timestamp())

        with _trends_db_lock:
            conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
            try:
                cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM traffic_rollups WHERE bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (start_ts, end_ts)
                )
                rows = cur.fetchall()
            finally:
                conn.close()

        # Build a mapping for quick lookup
        by_end = {r[0]: {"bytes": r[1], "flows": r[2]} for r in rows}

        # Identify missing buckets that need computation
        missing_buckets = []
        for i in range(bucket_count, 0, -1):
            et = current_bucket_end - timedelta(minutes=i*5)
            et_ts = int(et.timestamp())
            if et_ts not in by_end and et < now:
                missing_buckets.append(et)

        # Parallel compute missing buckets
        if missing_buckets:
            # Optimization for Mock Mode:
            # If we don't have real nfdump, we are using static sample data.
            # Calculating 288 buckets (24h) of identical static data is wasteful.
            # Calculate once and replicate.
            if state._has_nfdump is None:
                try:
                    subprocess.run(["nfdump", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    state._has_nfdump = True
                except (OSError, subprocess.CalledProcessError):
                    state._has_nfdump = False

            if state._has_nfdump is False and len(missing_buckets) > 1:
                # Compute the first one to prime the data
                ref_dt = missing_buckets[0]
                _ensure_rollup_for_bucket(ref_dt)

                # Copy result to all other buckets
                ref_ts = int(ref_dt.timestamp())

                with _trends_db_lock:
                    conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
                    try:
                        # Fetch the computed reference data
                        cur = conn.execute("SELECT bytes, flows FROM traffic_rollups WHERE bucket_end=?", (ref_ts,))
                        roll_row = cur.fetchone()

                        cur = conn.execute("SELECT ip, bytes, flows FROM top_sources WHERE bucket_end=?", (ref_ts,))
                        src_rows = cur.fetchall()

                        cur = conn.execute("SELECT ip, bytes, flows FROM top_dests WHERE bucket_end=?", (ref_ts,))
                        dst_rows = cur.fetchall()

                        # Bulk insert for all other missing buckets
                        if roll_row:
                            params = []
                            for dt in missing_buckets[1:]:
                                params.append((int(dt.timestamp()), roll_row[0], roll_row[1]))
                            conn.executemany("INSERT OR REPLACE INTO traffic_rollups(bucket_end, bytes, flows) VALUES (?,?,?)", params)

                        if src_rows:
                            params = []
                            for dt in missing_buckets[1:]:
                                ts = int(dt.timestamp())
                                for r in src_rows:
                                    params.append((ts, r[0], r[1], r[2]))
                            conn.executemany("INSERT OR REPLACE INTO top_sources(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)", params)

                        if dst_rows:
                            params = []
                            for dt in missing_buckets[1:]:
                                ts = int(dt.timestamp())
                                for r in dst_rows:
                                    params.append((ts, r[0], r[1], r[2]))
                            conn.executemany("INSERT OR REPLACE INTO top_dests(bucket_end, ip, bytes, flows) VALUES (?,?,?,?)", params)

                        conn.commit()
                    finally:
                        conn.close()
            else:
                # Normal behavior (or single bucket)
                # Use a reasonable number of workers to avoid overloading the system
                # 8 workers allows decent parallelism without excessive context switching
                with ThreadPoolExecutor(max_workers=8) as executor:
                    list(executor.map(_ensure_rollup_for_bucket, missing_buckets))

            # Re-fetch data after computation
            with _trends_db_lock:
                conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
                try:
                    cur = conn.execute(
                        "SELECT bucket_end, bytes, flows FROM traffic_rollups WHERE bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                        (start_ts, end_ts)
                    )
                    rows = cur.fetchall()
                    by_end = {r[0]: {"bytes": r[1], "flows": r[2]} for r in rows}
                finally:
                    conn.close()

        for i in range(bucket_count, 0, -1):
            et = current_bucket_end - timedelta(minutes=i*5)
            et_ts = int(et.timestamp())
            labels.append(et.strftime("%H:%M"))
            rec = by_end.get(et_ts)
            if rec:
                total_b = rec["bytes"]
                total_f = rec["flows"]
                val_bw = round((total_b*8)/(300*1_000_000),2)
                val_flows = round(total_f/300,2)
            else:
                val_bw = 0
                val_flows = 0

            bw.append(val_bw)
            flows.append(val_flows)

        data = {"labels":labels,"bandwidth":bw,"flows":flows, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
        with _lock_bandwidth:
            _bandwidth_cache["data"] = data
            _bandwidth_cache["ts"] = now_ts
            _bandwidth_cache["key"] = cache_key
        return jsonify(data)
    except Exception:
        return jsonify({"labels":[],"bandwidth":[],"flows":[]}), 500


@bp.route("/api/network/stats/overview")
@throttle(5, 10)
def api_network_stats_overview():
    """Get high-signal network stat box metrics for at-a-glance network behavior insight."""
    now = time.time()
    tf_24h = get_time_range('24h')
    
    # Get current active flows (1h range for "current")
    tf_1h = get_time_range('1h')
    
    # Load threat list for correlation
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    threat_set = threat_set - whitelist
    
    # Get total flow count without limit - use -q (quiet) mode and count all flows
    # This gives us the true count independent of display limits
    active_flows_count = 0
    external_connections_count = 0
    
    # Get total count by running without -n limit, using -q for quiet output
    # Count all flow lines (excluding header)
    try:
        full_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-q"], tf_1h)
        if full_output:
            lines = full_output.strip().split("\n")
            # Count non-header lines (actual flow records)
            for line in lines:
                if line and not line.startswith('ts,') and not line.startswith('firstSeen,') and not line.startswith('Date,') and ',' in line:
                    # Check if it's a valid flow line (has enough fields)
                    parts = line.split(',')
                    if len(parts) > 7:
                        active_flows_count += 1
    except Exception as e:
        # Log error in production, but don't fail the endpoint
        active_flows_count = 0
    
    # Now get external connections count using a sample
    # We use a sample (500 flows) to determine the ratio of external connections
    # This is more efficient than processing all flows
    if active_flows_count > 0:
        sample_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", "500"], tf_1h)
        sample_count = 0
        sample_external = 0
        
        try:
            lines = sample_output.strip().split("\n")
            start_idx = 0
            sa_idx = 0
            da_idx = 0
            
            if lines:
                line0 = lines[0]
                if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                    header = line0.split(',')
                    try:
                        sa_key = 'sa' if 'sa' in header else 'srcAddr'
                        if 'srcaddr' in header: sa_key = 'srcaddr'
                        da_key = 'da' if 'da' in header else 'dstAddr'
                        if 'dstaddr' in header: da_key = 'dstaddr'
                        if sa_key in header: sa_idx = header.index(sa_key)
                        if da_key in header: da_idx = header.index(da_key)
                        start_idx = 1
                    except:
                        pass
            
            for line in lines[start_idx:]:
                if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
                parts = line.split(',')
                if len(parts) > 7:
                    try:
                        # Safe access with bounds checking
                        src = parts[sa_idx] if len(parts) > sa_idx and sa_idx < len(parts) else ""
                        dst = parts[da_idx] if len(parts) > da_idx and da_idx < len(parts) else ""
                        
                        if src and dst:
                            sample_count += 1
                            
                            # Check if external connection (not internal-to-internal)
                            src_internal = is_internal(src)
                            dst_internal = is_internal(dst)
                            
                            if not (src_internal and dst_internal):
                                sample_external += 1
                    except:
                        pass
            
            # Estimate external connections based on sample ratio
            if sample_count > 0:
                external_ratio = sample_external / sample_count
                external_connections_count = int(active_flows_count * external_ratio)
            else:
                external_connections_count = 0
        except:
            external_connections_count = 0
    else:
        external_connections_count = 0
    
    # Count anomalies (detections) over 24h
    # Fetch flows with detection criteria over 24h range
    output_24h = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto"], tf_24h)
    
    anomalies_24h = 0
    
    try:
        lines_24h = output_24h.strip().split("\n")
        start_idx_24h = 0
        # Initialize index variables with safe defaults
        sa_idx_24h = 0
        da_idx_24h = 0
        ibyt_idx_24h = 0
        td_idx_24h = 0
        
        if lines_24h:
            line0_24h = lines_24h[0]
            if 'ts' in line0_24h or 'Date' in line0_24h or 'ibyt' in line0_24h or 'firstSeen' in line0_24h or 'firstseen' in line0_24h:
                header_24h = line0_24h.split(',')
                try:
                    sa_key_24h = 'sa' if 'sa' in header_24h else 'srcAddr'
                    if 'srcaddr' in header_24h: sa_key_24h = 'srcaddr'
                    da_key_24h = 'da' if 'da' in header_24h else 'dstAddr'
                    if 'dstaddr' in header_24h: da_key_24h = 'dstaddr'
                    ibyt_key_24h = 'ibyt' if 'ibyt' in header_24h else 'bytes'
                    if sa_key_24h in header_24h: sa_idx_24h = header_24h.index(sa_key_24h)
                    if da_key_24h in header_24h: da_idx_24h = header_24h.index(da_key_24h)
                    if ibyt_key_24h in header_24h: ibyt_idx_24h = header_24h.index(ibyt_key_24h)
                    if 'td' in header_24h: td_idx_24h = header_24h.index('td')
                    elif 'duration' in header_24h: td_idx_24h = header_24h.index('duration')
                    start_idx_24h = 1
                except:
                    pass
        
        for line in lines_24h[start_idx_24h:]:
            if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
            parts = line.split(',')
            if len(parts) > 7:
                try:
                    # Safe access with bounds checking
                    duration = float(parts[td_idx_24h]) if len(parts) > td_idx_24h and td_idx_24h < len(parts) else 0.0
                    src = parts[sa_idx_24h] if len(parts) > sa_idx_24h and sa_idx_24h < len(parts) else ""
                    dst = parts[da_idx_24h] if len(parts) > da_idx_24h and da_idx_24h < len(parts) else ""
                    b = int(parts[ibyt_idx_24h]) if len(parts) > ibyt_idx_24h and ibyt_idx_24h < len(parts) else 0
                    
                    if src and dst:
                        # Check if this flow matches detection criteria: long-lived, low-volume, external
                        src_internal = is_internal(src)
                        dst_internal = is_internal(dst)
                        is_external = not (src_internal and dst_internal)
                        
                        if is_external and duration > LONG_LOW_DURATION_THRESHOLD and b < LONG_LOW_BYTES_THRESHOLD:
                            anomalies_24h += 1
                except:
                    pass
    except:
        pass
    
    # Update baselines (incremental, respects update interval)
    from app.utils.baselines import update_baseline, calculate_trend
    update_baseline('active_flows', active_flows_count)
    update_baseline('external_connections', external_connections_count)
    
    # Calculate anomalies rate (anomalies per hour) and update baseline
    anomalies_rate = anomalies_24h / 24.0 if anomalies_24h > 0 else 0.0
    update_baseline('anomalies_rate', anomalies_rate)
    
    # Calculate trends (since last hour)
    active_flows_trend = calculate_trend('active_flows', active_flows_count)
    external_connections_trend = calculate_trend('external_connections', external_connections_count)
    anomalies_trend = calculate_trend('anomalies_rate', anomalies_rate)
    
    return jsonify({
        "active_flows": active_flows_count,
        "external_connections": external_connections_count,
        "anomalies_24h": anomalies_24h,
        "trends": {
            "active_flows": active_flows_trend,
            "external_connections": external_connections_trend,
            "anomalies": anomalies_trend
        }
    })


@bp.route("/api/health/baseline-signals")
@throttle(5, 10)
def api_health_baseline_signals():
    """Get baseline-aware health signals for overall health classification.
    
    Returns signals based on baseline deviations rather than static thresholds.
    This enables environment-specific, adaptive health classification.
    """
    from app.utils.baselines import is_abnormal, get_baseline_stats
    from app.services.netflow import run_nfdump
    from app.utils.helpers import get_time_range, is_internal
    from app.config import LONG_LOW_DURATION_THRESHOLD, LONG_LOW_BYTES_THRESHOLD
    import time
    
    now = time.time()
    tf_1h = get_time_range('1h')
    tf_24h = get_time_range('24h')
    
    signals = []
    signal_details = []
    
    # Get current metric values
    # 1. Active Flows
    try:
        full_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-q"], tf_1h)
        active_flows = 0
        if full_output:
            lines = full_output.strip().split("\n")
            for line in lines:
                if line and not line.startswith('ts,') and not line.startswith('firstSeen,') and not line.startswith('Date,') and ',' in line:
                    parts = line.split(',')
                    if len(parts) > 7:
                        active_flows += 1
    except:
        active_flows = 0
    
    # 2. External Connections (sample-based estimate)
    external_connections = 0
    if active_flows > 0:
        try:
            sample_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", "500"], tf_1h)
            sample_count = 0
            sample_external = 0
            if sample_output:
                lines = sample_output.strip().split("\n")
                start_idx = 0
                sa_idx = 0
                da_idx = 0
                if lines:
                    line0 = lines[0]
                    if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                        header = line0.split(',')
                        try:
                            sa_key = 'sa' if 'sa' in header else 'srcAddr'
                            if 'srcaddr' in header: sa_key = 'srcaddr'
                            da_key = 'da' if 'da' in header else 'dstAddr'
                            if 'dstaddr' in header: da_key = 'dstaddr'
                            if sa_key in header: sa_idx = header.index(sa_key)
                            if da_key in header: da_idx = header.index(da_key)
                            start_idx = 1
                        except:
                            pass
                for line in lines[start_idx:]:
                    if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
                    parts = line.split(',')
                    if len(parts) > 7:
                        try:
                            src = parts[sa_idx] if len(parts) > sa_idx and sa_idx < len(parts) else ""
                            dst = parts[da_idx] if len(parts) > da_idx and da_idx < len(parts) else ""
                            if src and dst:
                                sample_count += 1
                                src_internal = is_internal(src)
                                dst_internal = is_internal(dst)
                                if not (src_internal and dst_internal):
                                    sample_external += 1
                        except:
                            pass
                if sample_count > 0:
                    external_ratio = sample_external / sample_count
                    external_connections = int(active_flows * external_ratio)
        except:
            pass
    
    # 3. Firewall Blocks (24h)
    blocked_events_24h = 0
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cutoff_24h = now - 86400
                cur = conn.execute("""
                    SELECT COUNT(*) FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                """, (cutoff_24h,))
                blocked_events_24h = cur.fetchone()[0] or 0
            finally:
                conn.close()
    except:
        blocked_events_24h = 0
    
    # 4. Anomalies (24h)
    anomalies_24h = 0
    try:
        output_24h = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto"], tf_24h)
        if output_24h:
            lines_24h = output_24h.strip().split("\n")
            start_idx_24h = 0
            sa_idx_24h = 0
            da_idx_24h = 0
            ibyt_idx_24h = 0
            td_idx_24h = 0
            if lines_24h:
                line0_24h = lines_24h[0]
                if 'ts' in line0_24h or 'Date' in line0_24h or 'ibyt' in line0_24h or 'firstSeen' in line0_24h or 'firstseen' in line0_24h:
                    header_24h = line0_24h.split(',')
                    try:
                        sa_key_24h = 'sa' if 'sa' in header_24h else 'srcAddr'
                        if 'srcaddr' in header_24h: sa_key_24h = 'srcaddr'
                        da_key_24h = 'da' if 'da' in header_24h else 'dstAddr'
                        if 'dstaddr' in header_24h: da_key_24h = 'dstaddr'
                        ibyt_key_24h = 'ibyt' if 'ibyt' in header_24h else 'bytes'
                        if sa_key_24h in header_24h: sa_idx_24h = header_24h.index(sa_key_24h)
                        if da_key_24h in header_24h: da_idx_24h = header_24h.index(da_key_24h)
                        if ibyt_key_24h in header_24h: ibyt_idx_24h = header_24h.index(ibyt_key_24h)
                        if 'td' in header_24h: td_idx_24h = header_24h.index('td')
                        elif 'duration' in header_24h: td_idx_24h = header_24h.index('duration')
                        start_idx_24h = 1
                    except:
                        pass
            for line in lines_24h[start_idx_24h:]:
                if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
                parts = line.split(',')
                if len(parts) > 7:
                    try:
                        duration = float(parts[td_idx_24h]) if len(parts) > td_idx_24h and td_idx_24h < len(parts) else 0.0
                        src = parts[sa_idx_24h] if len(parts) > sa_idx_24h and sa_idx_24h < len(parts) else ""
                        dst = parts[da_idx_24h] if len(parts) > da_idx_24h and da_idx_24h < len(parts) else ""
                        b = int(parts[ibyt_idx_24h]) if len(parts) > ibyt_idx_24h and ibyt_idx_24h < len(parts) else 0
                        if src and dst:
                            src_internal = is_internal(src)
                            dst_internal = is_internal(dst)
                            is_external = not (src_internal and dst_internal)
                            if is_external and duration > LONG_LOW_DURATION_THRESHOLD and b < LONG_LOW_BYTES_THRESHOLD:
                                anomalies_24h += 1
                    except:
                        pass
    except:
        anomalies_24h = 0
    
    # Check baselines for each metric
    # Active Flows
    active_flows_check = is_abnormal('active_flows', active_flows)
    if active_flows_check and active_flows_check['abnormal']:
        signals.append('active_flows_spike')
        signal_details.append(f"active flows spike ({active_flows} vs baseline {active_flows_check['baseline_mean']:.0f})")
    
    # External Connections
    external_check = is_abnormal('external_connections', external_connections)
    if external_check and external_check['abnormal']:
        signals.append('external_connections_spike')
        signal_details.append(f"external connections spike ({external_connections} vs baseline {external_check['baseline_mean']:.0f})")
    
    # Firewall Blocks Rate
    blocks_rate = blocked_events_24h / 24.0 if blocked_events_24h > 0 else 0.0
    blocks_check = is_abnormal('firewall_blocks_rate', blocks_rate)
    if blocks_check and blocks_check['abnormal']:
        signals.append('firewall_blocks_spike')
        signal_details.append(f"firewall blocks spike ({blocked_events_24h} in 24h, {blocks_rate:.1f}/hr vs baseline {blocks_check['baseline_mean']:.1f}/hr)")
    
    # Anomalies Rate
    anomalies_rate = anomalies_24h / 24.0 if anomalies_24h > 0 else 0.0
    anomalies_check = is_abnormal('anomalies_rate', anomalies_rate)
    if anomalies_check and anomalies_check['abnormal']:
        signals.append('anomalies_spike')
        signal_details.append(f"network anomalies spike ({anomalies_24h} in 24h, {anomalies_rate:.1f}/hr vs baseline {anomalies_check['baseline_mean']:.1f}/hr)")
    
    # Also check if anomalies exist at all (even if not spiking)
    if anomalies_24h > 0:
        signals.append('anomalies_present')
        signal_details.append(f"{anomalies_24h} network anomal{'ies' if anomalies_24h > 1 else 'y'}")
    
    return jsonify({
        "signals": signals,
        "signal_details": signal_details,
        "metrics": {
            "active_flows": active_flows,
            "external_connections": external_connections,
            "blocked_events_24h": blocked_events_24h,
            "anomalies_24h": anomalies_24h
        },
        "baselines_available": {
            "active_flows": get_baseline_stats('active_flows') is not None,
            "external_connections": get_baseline_stats('external_connections') is not None,
            "firewall_blocks_rate": get_baseline_stats('firewall_blocks_rate') is not None,
            "anomalies_rate": get_baseline_stats('anomalies_rate') is not None,
        }
    })


@bp.route("/api/flows")
@throttle(10,30)
def api_flows():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except:
        limit = 10

    cache_key_local = f"{range_key}:{limit}"
    now = time.time()
    win = int(now // 60)
    with _lock_flows:
        if _flows_cache.get("data") and _flows_cache.get("key") == cache_key_local and _flows_cache.get("win") == win:
            global _metric_flow_cache_hits
            _metric_flow_cache_hits += 1
            return jsonify(_flows_cache["data"])
    tf = get_time_range(range_key)

    # Load threat list for correlation (Phase 1: Flow ↔ Threat correlation)
    threat_set = load_threatlist()
    whitelist = load_list(THREAT_WHITELIST)
    threat_set = threat_set - whitelist  # Exclude whitelisted IPs

    # Fetch raw flows to get actual flow partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' flows
    # If limit > 100, we might need more data.
    # Fetch raw flows to get actual flow partners
    # Use -O bytes to sort by bytes descending at nfdump level to get 'Top' flows
    # If limit > 100, we might need more data.
    fetch_limit = str(max(100, limit))
    # Aggregate by 5-tuple to merge duplicate/fragmented flows
    output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", fetch_limit], tf)

    convs = []
    # NFDump CSV indices defaults
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8

    # Lightweight heuristics tracking (per-request only, no persistent state)
    port_counts = defaultdict(int)  # Track destination port frequency
    external_ips_seen = set()  # Track external IPs seen in this batch
    connection_patterns = defaultdict(int)  # Track src->dst patterns for repeated connections

    try:
        lines = output.strip().split("\n")
        start_idx = 0
        if lines:
            line0 = lines[0]
            if 'ts' in line0 or 'Date' in line0 or 'ibyt' in line0 or 'firstSeen' in line0 or 'firstseen' in line0:
                header = line0.split(',')
                try:
                    # check for common variances
                    sa_key = 'sa' if 'sa' in header else 'srcAddr'
                    if 'srcaddr' in header: sa_key = 'srcaddr'
                    da_key = 'da' if 'da' in header else 'dstAddr'
                    if 'dstaddr' in header: da_key = 'dstaddr'
                    ibyt_key = 'ibyt' if 'ibyt' in header else 'bytes'

                    if sa_key in header: sa_idx = header.index(sa_key)
                    if da_key in header: da_idx = header.index(da_key)
                    if ibyt_key in header: ibyt_idx = header.index(ibyt_key)

                    # Try to map others if present
                    if 'ts' in header: ts_idx = header.index('ts')
                    if 'firstSeen' in header: ts_idx = header.index('firstSeen')
                    if 'firstseen' in header: ts_idx = header.index('firstseen')
                    if 'td' in header: td_idx = header.index('td')
                    if 'duration' in header: td_idx = header.index('duration')
                    if 'pr' in header: pr_idx = header.index('pr')
                    if 'proto' in header: pr_idx = header.index('proto')
                    if 'sp' in header: sp_idx = header.index('sp')
                    if 'srcPort' in header: sp_idx = header.index('srcPort')
                    if 'srcport' in header: sp_idx = header.index('srcport')
                    if 'dp' in header: dp_idx = header.index('dp')
                    if 'dstPort' in header: dp_idx = header.index('dstPort')
                    if 'dstport' in header: dp_idx = header.index('dstport')
                    if 'ipkt' in header: ipkt_idx = header.index('ipkt')
                    if 'packets' in header: ipkt_idx = header.index('packets')
                    start_idx = 1
                except:
                    pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstSeen,') or line.startswith('Date,'): continue
            parts = line.split(',')
            if len(parts) > 7:
                try:
                    ts_str = parts[ts_idx] if len(parts) > ts_idx else ""
                    duration = float(parts[td_idx]) if len(parts) > td_idx else 0.0
                    proto_val = parts[pr_idx] if len(parts) > pr_idx else "0"
                    src = parts[sa_idx]
                    src_port = parts[sp_idx] if len(parts) > sp_idx else "0"
                    dst = parts[da_idx]
                    dst_port = parts[dp_idx] if len(parts) > dp_idx else "0"
                    pkts = int(parts[ipkt_idx]) if len(parts) > ipkt_idx else 0
                    b = int(parts[ibyt_idx])

                    # Calculate Age
                    try:
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except:
                        age_sec = 0

                    if age_sec < 0: age_sec = 0

                    # Enrich with Geo
                    src_geo = lookup_geo(src) or {}
                    dst_geo = lookup_geo(dst) or {}

                    # Resolve hostnames (cached only, non-blocking)
                    src_hostname = resolve_ip(src) or None
                    dst_hostname = resolve_ip(dst) or None

                    # Determine internal/external classification
                    src_internal = is_internal(src)
                    dst_internal = is_internal(dst)
                    
                    # Determine flow direction
                    if src_internal and not dst_internal:
                        direction = "outbound"
                    elif not src_internal and dst_internal:
                        direction = "inbound"
                    elif src_internal and dst_internal:
                        direction = "internal"
                    else:
                        direction = "external"

                    # Resolve Service Name
                    try:
                        svc = socket.getservbyport(int(dst_port), 'tcp' if '6' in proto_val else 'udp')
                    except:
                        svc = dst_port

                    # Track for heuristics (lightweight, per-request only) - do this first
                    port_counts[dst_port] += 1
                    connection_key = f"{src}:{dst}"
                    connection_patterns[connection_key] += 1
                    
                    # Detect interesting flow characteristics (heuristics only, not alerts)
                    interesting_flags = []
                    
                    # 1. Long-lived low-volume flows
                    if duration > 300 and b < 100000:
                        interesting_flags.append("long_low")
                    
                    # 2. Short-lived high-volume flows
                    if duration < 10 and b > 500000:
                        interesting_flags.append("short_high")
                    
                    # 3. Rare destination ports (appears <= 2 times in this batch)
                    # Note: This is approximate since we're checking during processing
                    # A port appearing 1-2 times in a batch of 100+ flows is considered rare
                    if port_counts[dst_port] <= 2:
                        interesting_flags.append("rare_port")
                    
                    # 4. New external IPs (first time seeing this external IP in this batch)
                    is_new_external_dst = not dst_internal and dst not in external_ips_seen
                    is_new_external_src = not src_internal and src not in external_ips_seen
                    if is_new_external_dst:
                        external_ips_seen.add(dst)
                        interesting_flags.append("new_external")
                    elif is_new_external_src:
                        external_ips_seen.add(src)
                        interesting_flags.append("new_external")
                    
                    # 5. Repeated short connections (same src->dst with multiple short connections)
                    if connection_patterns[connection_key] > 1 and duration < 30:
                        interesting_flags.append("repeated_short")

                    # Phase 1: Flow ↔ Threat correlation
                    threat_ips = []
                    if src in threat_set:
                        threat_ips.append(src)
                    if dst in threat_set:
                        threat_ips.append(dst)
                    
                    has_threat = len(threat_ips) > 0
                    threat_count = len(threat_ips)
                    
                    # Get threat info for threat IPs (lightweight, only if threats found)
                    threat_info_list = []
                    if has_threat:
                        for threat_ip in threat_ips:
                            info = get_threat_info(threat_ip)
                            threat_info_list.append({
                                "ip": threat_ip,
                                "category": info.get('category', 'UNKNOWN'),
                                "feed": info.get('feed', 'unknown')
                            })

                    # Phase 2: Promote long-lived low-volume external flows to detection
                    # Detection criteria: duration > threshold AND bytes < threshold AND external (not internal)
                    is_detected = False
                    detection_reason = None
                    if direction in ("outbound", "inbound", "external"):  # External flow (not internal)
                        if duration > LONG_LOW_DURATION_THRESHOLD and b < LONG_LOW_BYTES_THRESHOLD:
                            is_detected = True
                            detection_reason = f"Long-lived ({duration:.1f}s) low-volume ({fmt_bytes(b)}) external flow. May indicate persistent C2, data exfiltration, or beaconing activity."

                    # Phase 3: Update rolling flow history (in-memory, 30-60 min)
                    history_key = (src, dst, dst_port)  # Aggregate by src/dst/port
                    flow_history = []
                    with _flow_history_lock:
                        if history_key not in _flow_history:
                            _flow_history[history_key] = []
                        _flow_history[history_key].append({
                            "ts": flow_time,
                            "bytes": b,
                            "packets": pkts,
                            "duration": duration
                        })
                        # Cleanup old entries (older than TTL)
                        cutoff_ts = now - _flow_history_ttl
                        _flow_history[history_key] = [
                            entry for entry in _flow_history[history_key]
                            if entry["ts"] >= cutoff_ts
                        ]
                        # Get history for this flow (for UI) - only if more than 1 entry (recurring pattern)
                        history_entries = sorted(_flow_history.get(history_key, []), key=lambda x: x["ts"])
                        if len(history_entries) > 1:
                            flow_history = history_entries
                        # Remove empty keys
                        if not _flow_history[history_key]:
                            del _flow_history[history_key]

                    convs.append({
                        "ts": ts_str,
                        "age_seconds": age_sec,  # Explicit age in seconds for reliable frontend calculation
                        "first_seen_ts": flow_time,  # Unix timestamp for age calculation fallback
                        "age": format_duration(age_sec) + " ago" if age_sec < 86400 else ts_str,
                        "duration": f"{duration:.2f}s",
                        "duration_seconds": duration,  # Raw duration in seconds
                        "proto": proto_val,
                        "proto_name": { "6": "TCP", "17": "UDP", "1": "ICMP" }.get(proto_val, proto_val),
                        "src": src,
                        "src_port": src_port,
                        "src_hostname": src_hostname,  # Cached hostname if available
                        "src_internal": src_internal,  # Internal/external flag
                        "src_flag": src_geo.get('flag', ''),
                        "src_country": src_geo.get('country', ''),
                        "dst": dst,
                        "dst_port": dst_port,
                        "dst_hostname": dst_hostname,  # Cached hostname if available
                        "dst_internal": dst_internal,  # Internal/external flag
                        "dst_flag": dst_geo.get('flag', ''),
                        "dst_country": dst_geo.get('country', ''),
                        "direction": direction,  # Flow direction: inbound, outbound, internal, external
                        "service": svc,
                        "bytes": b,
                        "bytes_fmt": fmt_bytes(b),
                        "packets": pkts,
                        "interesting_flags": interesting_flags[:2],  # Max 2 flags
                        # Phase 1: Threat correlation fields
                        "has_threat": has_threat,
                        "threat_count": threat_count,
                        "threat_ips": threat_ips,
                        "threat_info": threat_info_list,
                        # Phase 2: Detection fields
                        "is_detected": is_detected,
                        "detection_reason": detection_reason,
                        # Phase 3: Flow history (last 30-60 min, aggregated by src/dst/port)
                        "history": flow_history  # Only included if there's recurring pattern (len > 1)
                    })
                except:
                    pass


    except:
        pass  # Parsing error
    data = {"flows":convs, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    with _lock_flows:
        _flows_cache["data"] = data
        _flows_cache["ts"] = now
        _flows_cache["key"] = cache_key_local
        _flows_cache["win"] = win
    return jsonify(data)


@bp.route("/api/ip_detail/<ip>")
@throttle(5,10)
def api_ip_detail(ip):
    """Get detailed information about an IP address including traffic patterns, ports, protocols, and geo data."""
    start_threat_thread()

    # Support range parameter (default to 1h for backwards compatibility)
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    dt = datetime.now()
    start_dt = dt - timedelta(seconds=range_seconds)
    tf = f"{start_dt.strftime('%Y/%m/%d.%H:%M:%S')}-{dt.strftime('%Y/%m/%d.%H:%M:%S')}"

    try:
        direction = get_traffic_direction(ip, tf)
        src_ports = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","10","-a",f"src ip {ip}"], tf), expected_key='dp')
        dst_ports = parse_csv(run_nfdump(["-s","srcport/bytes/flows","-n","10","-a",f"dst ip {ip}"], tf), expected_key='sp')
        protocols = parse_csv(run_nfdump(["-s","proto/bytes/packets","-n","5","-a",f"ip {ip}"], tf), expected_key='proto')
    except Exception as e:
        # If nfdump fails, return partial data
        direction = {"upload": 0, "download": 0}
        src_ports = []
        dst_ports = []
        protocols = []
        print(f"Warning: nfdump query failed for IP {ip}: {e}")

    # Enrich
    for p in protocols:
        try:
            proto = int(p["key"]); p["proto_name"] = PROTOS.get(proto, f"Proto-{p['key']}")
        except Exception:
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
        if len(lines) > 1:
            header = lines[0].split(',')
            try:
                sa_idx = header.index('sa')
                da_idx = header.index('da')
                ibyt_idx = header.index('ibyt')
            except ValueError:
                sa_idx, da_idx, ibyt_idx = 3, 4, 12

            # Track IPs that communicate with this IP
            related_ip_stats = defaultdict(lambda: {'bytes': 0, 'count': 0, 'type': ''})

            for line in lines[1:]:
                if not line or line.startswith('ts,'): continue
                parts = line.split(',')
                if len(parts) > max(sa_idx, da_idx, ibyt_idx):
                    try:
                        src = parts[sa_idx].strip()
                        dst = parts[da_idx].strip()
                        bytes_val = int(parts[ibyt_idx]) if len(parts) > ibyt_idx and parts[ibyt_idx].strip().isdigit() else 0

                        if src == ip and dst != ip:
                            # This IP is source - track destination as related
                            related_ip_stats[dst]['bytes'] += bytes_val
                            related_ip_stats[dst]['count'] += 1
                            related_ip_stats[dst]['type'] = 'destination'
                        elif dst == ip and src != ip:
                            # This IP is destination - track source as related
                            related_ip_stats[src]['bytes'] += bytes_val
                            related_ip_stats[src]['count'] += 1
                            related_ip_stats[src]['type'] = 'source'
                    except (ValueError, IndexError):
                        pass

            # Get top related IPs (limit to 10)
            related_ips = sorted([{'ip': ip_addr, 'bytes': data['bytes'], 'count': data['count'], 'type': data['type']}
                                for ip_addr, data in related_ip_stats.items()],
                               key=lambda x: x['bytes'], reverse=True)[:10]

            # Enrich related IPs with geo data
            for r_ip in related_ips:
                r_geo = lookup_geo(r_ip['ip'])
                r_ip['country'] = r_geo.get('country', 'Unknown') if r_geo else 'Unknown'
                r_ip['country_code'] = r_geo.get('country_code', '') if r_geo else ''
    except Exception as e:
        print(f"Warning: Related IPs discovery failed for IP {ip}: {e}")

    data = {
        "ip": ip,
        "hostname": resolve_ip(ip),
        "region": get_region(ip, geo.get('country_iso') if geo else None),
        "internal": is_internal(ip),
        "geo": geo,
        "direction": direction,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "protocols": protocols,
        "threat": False,
        "related_ips": related_ips,
        "threat_intel": threat_intel,
        "anomalies": anomalies
    }
    return jsonify(data)



@bp.route("/api/trends/source/<ip>")
def api_trends_source(ip):
    """Return 5-min rollup trend for a source IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
    compare = request.args.get('compare', 'false').lower() == 'true'  # Historical comparison
    now = datetime.now()
    minutes = {'15m': 15, '30m': 30, '1h': 60, '6h': 360, '24h': 1440}.get(range_key, 1440)
    end_dt = _get_bucket_end(now)
    start_dt = end_dt - timedelta(minutes=minutes)
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT bucket_end, bytes, flows FROM top_sources WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                (ip, start_ts, end_ts)
            )
            rows = cur.fetchall()

            # Historical comparison: get same duration from previous period
            comparison = None
            if compare and rows:
                prev_end_dt = start_dt
                prev_start_dt = prev_end_dt - timedelta(minutes=minutes)
                prev_start_ts = int(prev_start_dt.timestamp())
                prev_end_ts = int(prev_end_dt.timestamp())

                prev_cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM top_sources WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (ip, prev_start_ts, prev_end_ts)
                )
                prev_rows = prev_cur.fetchall()
                if prev_rows:
                    comparison = {
                        "labels": [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in prev_rows],
                        "bytes": [r[1] for r in prev_rows],
                        "flows": [r[2] for r in prev_rows]
                    }
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    result = {"labels": labels, "bytes": bytes_arr, "flows": flows_arr}
    if comparison:
        result["comparison"] = comparison
    return jsonify(result)



@bp.route("/api/trends/dest/<ip>")
def api_trends_dest(ip):
    """Return 5-min rollup trend for a destination IP over the requested range (default 24h)."""
    range_key = request.args.get('range', '24h')
    compare = request.args.get('compare', 'false').lower() == 'true'  # Historical comparison
    now = datetime.now()
    minutes = {'15m': 15, '30m': 30, '1h': 60, '6h': 360, '24h': 1440}.get(range_key, 1440)
    end_dt = _get_bucket_end(now)
    start_dt = end_dt - timedelta(minutes=minutes)
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT bucket_end, bytes, flows FROM top_dests WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                (ip, start_ts, end_ts)
            )
            rows = cur.fetchall()

            # Historical comparison: get same duration from previous period
            comparison = None
            if compare and rows:
                prev_end_dt = start_dt
                prev_start_dt = prev_end_dt - timedelta(minutes=minutes)
                prev_start_ts = int(prev_start_dt.timestamp())
                prev_end_ts = int(prev_end_dt.timestamp())

                prev_cur = conn.execute(
                    "SELECT bucket_end, bytes, flows FROM top_dests WHERE ip=? AND bucket_end>=? AND bucket_end<=? ORDER BY bucket_end ASC",
                    (ip, prev_start_ts, prev_end_ts)
                )
                prev_rows = prev_cur.fetchall()
                if prev_rows:
                    comparison = {
                        "labels": [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in prev_rows],
                        "bytes": [r[1] for r in prev_rows],
                        "flows": [r[2] for r in prev_rows]
                    }
        finally:
            conn.close()
    labels = [datetime.fromtimestamp(r[0]).strftime('%H:%M') for r in rows]
    bytes_arr = [r[1] for r in rows]
    flows_arr = [r[2] for r in rows]
    result = {"labels": labels, "bytes": bytes_arr, "flows": flows_arr}
    if comparison:
        result["comparison"] = comparison
    return jsonify(result)


@bp.route("/api/export")
def export_csv():
    # Use Summary logic but return raw text
    range_key = request.args.get('range', '1h')
    tf = get_time_range(range_key)
    sources = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","20"], tf), expected_key='sa')
    csv = "IP,Bytes,Flows\n" + "\n".join([f"{s['key']},{s['bytes']},{s['flows']}" for s in sources])
    return csv, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=netflow_export.csv'}


@bp.route("/api/export_json")
def export_json():
    return api_stats_summary()


@bp.route("/api/test_alert")
def api_test_alert():
    alert = {"severity":"critical","msg":"TEST ALERT triggered from UI","feed":"local"}
    send_notifications([alert])
    return jsonify({"status":"ok","sent":True})


@bp.route('/api/threat_refresh', methods=['POST'])
def api_threat_refresh():
    fetch_threat_feed()
    return jsonify({"status":"ok","threat_status": threats_module._threat_status})



@bp.route('/api/ollama/chat', methods=['POST'])
@throttle(10, 60)  # 10 requests per minute
def api_ollama_chat():
    """Chat endpoint that proxies requests to local Ollama instance."""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        model = data.get('model', 'deepseek-coder-v2:16b')  # Default model, can be overridden
        stream = data.get('stream', False)

        if not message:
            return jsonify({"error": "Message is required"}), 400

        # Ollama API endpoint (default: 192.168.0.88:11434)
        ollama_base = os.getenv('OLLAMA_URL', 'http://192.168.0.88:11434')
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace('/api/chat', '')
        ollama_url = f"{ollama_base}/api/chat"

        # Prepare request to Ollama
        ollama_payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ],
            "stream": stream
        }

        # Make request to Ollama
        timeout = 120 if stream else 60  # Longer timeout for streaming
        response = requests.post(
            ollama_url,
            json=ollama_payload,
            timeout=timeout,
            stream=stream
        )

        if response.status_code != 200:
            return jsonify({
                "error": f"Ollama API error: {response.status_code}",
                "details": response.text[:200]
            }), response.status_code

        if stream:
            # For streaming, return Server-Sent Events
            def generate():
                for line in response.iter_lines():
                    if line:
                        yield f"data: {line.decode('utf-8')}\n\n"
                yield "data: [DONE]\n\n"

            return Response(
                generate(),
                mimetype='text/event-stream',
                headers={
                    'Cache-Control': 'no-cache',
                    'X-Accel-Buffering': 'no'
                }
            )
        else:
            # For non-streaming, return JSON response
            return jsonify(response.json())

    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": f"Cannot connect to Ollama at {ollama_url}. Make sure Ollama is running and accessible."
        }), 503
    except requests.exceptions.Timeout:
        return jsonify({
            "error": "Request to Ollama timed out"
        }), 504
    except Exception as e:
        print(f"Ollama chat error: {e}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)[:200]
        }), 500



@bp.route('/api/ollama/models', methods=['GET'])
@throttle(5, 60)
def api_ollama_models():
    """Get list of available Ollama models."""
    try:
        # Ollama API base URL (default: 192.168.0.88:11434)
        ollama_base = os.getenv('OLLAMA_URL', 'http://192.168.0.88:11434')
        # Remove /api/chat if present (for backwards compatibility)
        ollama_base = ollama_base.replace('/api/chat', '')
        response = requests.get(f"{ollama_base}/api/tags", timeout=10)

        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch models"}), response.status_code

        data = response.json()
        models = [model.get('name', '') for model in data.get('models', [])]
        return jsonify({"models": models})

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Cannot connect to Ollama", "models": []}), 503
    except Exception as e:
        print(f"Ollama models error: {e}")
        return jsonify({"error": str(e), "models": []}), 500



@bp.route('/api/stats/threats')
@throttle(5, 10)
def api_threats():
    """Get threat detections with category, geo info, and firewall block status"""
    range_key = request.args.get('range', '1h')
    range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
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
                cur = conn.execute("""
                    SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_blocked
                    FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                    GROUP BY src_ip
                """, (cutoff,))
                for row in cur.fetchall():
                    blocked_ips[row[0]] = {'count': row[1], 'last_blocked': row[2]}
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
            hits.append({
                "ip": ip,
                "category": info.get("category", "UNKNOWN"),
                "feed": info.get("feed", "unknown"),
                "bytes": item.get("bytes", 0),
                "bytes_fmt": fmt_bytes(item.get("bytes", 0)),
                "flows": item.get("flows", 0),
                "country": geo.get("country_code", "--"),
                "city": geo.get("city", ""),
                "hits": item.get("flows", 1),
                "blocked": block_info.get('count', 0) > 0,
                "block_count": block_info.get('count', 0),
                "last_blocked": datetime.fromtimestamp(block_info['last_blocked']).isoformat() if block_info.get('last_blocked') else None
            })

    # Sort by bytes descending
    hits.sort(key=lambda x: x["bytes"], reverse=True)

    # Summary stats
    total_blocked = sum(1 for h in hits if h['blocked'])

    return jsonify({
        "hits": hits[:20],
        "total_threats": len(hits),
        "total_blocked": total_blocked,
        "feed_ips": threats_module._threat_status.get("size", 0),
        "threat_status": threats_module._threat_status
    })



@bp.route('/api/stats/malicious_ports')
@throttle(5, 10)
def api_malicious_ports():
    """Get top malicious ports - combining threat traffic + firewall blocks"""
    range_key = request.args.get('range', '1h')

    # Suspicious ports to highlight
    SUSPICIOUS_PORTS = {
        22: 'SSH',
        23: 'Telnet',
        445: 'SMB',
        3389: 'RDP',
        5900: 'VNC',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        11211: 'Memcached',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        4444: 'Metasploit',
        5555: 'Android ADB',
        6666: 'IRC',
        31337: 'Back Orifice',
    }

    port_data = {}

    # Get blocked ports from firewall syslog
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            range_seconds = {'15m': 900, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
            cutoff = int(time.time()) - range_seconds

            # Get blocked ports with counts
            cur.execute("""
                SELECT dst_port, COUNT(*) as hits, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND dst_port > 0
                GROUP BY dst_port
                ORDER BY hits DESC
                LIMIT 50
            """, (cutoff,))

            for row in cur.fetchall():
                port = row['dst_port']
                service = SUSPICIOUS_PORTS.get(port, 'Unknown')
                port_data[port] = {
                    'port': port,
                    'service': service,
                    'blocked': row['hits'],
                    'unique_attackers': row['unique_ips'],
                    'netflow_bytes': 0,
                    'netflow_flows': 0,
                    'suspicious': port in SUSPICIOUS_PORTS
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
            blocked_ports = sorted(port_data.keys(), key=lambda p: port_data[p]['blocked'], reverse=True)[:20]

            if blocked_ports:
                # Query NetFlow for traffic on these ports from ANY source (not just blocked)
                # Blocked traffic won't appear in NetFlow, but we can show traffic that did get through
                # Use the same approach as regular ports endpoint for consistency
                try:
                    # Get all port stats and filter for our blocked ports
                    from app.services.netflow import get_common_nfdump_data
                    all_ports_data = get_common_nfdump_data("ports", range_key)
                    
                    # Match ports and update traffic data
                    for port_item in all_ports_data:
                        try:
                            port_num = int(port_item.get('key', 0))
                            if port_num in port_data:
                                port_data[port_num]['netflow_bytes'] = int(port_item.get('bytes', 0))
                                port_data[port_num]['netflow_flows'] = int(port_item.get('flows', 0))
                        except (ValueError, KeyError):
                            continue
                except Exception as e:
                    # Log but continue - syslog data is still valuable
                    print(f"Warning: NetFlow query for port traffic failed: {e}")
                    pass

        # Also try to get data from threat IPs (if threat list exists)
        threat_set = load_threatlist()
        if threat_set:
            # Get top threat IPs by bytes (limit to top 10 to prevent timeout)
            output = run_nfdump(["-o", "csv", "-n", "30", "-s", "ip/bytes"], tf)

            lines = output.strip().split('\n')
            if len(lines) > 1:
                header = [c.strip().lower() for c in lines[0].split(',')]
                ip_idx = next((i for i, h in enumerate(header) if 'ip' in h and 'addr' in h), None)
                byt_idx = next((i for i, h in enumerate(header) if h in ('ibyt', 'bytes')), None)

                if ip_idx is not None:
                    # Collect top threat IPs (limit to 10 to prevent timeout)
                    threat_ips = []
                    for line in lines[1:11]:  # Limit to top 10 threat IPs
                        parts = line.split(',')
                        if len(parts) > max(ip_idx, byt_idx or 0):
                            ip = parts[ip_idx].strip()
                            if ip in threat_set:
                                try:
                                    bytes_val = int(parts[byt_idx].strip()) if byt_idx else 0
                                    threat_ips.append((ip, bytes_val))
                                except (ValueError, IndexError):
                                    pass

                    # Process threat IPs (limit to 5 to prevent timeout)
                    for ip, _ in threat_ips[:5]:
                        try:
                            port_output = run_nfdump(["-o", "csv", "-n", "3", "-s", "port/bytes", f"src ip {ip} or dst ip {ip}"], tf)
                            port_lines = port_output.strip().split('\n')

                            if len(port_lines) > 1:
                                p_header = [c.strip().lower() for c in port_lines[0].split(',')]
                                p_idx = next((i for i, h in enumerate(p_header) if h == 'port'), None)
                                p_byt_idx = next((i for i, h in enumerate(p_header) if h in ('ibyt', 'bytes')), None)
                                p_fl_idx = next((i for i, h in enumerate(p_header) if h in ('fl', 'flows')), None)

                                if p_idx is not None:
                                    for pline in port_lines[1:]:
                                        pparts = pline.split(',')
                                        try:
                                            if len(pparts) > max(p_idx, p_byt_idx or 0, p_fl_idx or 0):
                                                port = int(pparts[p_idx].strip())
                                                bytes_val = int(pparts[p_byt_idx].strip()) if p_byt_idx else 0
                                                flows_val = int(pparts[p_fl_idx].strip()) if p_fl_idx else 0

                                                if port not in port_data:
                                                    port_data[port] = {
                                                        'port': port,
                                                        'service': SUSPICIOUS_PORTS.get(port, 'Unknown'),
                                                        'blocked': 0,
                                                        'unique_attackers': 0,
                                                        'netflow_bytes': 0,
                                                        'netflow_flows': 0,
                                                        'suspicious': port in SUSPICIOUS_PORTS
                                                    }
                                                port_data[port]['netflow_bytes'] += bytes_val
                                                port_data[port]['netflow_flows'] += flows_val
                                        except (ValueError, IndexError):
                                            pass
                        except Exception as e:
                            # Continue with next IP if this one fails
                            continue
    except Exception as e:
        # Log error but don't fail completely - return what we have from syslog
        print(f"Warning: Failed to fetch threat port data: {e}")
        pass

    # Common port to service name mapping (fallback if socket.getservbyport fails)
    COMMON_PORTS = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        27017: 'MongoDB', 11211: 'Memcached', 1900: 'UPnP', 6881: 'BitTorrent',
        4444: 'Metasploit', 5555: 'Android ADB', 6666: 'IRC', 6667: 'IRC', 31337: 'Back Orifice'
    }

    # Update service names for all ports using socket.getservbyport when possible
    import socket
    for port in port_data:
        if port_data[port]['service'] == 'Unknown':
            service_name = None
            # Try TCP first (most common)
            try:
                service_name = socket.getservbyport(port, 'tcp')
            except (OSError, socket.error):
                # Try UDP
                try:
                    service_name = socket.getservbyport(port, 'udp')
                except (OSError, socket.error):
                    pass

            # Fallback to common ports dict or generic name
            if not service_name:
                service_name = COMMON_PORTS.get(port, f'Port {port}')

            port_data[port]['service'] = service_name

    # Convert to list and sort by total activity (blocked + flows)
    ports = list(port_data.values())
    for p in ports:
        p['total_score'] = p['blocked'] * 10 + p['netflow_flows']  # Weight blocks higher
        # Ensure netflow_bytes and netflow_flows are integers
        p['netflow_bytes'] = int(p.get('netflow_bytes', 0))
        p['netflow_flows'] = int(p.get('netflow_flows', 0))
        # Set bytes_fmt only if there's actual data
        p['bytes_fmt'] = fmt_bytes(p['netflow_bytes']) if p['netflow_bytes'] > 0 else None

    ports.sort(key=lambda x: x['total_score'], reverse=True)

    return jsonify({
        "ports": ports[:15],  # Limit to top 15 (for scrollable view)
        "total": len(ports),
        "has_syslog": any(p['blocked'] > 0 for p in ports)
    })



@bp.route('/api/stats/feeds')
@throttle(5, 10)
def api_feed_status():
    """Get per-feed health status"""
    feeds = []
    for name, info in threats_module._feed_status.items():
        last_ok = info.get('last_ok', 0)
        feeds.append({
            "name": name,
            "category": info.get("category", "UNKNOWN"),
            "status": info.get("status", "unknown"),
            "ips": info.get("ips", 0),
            "latency_ms": info.get("latency_ms", 0),
            "error": info.get("error"),
            "last_ok_ago": format_time_ago(last_ok) if last_ok else "never"
        })

    # Sort by status (ok first), then by ips
    feeds.sort(key=lambda x: (0 if x["status"] == "ok" else 1, -x["ips"]))

    return jsonify({
        "feeds": feeds,
        "summary": {
            "total": len(feeds),
            "ok": sum(1 for f in feeds if f["status"] == "ok"),
            "error": sum(1 for f in feeds if f["status"] == "error"),
            "total_ips": threats_module._threat_status.get("size", 0),
            "last_refresh": format_time_ago(threats_module._threat_status.get("last_ok", 0)) if threats_module._threat_status.get("last_ok") else "never"
        }
    })



@bp.route('/api/security/score')
@throttle(5, 10)
def api_security_score():
    """Get current security score"""
    return jsonify(calculate_security_score())



@bp.route('/api/security/alerts/history')
@throttle(5, 10)
def api_alert_history():
    """Get alert history for past 24 hours"""
    now = time.time()
    cutoff = now - 86400  # 24 hours

    with threats_module._alert_history_lock:
        recent = [a for a in threats_module._alert_history if a.get('ts', 0) > cutoff]

    # Sort by timestamp descending
    recent.sort(key=lambda x: x.get('ts', 0), reverse=True)

    # Format timestamps
    for alert in recent:
        ts = alert.get('ts', 0)
        alert['time_ago'] = format_time_ago(ts)
        alert['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))

    # Group by hour for chart
    hourly = defaultdict(int)
    for alert in recent:
        hour = time.strftime('%H:00', time.localtime(alert.get('ts', 0)))
        hourly[hour] += 1

    return jsonify({
        'alerts': recent[:100],
        'total': len(recent),
        'by_severity': {
            'critical': sum(1 for a in recent if a.get('severity') == 'critical'),
            'high': sum(1 for a in recent if a.get('severity') == 'high'),
            'medium': sum(1 for a in recent if a.get('severity') == 'medium'),
            'low': sum(1 for a in recent if a.get('severity') == 'low'),
        },
        'hourly': dict(hourly)
    })



@bp.route('/api/security/threats/export')
def api_export_threats():
    """Export detected threats as JSON or CSV"""
    fmt = request.args.get('format', 'json')

    # Get recent threats
    now = time.time()
    threats = []
    for ip, timeline in threats_module._threat_timeline.items():
        if now - timeline['last_seen'] < 86400:  # Last 24h
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            threats.append({
                'ip': ip,
                'category': info.get('category', 'UNKNOWN'),
                'feed': info.get('feed', 'unknown'),
                'mitre_technique': info.get('mitre_technique', ''),
                'mitre_tactic': info.get('mitre_tactic', ''),
                'country': geo.get('country_code', '--'),
                'city': geo.get('city', ''),
                'first_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timeline['first_seen'])),
                'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timeline['last_seen'])),
                'hit_count': timeline['hit_count']
            })

    if fmt == 'csv':
        import io
        import csv
        output = io.StringIO()
        if threats:
            writer = csv.DictWriter(output, fieldnames=threats[0].keys())
            writer.writeheader()
            writer.writerows(threats)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=threats.csv'}
        )

    return jsonify({
        'threats': threats,
        'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total': len(threats)
    })



@bp.route('/api/security/attack-timeline')
@throttle(5, 10)
def api_attack_timeline():
    """Get attack timeline data for visualization with configurable time range."""
    range_key = request.args.get('range', '24h')
    range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 86400)
    now = time.time()
    cutoff = now - range_seconds

    with threats_module._alert_history_lock:
        recent = [a for a in threats_module._alert_history if a.get('ts', 0) > cutoff]

    # Determine bucket size based on range
    if range_key == '1h':
        bucket_size = 300  # 5-minute buckets for 1 hour (12 buckets)
        bucket_label_format = '%H:%M'
    elif range_key == '6h':
        bucket_size = 1800  # 30-minute buckets for 6 hours (12 buckets)
        bucket_label_format = '%H:%M'
    elif range_key == '24h':
        bucket_size = 3600  # 1-hour buckets for 24 hours (24 buckets)
        bucket_label_format = '%H:00'
    elif range_key == '7d':
        bucket_size = 86400  # 1-day buckets for 7 days (7 buckets)
        bucket_label_format = '%m/%d'
    else:
        bucket_size = 3600
        bucket_label_format = '%H:00'

    num_buckets = int(range_seconds / bucket_size)

    # Get firewall block counts from syslog (if available)
    fw_buckets = {}
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff_int = int(cutoff)

            if range_key == '7d':
                # Daily buckets for 7 days
                cur.execute("""
                    SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as day,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY day
                """, (cutoff_int,))
                for row in cur.fetchall():
                    day_str = time.strftime('%m/%d', time.strptime(row[0], '%Y-%m-%d'))
                    fw_buckets[day_str] = {'blocks': row[1], 'threat_blocks': row[2] or 0}
            elif range_key == '24h':
                # Hourly buckets for 24h
                cur.execute("""
                    SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) as hour,
                           COUNT(*) as blocks,
                           SUM(is_threat) as threat_blocks
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                    GROUP BY hour
                """, (cutoff_int,))
                for row in cur.fetchall():
                    fw_buckets[row[0] + ':00'] = {'blocks': row[1], 'threat_blocks': row[2] or 0}
            else:
                # For 1h and 6h, fetch all blocks and group by bucket
                cur.execute("""
                    SELECT timestamp, is_threat
                    FROM fw_logs
                    WHERE action = 'block' AND timestamp >= ?
                """, (cutoff_int,))
                for row in cur.fetchall():
                    bucket_start = int(row[0] / bucket_size) * bucket_size
                    bucket_label = time.strftime(bucket_label_format, time.localtime(bucket_start))
                    if bucket_label not in fw_buckets:
                        fw_buckets[bucket_label] = {'blocks': 0, 'threat_blocks': 0}
                    fw_buckets[bucket_label]['blocks'] += 1
                    if row[1]:
                        fw_buckets[bucket_label]['threat_blocks'] += 1
            conn.close()
    except Exception:
        pass

    # Build timeline buckets
    timeline = []
    for i in range(num_buckets):
        bucket_start = now - ((num_buckets - 1 - i) * bucket_size)
        bucket_end = bucket_start + bucket_size
        bucket_label = time.strftime(bucket_label_format, time.localtime(bucket_start))

        # Filter alerts for this bucket
        bucket_alerts = [a for a in recent if bucket_start <= a.get('ts', 0) < bucket_end]

        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for a in bucket_alerts:
            by_type[a.get('type', 'unknown')] += 1
            by_severity[a.get('severity', 'low')] += 1

        # Add firewall block data
        fw_data = fw_buckets.get(bucket_label, {'blocks': 0, 'threat_blocks': 0})

        timeline.append({
            'hour': bucket_label,  # Keep 'hour' key for compatibility, but contains appropriate label
            'timestamp': bucket_start,
            'total': len(bucket_alerts),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0),
            'fw_blocks': fw_data['blocks'],
            'fw_threat_blocks': fw_data['threat_blocks']
        })

    # Peak bucket
    peak = max(timeline, key=lambda x: x['total']) if timeline else None
    total_fw_blocks = sum(t['fw_blocks'] for t in timeline)

    return jsonify({
        'timeline': timeline,
        'total_24h': len(recent),  # Keep key for compatibility, but contains data for selected range
        'peak_hour': peak['hour'] if peak else None,
        'peak_count': peak['total'] if peak else 0,
        'fw_blocks_24h': total_fw_blocks,
        'has_fw_data': total_fw_blocks > 0
    })



@bp.route('/api/security/mitre-heatmap')
@throttle(5, 10)
def api_mitre_heatmap():
    """Get MITRE ATT&CK technique coverage from alerts."""
    now = time.time()
    cutoff = now - 86400  # 24 hours

    with threats_module._alert_history_lock:
        recent = [a for a in threats_module._alert_history if a.get('ts', 0) > cutoff]

    # Count by MITRE technique
    techniques = defaultdict(lambda: {'count': 0, 'alerts': [], 'tactic': '', 'name': ''})

    for alert in recent:
        mitre = alert.get('mitre', '')
        if mitre:
            techniques[mitre]['count'] += 1
            if len(techniques[mitre]['alerts']) < 5:
                techniques[mitre]['alerts'].append({
                    'type': alert.get('type'),
                    'msg': alert.get('msg', '')[:50],
                    'severity': alert.get('severity')
                })

    # Enrich with MITRE info
    mitre_info = {
        'T1046': {'tactic': 'Discovery', 'name': 'Network Service Discovery'},
        'T1110': {'tactic': 'Credential Access', 'name': 'Brute Force'},
        'T1041': {'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
        'T1071': {'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
        'T1071.004': {'tactic': 'Command and Control', 'name': 'DNS'},
        'T1021': {'tactic': 'Lateral Movement', 'name': 'Remote Services'},
        'T1095': {'tactic': 'Command and Control', 'name': 'Non-Application Layer Protocol'},
        'T1029': {'tactic': 'Exfiltration', 'name': 'Scheduled Transfer'},
        'T1190': {'tactic': 'Initial Access', 'name': 'Exploit Public-Facing Application'},
        'T1105': {'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
        'T1595': {'tactic': 'Reconnaissance', 'name': 'Active Scanning'},
        'T1090': {'tactic': 'Command and Control', 'name': 'Proxy'},
        'T1584': {'tactic': 'Resource Development', 'name': 'Compromise Infrastructure'},
        'T1583': {'tactic': 'Resource Development', 'name': 'Acquire Infrastructure'},
    }

    heatmap = []
    for tech_id, data in techniques.items():
        info = mitre_info.get(tech_id, {'tactic': 'Unknown', 'name': tech_id})
        heatmap.append({
            'technique': tech_id,
            'tactic': info['tactic'],
            'name': info['name'],
            'count': data['count'],
            'alerts': data['alerts']
        })

    # Sort by count descending
    heatmap.sort(key=lambda x: x['count'], reverse=True)

    # Group by tactic for visualization
    by_tactic = defaultdict(list)
    for item in heatmap:
        by_tactic[item['tactic']].append(item)

    return jsonify({
        'techniques': heatmap,
        'by_tactic': dict(by_tactic),
        'total_techniques': len(heatmap),
        'total_detections': sum(t['count'] for t in heatmap)
    })



@bp.route('/api/security/protocol-anomalies')
@throttle(5, 10)
def api_protocol_anomalies():
    """Get protocol anomaly data for Security Center."""

    range_key = request.args.get('range', '1h')
    protocols_data = get_common_nfdump_data("protocols", range_key)[:20]

    anomalies = []
    for proto in protocols_data:
        proto_name = proto.get('key') or proto.get('proto')
        proto_bytes = proto.get('bytes', 0)

        baseline = threats_module._protocol_baseline.get(proto_name, {})
        avg = baseline.get('total_bytes', proto_bytes) / max(baseline.get('samples', 1), 1)

        deviation = (proto_bytes / avg) if avg > 0 else 1

        anomalies.append({
            'protocol': proto_name,
            'bytes': proto_bytes,
            'bytes_fmt': fmt_bytes(proto_bytes),
            'avg_bytes': avg,
            'avg_fmt': fmt_bytes(avg),
            'deviation': round(deviation, 2),
            'is_anomaly': deviation > 2.0 and proto_bytes > 5 * 1024 * 1024,  # 2x+ and 5MB+
            'flows': proto.get('flows', 0)
        })

    # Sort anomalies first, then by deviation
    anomalies.sort(key=lambda x: (not x['is_anomaly'], -x['deviation']))

    return jsonify({
        'protocols': anomalies,
        'anomaly_count': sum(1 for a in anomalies if a['is_anomaly']),
        'baseline_samples': sum(b.get('samples', 0) for b in threats_module._protocol_baseline.values())
    })



@bp.route('/api/security/run-detection')
@throttle(2, 10)
def api_run_detection():
    """Manually trigger all detection algorithms."""
    range_key = request.args.get('range', '1h')

    try:
        ports_data = get_common_nfdump_data("ports", range_key)[:50]
        sources_data = get_common_nfdump_data("sources", range_key)[:50]
        destinations_data = get_common_nfdump_data("destinations", range_key)[:50]
        protocols_data = get_common_nfdump_data("protocols", range_key)[:20]

        # Run all detections
        new_alerts = run_all_detections(ports_data, sources_data, destinations_data, protocols_data)

        return jsonify({
            'status': 'ok',
            'new_alerts': len(new_alerts),
            'alerts': new_alerts[:20]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500



@bp.route('/api/security/threats/by_country')
@throttle(5, 10)
def api_threats_by_country():
    """Get threat counts grouped by country with firewall block data"""
    country_stats = defaultdict(lambda: {'count': 0, 'ips': [], 'categories': defaultdict(int), 'blocked': 0})

    # Get blocked IPs by country from syslog
    blocked_by_country = {}
    try:
        db_path = FIREWALL_DB_PATH
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path, timeout=5)
            cur = conn.cursor()
            cutoff = int(time.time()) - 86400
            cur.execute("""
                SELECT country_iso, COUNT(*) as blocks, COUNT(DISTINCT src_ip) as unique_ips
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ? AND country_iso IS NOT NULL
                GROUP BY country_iso
            """, (cutoff,))
            for row in cur.fetchall():
                if row[0]:
                    blocked_by_country[row[0]] = {'blocks': row[1], 'unique_ips': row[2]}
            conn.close()
    except:
        pass

    for ip, timeline in threats_module._threat_timeline.items():
        if time.time() - timeline['last_seen'] < 86400:
            geo = lookup_geo(ip) or {}
            country = geo.get('country_code', 'XX')
            country_name = geo.get('country', 'Unknown')

            country_stats[country]['count'] += 1
            country_stats[country]['name'] = country_name
            if len(country_stats[country]['ips']) < 5:
                country_stats[country]['ips'].append(ip)

            info = get_threat_info(ip)
            country_stats[country]['categories'][info.get('category', 'UNKNOWN')] += 1

    # Merge with firewall block data
    for code, block_data in blocked_by_country.items():
        if code not in country_stats:
            # Country only seen in firewall blocks, not in threat feeds
            country_stats[code]['name'] = code  # We don't have the full name
            country_stats[code]['blocked_only'] = True
        country_stats[code]['blocked'] = block_data['blocks']
        country_stats[code]['blocked_ips'] = block_data['unique_ips']

    # Convert to list and sort
    result = []
    for code, data in country_stats.items():
        result.append({
            'country_code': code,
            'country_name': data.get('name', 'Unknown'),
            'threat_count': data['count'],
            'blocked': data.get('blocked', 0),
            'blocked_ips': data.get('blocked_ips', 0),
            'sample_ips': data['ips'],
            'categories': dict(data['categories']),
            'blocked_only': data.get('blocked_only', False)
        })

    result.sort(key=lambda x: (x['threat_count'] + x['blocked']), reverse=True)
    total_blocked = sum(r['blocked'] for r in result)

    return jsonify({
        'countries': result[:20],
        'total_countries': len(result),
        'total_blocked': total_blocked,
        'has_fw_data': total_blocked > 0
    })



@bp.route('/api/security/threat_velocity')
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
            ts = alert.get('ts', 0)
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

    return jsonify({
        'current': current_hour,
        'trend': trend,
        'total_24h': total_24h,
        'peak': peak,
        'hourly': dict(hourly_counts)
    })



@bp.route('/api/security/top_threat_ips')
@throttle(5, 10)
def api_top_threat_ips():
    """Get top threat IPs by hit count"""
    now = time.time()

    # Get IPs with timeline data from last 24h
    threat_ips = []
    for ip, timeline in threats_module._threat_timeline.items():
        if now - timeline['last_seen'] < 86400:
            info = get_threat_info(ip)
            geo = lookup_geo(ip) or {}
            threat_ips.append({
                'ip': ip,
                'hits': timeline.get('hit_count', 1),
                'first_seen': timeline.get('first_seen'),
                'last_seen': timeline.get('last_seen'),
                'category': info.get('category', 'UNKNOWN'),
                'feed': info.get('feed', 'unknown'),
                'country': geo.get('country_code', '--'),
                'mitre': info.get('mitre_technique', '')
            })

    # Sort by hits descending
    threat_ips.sort(key=lambda x: x['hits'], reverse=True)

    return jsonify({
        'ips': threat_ips[:10],
        'total': len(threat_ips)
    })


@bp.route('/api/security/compromised_hosts')
@throttle(5, 10)
def api_compromised_hosts():
    """Identify internal hosts communicating with known threats."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)

    with _lock_compromised:
        if _stats_compromised_cache["data"] and _stats_compromised_cache.get("key") == range_key and _stats_compromised_cache.get("win") == win:
            return jsonify(_stats_compromised_cache["data"])

    tf = get_time_range(range_key)
    threat_set = load_threatlist()
    watchlist = load_watchlist()
    # Combine sets safely (ensure both are sets)
    full_threat_set = set(threat_set) | set(watchlist)

    if not full_threat_set:
        data = {"hosts": [], "count": 0}
        with _lock_compromised:
            _stats_compromised_cache["data"] = data
            _stats_compromised_cache["ts"] = now
            _stats_compromised_cache["key"] = range_key
            _stats_compromised_cache["win"] = win
        return jsonify(data)

    # Run nfdump to get top flows (src, dst, bytes, flows, port)
    # Using 2000 flows to get a reasonable sample
    output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,dstport", "-n", "2000"], tf)

    compromised = {}  # Map internal_ip -> info

    try:
        lines = output.strip().split("\n")
        # Header parsing logic similar to other endpoints
        start_idx = 0
        sa_idx, da_idx, dp_idx, ibyt_idx, fl_idx = 3, 4, 6, 8, 9

        if lines:
            line0 = lines[0].lower()
            if 'ts' in line0 or 'date' in line0 or 'ibyt' in line0:
                header = [c.strip() for c in line0.split(',')]
                try:
                    sa_idx = header.index('sa') if 'sa' in header else header.index('srcaddr')
                    da_idx = header.index('da') if 'da' in header else header.index('dstaddr')
                    dp_idx = header.index('dp') if 'dp' in header else header.index('dstport')
                    ibyt_idx = header.index('ibyt') if 'ibyt' in header else header.index('bytes')
                    fl_idx = header.index('fl') if 'fl' in header else header.index('flows')
                    start_idx = 1
                except:
                    pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('Date,'): continue
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, dp_idx, ibyt_idx):
                try:
                    src = parts[sa_idx].strip()
                    dst = parts[da_idx].strip()
                    port = int(parts[dp_idx].strip())
                    bytes_val = int(parts[ibyt_idx].strip())
                    flows_val = int(parts[fl_idx].strip()) if len(parts) > fl_idx else 1

                    src_int = is_internal(src)
                    dst_int = is_internal(dst)

                    # Logic: Internal <-> Threat
                    internal_ip = None
                    threat_ip = None
                    direction = None

                    if src_int and dst in full_threat_set:
                        internal_ip = src
                        threat_ip = dst
                        direction = 'outbound'
                    elif dst_int and src in full_threat_set:
                        internal_ip = dst
                        threat_ip = src
                        direction = 'inbound'

                    if internal_ip:
                        if internal_ip not in compromised:
                            compromised[internal_ip] = {
                                "ip": internal_ip,
                                "hostname": resolve_ip(internal_ip),
                                "threat_peers": set(),
                                "bytes": 0,
                                "flows": 0,
                                "top_threat": threat_ip,
                                "max_bytes": 0,
                                "direction": direction # Dominant direction
                            }

                        entry = compromised[internal_ip]
                        entry["threat_peers"].add(threat_ip)
                        entry["bytes"] += bytes_val
                        entry["flows"] += flows_val

                        # Update top threat if this flow is larger
                        if bytes_val > entry["max_bytes"]:
                            entry["max_bytes"] = bytes_val
                            entry["top_threat"] = threat_ip
                            entry["direction"] = direction
                except Exception:
                    pass
    except Exception as e:
        print(f"Error processing compromised hosts: {e}")

    # Format results
    results = []
    for ip, data in compromised.items():
        threat_count = len(data["threat_peers"])
        info = get_threat_info(data["top_threat"])
        geo = lookup_geo(data["top_threat"]) or {}

        results.append({
            "ip": ip,
            "hostname": data["hostname"],
            "role": "Victim" if data["direction"] == "inbound" else "Exfiltrator?",
            "direction": data["direction"],
            "threat_ip": data["top_threat"],
            "threat_count": threat_count,
            "bytes": data["bytes"],
            "bytes_fmt": fmt_bytes(data["bytes"]),
            "flows": data["flows"],
            "threat_category": info.get("category", "UNKNOWN"),
            "threat_country": geo.get("country_code", "--"),
            "risk_score": min(100, threat_count * 10 + (data["bytes"] / 1000000)) # Simple score
        })

    # Sort by risk score descending
    results.sort(key=lambda x: x["risk_score"], reverse=True)

    data = {
        "hosts": results[:20],
        "count": len(results)
    }

    with _lock_compromised:
        _stats_compromised_cache["data"] = data
        _stats_compromised_cache["ts"] = now
        _stats_compromised_cache["key"] = range_key
        _stats_compromised_cache["win"] = win

    return jsonify(data)



@bp.route('/api/security/risk_index')
@throttle(5, 10)
def api_risk_index():
    """Calculate Network Risk Index based on traffic patterns and threats"""
    # Gather risk factors
    risk_factors = []
    risk_score = 0

    # Factor 1: Active threats (0-30 points)
    threat_count = len(threats_module._threat_timeline)
    if threat_count == 0:
        risk_factors.append({'factor': 'Active Threats', 'value': 'None', 'impact': 'low', 'points': 0})
    elif threat_count <= 5:
        risk_score += 10
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'medium', 'points': 10})
    elif threat_count <= 20:
        risk_score += 20
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'high', 'points': 20})
    else:
        risk_score += 30
        risk_factors.append({'factor': 'Active Threats', 'value': f'{threat_count} IPs', 'impact': 'critical', 'points': 30})

    # Factor 2: Threat velocity (0-20 points)
    # Count threats seen in the last hour
    one_hour_ago = time.time() - 3600
    hourly_threats = len([ip for ip in threats_module._threat_timeline
                          if threats_module._threat_timeline[ip]['last_seen'] >= one_hour_ago])
    if hourly_threats == 0:
        risk_factors.append({'factor': 'Threat Velocity', 'value': '0/hr', 'impact': 'low', 'points': 0})
    elif hourly_threats <= 5:
        risk_score += 5
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'medium', 'points': 5})
    elif hourly_threats <= 20:
        risk_score += 10
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'high', 'points': 10})
    else:
        risk_score += 20
        risk_factors.append({'factor': 'Threat Velocity', 'value': f'{hourly_threats}/hr', 'impact': 'critical', 'points': 20})

    # Factor 3: Feed coverage (0-15 points for poor coverage)
    if threats_module._feed_status:
        ok_feeds = sum(1 for f in threats_module._feed_status.values() if f.get('status') == 'ok')
        total_feeds = len(threats_module._feed_status)
        if total_feeds > 0:
            coverage = ok_feeds / total_feeds
            if coverage >= 0.9:
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'low', 'points': 0})
            elif coverage >= 0.7:
                risk_score += 5
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'medium', 'points': 5})
            else:
                risk_score += 15
                risk_factors.append({'factor': 'Feed Coverage', 'value': f'{ok_feeds}/{total_feeds}', 'impact': 'high', 'points': 15})

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
        risk_factors.append({'factor': 'Suspicious Ports', 'value': 'Detected', 'impact': 'medium', 'points': 10})
    else:
        risk_factors.append({'factor': 'Suspicious Ports', 'value': 'Normal', 'impact': 'low', 'points': 0})

    # Factor 5: External exposure (0-15 points)
    # Simplified: assume some external exposure exists
    risk_score += 5
    risk_factors.append({'factor': 'External Traffic', 'value': 'Present', 'impact': 'medium', 'points': 5})

    # Calculate risk level
    if risk_score <= 15:
        risk_level = 'LOW'
        risk_color = 'green'
    elif risk_score <= 35:
        risk_level = 'MODERATE'
        risk_color = 'yellow'
    elif risk_score <= 55:
        risk_level = 'ELEVATED'
        risk_color = 'orange'
    elif risk_score <= 75:
        risk_level = 'HIGH'
        risk_color = 'red'
    else:
        risk_level = 'CRITICAL'
        risk_color = 'red'

    return jsonify({
        'score': risk_score,
        'max_score': 100,
        'level': risk_level,
        'color': risk_color,
        'factors': risk_factors
    })



@bp.route('/api/security/watchlist', methods=['GET'])
@throttle(5, 10)
def api_get_watchlist():
    """Get current watchlist"""
    watchlist = load_watchlist()
    items = []
    for ip in watchlist:
        geo = lookup_geo(ip) or {}
        items.append({
            'ip': ip,
            'country': geo.get('country_code', '--'),
            'city': geo.get('city', '')
        })
    return jsonify({'watchlist': items, 'count': len(items)})



@bp.route('/api/security/watchlist', methods=['POST'])
def api_add_watchlist():
    """Add IP to watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP required'}), 400

    success = add_to_watchlist(ip)
    return jsonify({'success': success, 'ip': ip})



@bp.route('/api/security/watchlist', methods=['DELETE'])
def api_remove_watchlist():
    """Remove IP from watchlist"""
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP required'}), 400

    success = remove_from_watchlist(ip)
    return jsonify({'success': success, 'ip': ip})



@bp.route("/api/notify_status")
def api_notify_status():
    return jsonify(load_notify_cfg())


@bp.route("/api/notify_toggle", methods=['POST'])
def api_notify_toggle():
    data = request.get_json(force=True, silent=True) or {}
    target = data.get('target')
    state = bool(data.get('state', True))
    cfg = load_notify_cfg()
    if target == 'email':
        cfg['email'] = state
    elif target == 'webhook':
        cfg['webhook'] = state
    save_notify_cfg(cfg)
    return jsonify(cfg)


@bp.route("/api/alerts_history")
def api_alerts_history():
    return jsonify(list(threats_module._alert_history))


@bp.route('/api/alerts_export')
def api_alerts_export():
    return jsonify(list(threats_module._alert_history))


@bp.route('/api/notify_mute', methods=['POST'])
def api_notify_mute():
    data = request.get_json(force=True, silent=True) or {}
    mute = bool(data.get('mute', True))
    cfg = load_notify_cfg()
    cfg['mute_until'] = time.time() + 3600 if mute else 0
    save_notify_cfg(cfg)
    return jsonify(cfg)


@bp.route('/api/thresholds', methods=['GET', 'POST'])
def api_thresholds():
    if request.method == 'GET':
        return jsonify(load_thresholds())
    data = request.get_json(force=True, silent=True) or {}
    saved = save_thresholds(data)
    return jsonify(saved)


# ===== FORENSICS API ENDPOINTS =====


@bp.route('/api/forensics/flow-search')
def api_forensics_flow_search():
    """Advanced flow search with multi-criteria filtering for forensics investigation."""
    range_val = request.args.get('range', '1h')
    src_ip = request.args.get('src_ip', '')
    dst_ip = request.args.get('dst_ip', '')
    port = request.args.get('port', '')
    protocol = request.args.get('protocol', '')
    country = request.args.get('country', '')

    # Build nfdump filter
    filters = []
    if src_ip:
        filters.append(f"src ip {src_ip}")
    if dst_ip:
        filters.append(f"dst ip {dst_ip}")
    if port:
        filters.append(f"(src port {port} or dst port {port})")
    if protocol:
        proto_map = {'tcp': '6', 'udp': '17', 'icmp': '1'}
        proto_num = proto_map.get(protocol.lower(), protocol)
        filters.append(f"proto {proto_num}")

    filter_str = ' and '.join(filters) if filters else ''
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
            return jsonify({'flows': [], 'count': 0})

        # Parse header dynamically
        header = lines[0].split(',')
        try:
            sa_idx = header.index('sa')
            da_idx = header.index('da')
            dp_idx = header.index('dp')
            pr_idx = header.index('proto')
            ibyt_idx = header.index('ibyt')
            ipkt_idx = header.index('ipkt')
        except ValueError:
            # Fallback indices (based on mock/nfdump std)
            sa_idx, da_idx, dp_idx, pr_idx, ibyt_idx, ipkt_idx = 3, 4, 6, 7, 12, 11

        seen_flows = set()
        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
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

                    bytes_val = int(parts[ibyt_idx]) if len(parts) > ibyt_idx and parts[ibyt_idx].strip().isdigit() else 0
                    packets_val = int(parts[ipkt_idx]) if len(parts) > ipkt_idx and parts[ipkt_idx].strip().isdigit() else 0
                    port_val = int(dst_port) if dst_port.isdigit() else 0

                    # Map protocol number to name if needed
                    proto_name = proto
                    if proto.isdigit():
                        proto_name = PROTOS.get(int(proto), proto)

                    flows.append({
                        'src': src,
                        'dst': dst,
                        'proto': proto_name,
                        'port': port_val,
                        'bytes': bytes_val,
                        'packets': packets_val
                    })
                except (ValueError, IndexError):
                    continue

        # Sort by bytes descending
        flows.sort(key=lambda x: x.get('bytes', 0), reverse=True)
        flows = flows[:100]  # Limit to top 100

        # Apply country filter if specified
        if country:
            city_db = load_city_db()
            if city_db:
                filtered_flows = []
                for flow in flows:
                    try:
                        src_rec = city_db.get(flow['src'])
                        dst_rec = city_db.get(flow['dst'])
                        src_country = src_rec.get('country', {}).get('iso_code') if src_rec else None
                        dst_country = dst_rec.get('country', {}).get('iso_code') if dst_rec else None
                        if (src_country == country.upper()) or (dst_country == country.upper()):
                            filtered_flows.append(flow)
                    except:
                        pass
                flows = filtered_flows

        return jsonify({'flows': flows, 'count': len(flows)})

    except Exception as e:
        print(f"Flow search error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'flows': [], 'count': 0, 'error': str(e)})



@bp.route('/api/forensics/alert-correlation')
def api_forensics_alert_correlation():
    """Correlate alerts to identify attack chains and multi-stage attacks."""
    try:
        range_val = request.args.get('range', '24h')
        range_seconds = {'1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_val, 86400)
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
            alerts = [a for a in threats_module._alert_history if a.get('ts', 0) > cutoff or a.get('timestamp', 0) > cutoff]

        # Group alerts by IP and time proximity (within 1 hour)
        chains = {}
        time_threshold = 3600  # 1 hour in seconds

        for alert in sorted(alerts, key=lambda x: _parse_ts(x.get('timestamp', 0) or x.get('ts', 0)) or 0):
            ip = alert.get('ip') or alert.get('source_ip')
            if not ip:
                continue

            # Ensure timestamp is float
            timestamp = _parse_ts(alert.get('timestamp', 0) or alert.get('ts', 0))
            if timestamp is None:
                continue

            # Find if this IP has an existing chain within time threshold
            found_chain = False

            # Optimization: Direct lookup instead of iteration
            if ip in chains:
                chain_data = chains[ip]
                last_alert = chain_data['alerts'][-1]
                last_alert_time = _parse_ts(last_alert.get('timestamp', 0) or last_alert.get('ts', 0))
                if last_alert_time is not None and timestamp - last_alert_time <= time_threshold:
                    chain_data['alerts'].append(alert)
                    chain_data['end_time'] = timestamp
                    found_chain = True

            # Create new chain if not found (or time gap too large - overwrites old chain logic preserved for now to avoid logic drift)
            if not found_chain:
                # If we are overwriting, we effectively split the chain and keep the latest segment.
                # Ideally we should store a list of chains, but for now let's just be robust.
                chains[ip] = {
                    'ip': ip,
                    'alerts': [alert],
                    'start_time': timestamp,
                    'end_time': timestamp
                }

        # Filter chains with multiple alerts and format response
        result_chains = []
        for ip, chain_data in chains.items():
            if len(chain_data['alerts']) > 1:  # Only chains with multiple related alerts
                formatted_alerts = []
                for a in chain_data['alerts']:
                    ts_val = _parse_ts(a.get('timestamp', 0) or a.get('ts', 0))
                    if ts_val is None:
                        time_str = 'recent'
                        ts_val = 0
                    else:
                        time_str = datetime.fromtimestamp(ts_val).strftime('%H:%M:%S')

                    formatted_alerts.append({
                        'id': f"{a.get('type', 'alert')}_{ts_val}",
                        'type': a.get('type', 'unknown'),
                        'message': a.get('msg', 'Alert'),
                        'time': time_str
                    })

                result_chains.append({
                    'ip': ip,
                    'alerts': formatted_alerts,
                    'timespan': f"{len(chain_data['alerts'])} alerts over {int((chain_data['end_time'] - chain_data['start_time']) / 60)}min"
                })

        return jsonify({'chains': result_chains, 'count': len(result_chains)})
    except Exception as e:
        print(f"Error in alert correlation: {e}")
        return jsonify({'chains': [], 'count': 0, 'error': str(e)}), 500


# ===== Configuration Settings =====

@bp.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update application configuration."""
    if request.method == 'GET':
        cfg = load_config()
        # Mask sensitive values for display
        if cfg.get('snmp_community'):
            cfg['snmp_community_masked'] = '*' * len(cfg['snmp_community'])
        return jsonify(cfg)
    data = request.get_json(force=True, silent=True) or {}
    saved = save_config(data)
    return jsonify({'status': 'ok', 'config': saved})


@bp.route('/api/app/metadata')
@throttle(10, 60)
def api_app_metadata():
    """Get application metadata (name, version)."""
    from app.config import APP_NAME, APP_VERSION, APP_VERSION_DISPLAY
    return jsonify({
        'name': APP_NAME,
        'version': APP_VERSION,
        'version_display': APP_VERSION_DISPLAY
    })



@bp.route('/metrics')
def metrics():
    """Prometheus-style metrics for basic instrumentation."""
    lines = []
    def add_metric(name, value, help_text=None, mtype='gauge'):
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        if mtype:
            lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    add_metric('netflow_nfdump_calls_total', _metric_nfdump_calls, 'Total number of nfdump calls', 'counter')
    add_metric('netflow_stats_cache_hits_total', _metric_stats_cache_hits, 'Cache hits for stats endpoints', 'counter')
    add_metric('netflow_bw_cache_hits_total', _metric_bw_cache_hits, 'Cache hits for bandwidth endpoint', 'counter')
    add_metric('netflow_flow_cache_hits_total', _metric_flow_cache_hits, 'Cache hits for flows endpoint', 'counter')
    add_metric('netflow_http_429_total', _metric_http_429, 'HTTP 429 rate-limit responses', 'counter')
    # Cache sizes
    add_metric('netflow_common_cache_size', len(_common_data_cache))
    add_metric('netflow_dns_cache_size', len(dns_module._dns_cache))
    add_metric('netflow_geo_cache_size', len(geoip_module._geo_cache))
    add_metric('netflow_bandwidth_history_size', len(_bandwidth_history_cache))
    # Threads status
    add_metric('netflow_threat_thread_started', 1 if _threat_thread_started else 0)
    add_metric('netflow_snmp_thread_started', 1 if _snmp_thread_started else 0)
    add_metric('netflow_trends_thread_started', 1 if _trends_thread_started else 0)
    add_metric('netflow_agg_thread_started', 1 if _agg_thread_started else 0)

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype='text/plain; version=0.0.4')



@bp.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    checks = {
        'database': False,
        'disk_space': check_disk_space('/var/cache/nfdump'),
        'syslog_active': _syslog_stats.get('received', 0) > 0,
        'nfdump_available': state._has_nfdump,
        'memory_usage_mb': 0
    }

    # Check database connectivity
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            conn.execute("SELECT 1")
            conn.close()
        checks['database'] = True
    except Exception:
        checks['database'] = False

    # Check memory usage (simple approximation)
    try:
        import resource
        mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux returns KB
        checks['memory_usage_mb'] = round(mem_mb, 1)
    except Exception:
        pass

    # Determine overall status
    disk_status = checks['disk_space'].get('status', 'unknown')
    all_ok = checks['database'] and checks['syslog_active'] and checks['nfdump_available'] and disk_status != 'critical'

    status_code = 200 if all_ok else 503
    status_text = 'healthy' if all_ok else 'degraded'

    return jsonify({
        'status': status_text,
        'checks': checks,
        'timestamp': datetime.now().isoformat()
    }), status_code



@bp.route('/api/server/health')
@throttle(10, 5)  # Allow 10 requests per 5 seconds (2 req/sec) for 1-2 sec refresh
def api_server_health():
    """Comprehensive server health statistics for the dashboard server."""
    global _server_health_cache
    now = time.time()

    # Use cache if data is fresh (1 second TTL for near-real-time updates)
    SERVER_HEALTH_CACHE_TTL = 1.0
    with _cache_lock:
        if _server_health_cache["data"] and (now - _server_health_cache["ts"]) < SERVER_HEALTH_CACHE_TTL:
            return jsonify(_server_health_cache["data"])

    from app.config import APP_NAME, APP_VERSION
    
    data = {
        'application': {
            'name': APP_NAME,
            'version': APP_VERSION
        },
        'cpu': {},
        'memory': {},
        'disk': {},
        'syslog': {},
        'netflow': {},
        'database': {},
        'system': {},
        'timestamp': datetime.now().isoformat()
    }

    # CPU Statistics - use /proc filesystem (no psutil)
    try:
        # Get CPU percentage from /proc/stat (accurate method)
        cpu_percent, per_core, num_cores = calculate_cpu_percent_from_stat()
        if cpu_percent is not None:
            data['cpu']['percent'] = cpu_percent
        if per_core:
            data['cpu']['per_core'] = [round(p, 1) for p in per_core]
        if num_cores:
            data['cpu']['cores'] = num_cores

        # Get load averages
        try:
            loadavg = os.getloadavg() if hasattr(os, 'getloadavg') else None
            if loadavg:
                data['cpu']['load_1min'] = round(loadavg[0], 2)
                data['cpu']['load_5min'] = round(loadavg[1], 2)
                data['cpu']['load_15min'] = round(loadavg[2], 2)
            else:
                # Fallback to /proc/loadavg
                with open('/proc/loadavg', 'r') as f:
                    loads = [float(x) for x in f.read().split()[:3]]
                    data['cpu']['load_1min'] = round(loads[0], 2)
                    data['cpu']['load_5min'] = round(loads[1], 2)
                    data['cpu']['load_15min'] = round(loads[2], 2)
        except Exception:
            pass

        # Get process count
        try:
            proc_count = len([d for d in os.listdir('/proc') if d.isdigit()])
            data['cpu']['process_count'] = proc_count
        except Exception:
            pass

        # Get CPU frequency (if available)
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                # Try to find frequency
                import re
                freq_match = re.search(r'cpu MHz\s*:\s*([\d.]+)', cpuinfo)
                if freq_match:
                    freq_mhz = float(freq_match.group(1))
                    data['cpu']['frequency_mhz'] = round(freq_mhz, 0)
        except Exception:
            pass

        # Count CPU cores if not already set
        if 'cores' not in data['cpu']:
            try:
                with open('/proc/cpuinfo', 'r') as cf:
                    cores = len([l for l in cf.readlines() if l.startswith('processor')])
                data['cpu']['cores'] = max(cores, 1)
            except Exception:
                data['cpu']['cores'] = 1

        # If CPU percent still not set, use load average approximation as fallback
        if 'percent' not in data['cpu'] or data['cpu']['percent'] is None:
            if 'load_1min' in data['cpu'] and 'cores' in data['cpu']:
                cores = data['cpu']['cores']
                load = data['cpu']['load_1min']
                data['cpu']['percent'] = min(round((load / cores) * 100, 1), 100.0)
    except Exception as e:
        data['cpu'] = {'percent': 0, 'error': str(e)}

    # Memory Statistics - use /proc filesystem (Linux)
    try:
        import resource
        # Get process memory
        try:
            mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux returns KB
            mem_mb = mem_kb / 1024
            data['memory']['process_mb'] = round(mem_mb, 1)
        except Exception:
            pass

        # Get system memory from /proc/meminfo
        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)

            if 'MemTotal' in meminfo and 'MemAvailable' in meminfo:
                total_kb = meminfo['MemTotal']
                avail_kb = meminfo['MemAvailable']
                used_kb = total_kb - avail_kb
                data['memory']['total_gb'] = round(total_kb / (1024 * 1024), 2)
                data['memory']['used_gb'] = round(used_kb / (1024 * 1024), 2)
                data['memory']['available_gb'] = round(avail_kb / (1024 * 1024), 2)
                data['memory']['percent'] = round((used_kb / total_kb) * 100, 1) if total_kb > 0 else 0

                # Memory breakdown
                if 'MemFree' in meminfo:
                    data['memory']['free_gb'] = round(meminfo['MemFree'] / (1024 * 1024), 2)
                if 'Buffers' in meminfo:
                    data['memory']['buffers_gb'] = round(meminfo['Buffers'] / (1024 * 1024), 2)
                if 'Cached' in meminfo:
                    data['memory']['cached_gb'] = round(meminfo['Cached'] / (1024 * 1024), 2)

                # Memory pressure indicator
                if data['memory']['percent'] >= 90:
                    data['memory']['pressure'] = 'high'
                elif data['memory']['percent'] >= 75:
                    data['memory']['pressure'] = 'medium'
                else:
                    data['memory']['pressure'] = 'low'

            # Swap statistics
            if 'SwapTotal' in meminfo and 'SwapFree' in meminfo:
                swap_total_kb = meminfo['SwapTotal']
                swap_free_kb = meminfo['SwapFree']
                swap_used_kb = swap_total_kb - swap_free_kb
                if swap_total_kb > 0:
                    data['memory']['swap_total_gb'] = round(swap_total_kb / (1024 * 1024), 2)
                    data['memory']['swap_used_gb'] = round(swap_used_kb / (1024 * 1024), 2)
                    data['memory']['swap_free_gb'] = round(swap_free_kb / (1024 * 1024), 2)
                    data['memory']['swap_percent'] = round((swap_used_kb / swap_total_kb) * 100, 1)
        except Exception as e:
            pass
    except Exception as e:
        data['memory'] = {'error': str(e)}

    # Disk Statistics
    try:
        # Root filesystem
        root_disk = check_disk_space('/')
        data['disk']['root'] = root_disk

        # NetFlow data directory
        nfdump_disk = check_disk_space('/var/cache/nfdump')
        data['disk']['nfdump'] = nfdump_disk

        # Count nfdump files
        try:
            nfdump_dir = '/var/cache/nfdump'
            if os.path.exists(nfdump_dir):
                files = [f for f in os.listdir(nfdump_dir) if f.startswith('nfcapd.')]
                data['disk']['nfdump_files'] = len(files)
            else:
                data['disk']['nfdump_files'] = 0
        except Exception:
            data['disk']['nfdump_files'] = 0
    except Exception:
        data['disk'] = {'error': 'Unable to read disk stats'}

    # Syslog Statistics
    try:
        with _syslog_stats_lock:
            # Syslog is active if: thread is started (receiver is running)
            # If logs have been received, also check if last log was recent (within 5 min)
            last_log_ts = _syslog_stats.get('last_log')
            if last_log_ts:
                # If we have logs, check if they're recent
                syslog_active = (time.time() - last_log_ts) < 300
            else:
                # If no logs yet, consider active if thread is running (receiver is listening)
                syslog_active = state._syslog_thread_started

            data['syslog'] = {
                'received': _syslog_stats.get('received', 0),
                'parsed': _syslog_stats.get('parsed', 0),
                'errors': _syslog_stats.get('errors', 0),
                'last_log': last_log_ts,
                'active': syslog_active
            }
    except Exception:
        data['syslog'] = {'error': 'Unable to read syslog stats'}

    # NetFlow Statistics
    try:
        nfdump_dir = '/var/cache/nfdump'
        netflow_data = {
            'available': state._has_nfdump if state._has_nfdump is not None else False,
            'directory': nfdump_dir,
            'disk_usage': data['disk'].get('nfdump', {}),
            'files_count': data['disk'].get('nfdump_files', 0)
        }

        # Try to get nfdump version
        try:
            result = subprocess.run(['nfdump', '-V'], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0] if result.stdout else ''
                netflow_data['version'] = version_line.strip()
        except Exception:
            pass

        data['netflow'] = netflow_data
    except Exception:
        data['netflow'] = {'error': 'Unable to read NetFlow stats'}

    # Database Statistics
    try:
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                # Get row count
                cursor = conn.execute("SELECT COUNT(*) FROM fw_logs")
                log_count = cursor.fetchone()[0]

                # Get database size
                db_path = FIREWALL_DB_PATH
                db_size = 0
                if os.path.exists(db_path):
                    db_size = os.path.getsize(db_path)

                db_info = {
                    'connected': True,
                    'log_count': log_count,
                    'size_mb': round(db_size / (1024 * 1024), 2),
                    'path': db_path
                }

                # Get records from last 24h and 1h for growth rate calculation
                try:
                    now = time.time()
                    cutoff_24h = now - 86400
                    cutoff_1h = now - 3600
                    cursor_24h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_24h,))
                    count_24h = cursor_24h.fetchone()[0]
                    cursor_1h = conn.execute("SELECT COUNT(*) FROM fw_logs WHERE timestamp > ?", (cutoff_1h,))
                    count_1h = cursor_1h.fetchone()[0]
                    db_info['logs_24h'] = count_24h
                    db_info['logs_1h'] = count_1h
                    db_info['growth_rate_per_hour'] = count_1h
                    db_info['growth_rate_per_day'] = count_24h
                except Exception:
                    pass

                data['database'] = db_info
            finally:
                conn.close()
    except Exception as e:
        data['database'] = {'connected': False, 'error': str(e)}

    # System Information (Uptime, Process Info)
    try:
        # Get system uptime from /proc/uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                data['system']['uptime_seconds'] = int(uptime_seconds)
                data['system']['uptime_formatted'] = f"{days}d {hours}h {minutes}m"
        except Exception:
            data['system']['uptime_formatted'] = 'N/A'

        # Get process/thread information using /proc
        try:
            import glob
            pid = os.getpid()
            # Count threads in /proc/PID/task/
            thread_count = len([d for d in glob.glob(f'/proc/{pid}/task/*') if os.path.isdir(d)])
            data['system']['process_threads'] = thread_count

            # Get process name/command
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    data['system']['process_name'] = f.read().strip()
            except Exception:
                data['system']['process_name'] = 'python3'
        except Exception:
            data['system']['process_threads'] = 0

        # Get boot time
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            boot_time = time.time() - uptime_seconds
            data['system']['boot_time'] = datetime.fromtimestamp(boot_time).isoformat()
            data['system']['boot_time_formatted'] = datetime.fromtimestamp(boot_time).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass

        # Get kernel version
        try:
            with open('/proc/version', 'r') as f:
                version_line = f.read().strip()
                # Extract kernel version (e.g., "Linux version 5.10.0-...")
                import re
                kernel_match = re.search(r'Linux version ([^\s]+)', version_line)
                if kernel_match:
                    data['system']['kernel_version'] = kernel_match.group(1)
                data['system']['os_info'] = version_line.split('(')[0].strip()
        except Exception:
            pass

        # Get hostname
        try:
            data['system']['hostname'] = socket_module.gethostname()
        except Exception:
            try:
                with open('/etc/hostname', 'r') as f:
                    data['system']['hostname'] = f.read().strip()
            except Exception:
                pass
    except Exception:
        data['system'] = {'error': 'Unable to read system stats'}

    # Network Statistics (from /proc/net/dev)
    try:
        interfaces = {}
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.split(':')
                    iface_name = parts[0].strip()
                    stats = parts[1].split()
                    if len(stats) >= 16:
                        interfaces[iface_name] = {
                            'rx_bytes': int(stats[0]),
                            'rx_packets': int(stats[1]),
                            'tx_bytes': int(stats[8]),
                            'tx_packets': int(stats[9])
                        }
        data['network'] = {'interfaces': interfaces}
    except Exception:
        data['network'] = {'interfaces': {}}

    # Cache Statistics
    try:
        with _cache_lock:
            data['cache'] = {
                'dns_cache_size': len(dns_module._dns_cache),
                'geo_cache_size': len(geoip_module._geo_cache),
                'common_cache_size': len(_common_data_cache),
                'bandwidth_history_size': len(_bandwidth_history_cache)
            }
    except Exception:
        data['cache'] = {}

    # Process/Application Metrics
    try:
        import resource
        pid = os.getpid()

        # Get process memory
        mem_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        mem_mb = mem_kb / 1024

        process_metrics = {
            'process_memory_mb': round(mem_mb, 1),
            'threads': data.get('system', {}).get('process_threads', 0)
        }

        # Get process stats from /proc/PID/stat
        try:
            with open(f'/proc/{pid}/stat', 'r') as f:
                stat_parts = f.read().split()
                if len(stat_parts) > 13:
                    # utime + stime = total CPU time
                    utime = int(stat_parts[13])
                    stime = int(stat_parts[14])
                    process_metrics['cpu_time'] = utime + stime
        except Exception:
            pass

        data['process'] = process_metrics
    except Exception:
        data['process'] = {}

    # Cache the result
    with _cache_lock:
        _server_health_cache["data"] = data
        _server_health_cache["ts"] = now

    return jsonify(data)


@bp.route('/api/firewall/snmp-status')
@throttle(5, 10)
def api_firewall_snmp_status():
    """Get firewall SNMP operational health data."""
    from app.services.snmp import get_snmp_data, discover_interfaces
    import time
    import subprocess
    from app.config import SNMP_HOST, SNMP_COMMUNITY
    
    snmp_data = get_snmp_data()
    
    # Store cache timestamp for staleness checks
    import app.core.state as state
    with state._snmp_cache_lock:
        cache_ts = state._snmp_cache.get("ts", time.time())
    snmp_data["_cache_ts"] = cache_ts
    
    # Check for errors FIRST - don't proceed if SNMP is unavailable
    if "error" in snmp_data:
        return jsonify({
            "error": snmp_data.get("error", "SNMP unavailable"),
            "backoff": snmp_data.get("backoff", False),
            "data": None
        }), 503 if snmp_data.get("backoff") else 200
    
    # Discover VPN interfaces (WireGuard and TailScale) - only if SNMP is working
    vpn_interfaces = {}
    try:
        interface_mapping = discover_interfaces()
        if interface_mapping:
            if "wireguard" in interface_mapping:
                vpn_interfaces["wireguard"] = interface_mapping["wireguard"]
            if "tailscale" in interface_mapping:
                vpn_interfaces["tailscale"] = interface_mapping["tailscale"]
        # Debug logging
        from app.config import DEBUG_MODE
        if DEBUG_MODE:
            print(f"VPN interface discovery: found {len(vpn_interfaces)} interfaces: {vpn_interfaces}")
    except Exception as e:
        # Discovery failed - log but don't break the endpoint
        import traceback
        print(f"VPN interface discovery failed: {e}")
        print(traceback.format_exc())
        pass  # Continue without VPN interfaces
    
    # Extract interface data with proper status logic
    interfaces = []
    
    # Helper function to determine interface status
    def determine_interface_status(oper_status, admin_status, has_traffic, has_sessions, data_age_seconds):
        """Determine interface status with proper logic to avoid false DOWN states."""
        # If SNMP data is stale (>60s), mark as STALE
        if data_age_seconds > 60:
            return "stale"
        
        # Check admin status first - if admin down, show as ADMIN DOWN
        if admin_status is not None and admin_status == 2:
            return "admin_down"
        
        # If operStatus is explicitly available, use it
        if oper_status is not None:
            if oper_status == 1:
                return "up"
            elif oper_status == 2:
                # Only show DOWN if there's no traffic AND no sessions
                # If traffic exists, it's likely a false negative
                if not has_traffic and not has_sessions:
                    return "down"
                else:
                    return "unknown"  # Status says down but traffic exists - uncertain
            else:
                return "unknown"
        
        # If operStatus unknown, infer from traffic/sessions
        if has_traffic or has_sessions:
            return "up"  # Traffic/sessions indicate interface is up
        else:
            return "unknown"  # Can't determine without operStatus
    
    # Get data age for staleness check
    data_age = time.time() - snmp_data.get("_cache_ts", time.time())
    
    # Check if we have active sessions (indicates firewall is operational)
    has_sessions = snmp_data.get("tcp_conns", 0) > 0
    
    # WAN interface
    wan_status_raw = snmp_data.get("if_wan_status")
    wan_admin_status = snmp_data.get("if_wan_admin")
    # Check for traffic: use rates if available, otherwise check raw counters
    wan_has_traffic = False
    if snmp_data.get("wan_rx_mbps") is not None and snmp_data.get("wan_rx_mbps", 0) > 0:
        wan_has_traffic = True
    elif snmp_data.get("wan_tx_mbps") is not None and snmp_data.get("wan_tx_mbps", 0) > 0:
        wan_has_traffic = True
    elif snmp_data.get("wan_in", 0) > 0 or snmp_data.get("wan_out", 0) > 0:
        wan_has_traffic = True
    wan_status = determine_interface_status(wan_status_raw, wan_admin_status, wan_has_traffic, has_sessions, data_age)
    
    interfaces.append({
        "name": "WAN",
        "status": wan_status,
        "rx_mbps": snmp_data.get("wan_rx_mbps") if snmp_data.get("wan_rx_mbps") is not None else None,
        "tx_mbps": snmp_data.get("wan_tx_mbps") if snmp_data.get("wan_tx_mbps") is not None else None,
        "rx_errors": snmp_data.get("wan_in_err_s") if snmp_data.get("wan_in_err_s") is not None else None,
        "tx_errors": snmp_data.get("wan_out_err_s") if snmp_data.get("wan_out_err_s") is not None else None,
        "rx_drops": snmp_data.get("wan_in_disc_s") if snmp_data.get("wan_in_disc_s") is not None else None,
        "tx_drops": snmp_data.get("wan_out_disc_s") if snmp_data.get("wan_out_disc_s") is not None else None,
        "utilization": snmp_data.get("wan_util_percent") if snmp_data.get("wan_util_percent") is not None and snmp_data.get("wan_util_percent") >= 0 else None,
        "speed_mbps": snmp_data.get("wan_speed_mbps") if snmp_data.get("wan_speed_mbps") is not None else snmp_data.get("wan_speed"),
        "saturation_hint": None  # Will be set by saturation detection logic below
    })
    
    # LAN interface
    lan_status_raw = snmp_data.get("if_lan_status")
    lan_admin_status = snmp_data.get("if_lan_admin")
    # Check for traffic: use rates if available, otherwise check raw counters
    lan_has_traffic = False
    if snmp_data.get("lan_rx_mbps") is not None and snmp_data.get("lan_rx_mbps", 0) > 0:
        lan_has_traffic = True
    elif snmp_data.get("lan_tx_mbps") is not None and snmp_data.get("lan_tx_mbps", 0) > 0:
        lan_has_traffic = True
    elif snmp_data.get("lan_in", 0) > 0 or snmp_data.get("lan_out", 0) > 0:
        lan_has_traffic = True
    lan_status = determine_interface_status(lan_status_raw, lan_admin_status, lan_has_traffic, has_sessions, data_age)
    
    interfaces.append({
        "name": "LAN",
        "status": lan_status,
        "rx_mbps": snmp_data.get("lan_rx_mbps") if snmp_data.get("lan_rx_mbps") is not None else None,
        "tx_mbps": snmp_data.get("lan_tx_mbps") if snmp_data.get("lan_tx_mbps") is not None else None,
        "rx_errors": snmp_data.get("lan_in_err_s") if snmp_data.get("lan_in_err_s") is not None else None,
        "tx_errors": snmp_data.get("lan_out_err_s") if snmp_data.get("lan_out_err_s") is not None else None,
        "rx_drops": snmp_data.get("lan_in_disc_s") if snmp_data.get("lan_in_disc_s") is not None else None,
        "tx_drops": snmp_data.get("lan_out_disc_s") if snmp_data.get("lan_out_disc_s") is not None else None,
        "utilization": snmp_data.get("lan_util_percent") if snmp_data.get("lan_util_percent") is not None and snmp_data.get("lan_util_percent") >= 0 else None,
        "speed_mbps": snmp_data.get("lan_speed_mbps") if snmp_data.get("lan_speed_mbps") is not None else snmp_data.get("lan_speed"),
        "saturation_hint": None  # Will be set by saturation detection logic below
    })
    
    # Add VPN interfaces (WireGuard and TailScale)
    # Debug: Log VPN interfaces found
    if DEBUG_MODE and vpn_interfaces:
        print(f"DEBUG: Adding VPN interfaces: {vpn_interfaces}")
    
    for vpn_name, vpn_idx in vpn_interfaces.items():
        try:
            # Get VPN interface counters using SNMP
            # Try 64-bit counters first (ifHCInOctets/ifHCOutOctets), fallback to 32-bit if not available
            vpn_in_oid_hc = f".1.3.6.1.2.1.31.1.1.1.6.{vpn_idx}"  # ifHCInOctets (64-bit)
            vpn_out_oid_hc = f".1.3.6.1.2.1.31.1.1.1.10.{vpn_idx}"  # ifHCOutOctets (64-bit)
            vpn_in_oid_32 = f".1.3.6.1.2.1.2.2.1.10.{vpn_idx}"  # ifInOctets (32-bit fallback)
            vpn_out_oid_32 = f".1.3.6.1.2.1.2.2.1.16.{vpn_idx}"  # ifOutOctets (32-bit fallback)
            vpn_status_oid = f".1.3.6.1.2.1.2.2.1.8.{vpn_idx}"  # ifOperStatus
            vpn_speed_oid = f".1.3.6.1.2.1.31.1.1.1.15.{vpn_idx}"  # ifHighSpeed
            
            # Try 64-bit counters first
            try:
                cmd = f"snmpget -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} {vpn_in_oid_hc} {vpn_out_oid_hc} {vpn_status_oid} {vpn_speed_oid}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, timeout=3, text=True)
                values = output.strip().split("\n")
                if len(values) >= 4 and "No Such" not in output:
                    use_64bit = True
                else:
                    raise ValueError("64-bit counters not available")
            except:
                # Fallback to 32-bit counters
                cmd = f"snmpget -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} {vpn_in_oid_32} {vpn_out_oid_32} {vpn_status_oid} {vpn_speed_oid}"
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, timeout=3, text=True)
                values = output.strip().split("\n")
                use_64bit = False
            
            if len(values) >= 4:
                # Parse values: strip quotes, handle Counter64: prefix, convert to int
                def parse_counter(val):
                    val = val.strip().strip('"')
                    if "Counter64:" in val:
                        val = val.split(":")[-1].strip()
                    elif "Counter32:" in val:
                        val = val.split(":")[-1].strip()
                    return int(val) if val else 0
                
                vpn_in = parse_counter(values[0])
                vpn_out = parse_counter(values[1])
                vpn_status_raw = int(values[2].strip().strip('"'))
                vpn_speed = int(values[3].strip().strip('"')) if values[3].strip().strip('"') else None
                
                # Calculate rates (similar to WAN/LAN)
                # Import state at the top level to ensure it's accessible
                import app.core.state as state
                prev_in_key = f"{vpn_name}_in"
                prev_out_key = f"{vpn_name}_out"
                prev_ts_key = f"{vpn_name}_ts"
                
                # Get previous values BEFORE storing new ones
                prev_in = state._snmp_prev_sample.get(prev_in_key)
                prev_out = state._snmp_prev_sample.get(prev_out_key)
                prev_ts = state._snmp_prev_sample.get(prev_ts_key, 0)
                now = time.time()
                from app.config import SNMP_POLL_INTERVAL
                # Use VPN-specific timestamp for accurate delta calculation
                dt = max(1.0, now - prev_ts) if prev_ts > 0 else SNMP_POLL_INTERVAL
                
                # Calculate RX/TX rates
                vpn_rx_mbps = None
                vpn_tx_mbps = None
                
                # Calculate rates if we have previous values
                if prev_in is not None and prev_out is not None and dt > 0:
                    d_in = vpn_in - prev_in
                    d_out = vpn_out - prev_out
                    if d_in >= 0 and d_out >= 0:  # No counter wrap
                        vpn_rx_mbps = round((d_in * 8) / (dt * 1_000_000), 2)  # bytes -> Mbps
                        vpn_tx_mbps = round((d_out * 8) / (dt * 1_000_000), 2)
                
                # Always store current values AFTER calculating rates (for next poll)
                state._snmp_prev_sample[prev_in_key] = vpn_in
                state._snmp_prev_sample[prev_out_key] = vpn_out
                state._snmp_prev_sample[prev_ts_key] = now  # Store VPN-specific timestamp
                
                # Calculate rates if we have previous values
                # Debug logging
                from app.config import DEBUG_MODE
                if DEBUG_MODE:
                    print(f"VPN {vpn_name}: prev_in={prev_in}, prev_out={prev_out}, prev_ts={prev_ts}, dt={dt}")
                    print(f"VPN {vpn_name}: curr_in={vpn_in}, curr_out={vpn_out}, now={now}")
                
                if prev_in is not None and prev_out is not None and dt > 0:
                    d_in = vpn_in - prev_in
                    d_out = vpn_out - prev_out
                    if DEBUG_MODE:
                        print(f"VPN {vpn_name}: d_in={d_in}, d_out={d_out}, dt={dt}")
                    if d_in >= 0 and d_out >= 0:  # No counter wrap
                        vpn_rx_mbps = round((d_in * 8) / (dt * 1_000_000), 2)  # bytes -> Mbps
                        vpn_tx_mbps = round((d_out * 8) / (dt * 1_000_000), 2)
                        if DEBUG_MODE:
                            print(f"VPN {vpn_name}: Calculated rates: rx={vpn_rx_mbps}, tx={vpn_tx_mbps}")
                    else:
                        # Counter wrapped or reset - set rates to None
                        if DEBUG_MODE:
                            print(f"VPN {vpn_name}: Counter wrap detected (d_in={d_in}, d_out={d_out})")
                else:
                    # First poll or missing previous values - rates will be None until next poll
                    if DEBUG_MODE:
                        print(f"VPN {vpn_name}: First poll or missing prev values - prev_in={prev_in}, prev_out={prev_out}, dt={dt}")
                    # On first poll, we can't calculate rates yet, but we've stored the values for next time
                
                # Calculate utilization if speed is known
                vpn_util = None
                if vpn_speed and vpn_rx_mbps is not None and vpn_tx_mbps is not None:
                    total_mbps = vpn_rx_mbps + vpn_tx_mbps
                    vpn_util = round((total_mbps / vpn_speed) * 100, 1) if vpn_speed > 0 else None
                
                # Determine status
                vpn_has_traffic = (vpn_rx_mbps is not None and vpn_rx_mbps > 0) or (vpn_tx_mbps is not None and vpn_tx_mbps > 0)
                vpn_status = determine_interface_status(vpn_status_raw, None, vpn_has_traffic, has_sessions, data_age)
                
                # Add VPN interface
                interfaces.append({
                    "name": vpn_name.upper(),
                    "status": vpn_status,
                    "rx_mbps": vpn_rx_mbps,
                    "tx_mbps": vpn_tx_mbps,
                    "rx_errors": None,  # VPN interfaces typically don't have error counters
                    "tx_errors": None,
                    "rx_drops": None,
                    "tx_drops": None,
                    "utilization": vpn_util,
                    "speed_mbps": vpn_speed,
                    "saturation_hint": None
                })
        except Exception as e:
            # VPN interface polling failed - log the error for debugging
            import traceback
            print(f"VPN interface {vpn_name} (index {vpn_idx}) polling failed: {e}")
            print(traceback.format_exc())
            # Add interface with error state so user knows it was attempted
            interfaces.append({
                "name": vpn_name.upper(),
                "status": "unknown",
                "rx_mbps": None,
                "tx_mbps": None,
                "rx_errors": None,
                "tx_errors": None,
                "rx_drops": None,
                "tx_drops": None,
                "utilization": None,
                "speed_mbps": None,
                "saturation_hint": None,
                "utilization_history": []
            })
            pass
    
    # Calculate aggregate throughput (handle None values)
    total_throughput = sum([(i.get("rx_mbps") or 0) + (i.get("tx_mbps") or 0) for i in interfaces])
    
    # Correlate SNMP throughput with NetFlow traffic volume
    # Use 1h window to match typical SNMP polling cadence
    try:
        from app.services.netflow import get_common_nfdump_data
        from app.utils.helpers import get_time_range
        
        # Get NetFlow total bytes for last hour
        range_key = "1h"
        netflow_sources = get_common_nfdump_data("sources", range_key)
        netflow_total_bytes = sum(i.get("bytes", 0) for i in netflow_sources) if netflow_sources else 0
        
        # Calculate SNMP total bytes for same window (1 hour)
        # SNMP rates are in Mbps, convert to total bytes over 1 hour
        snmp_total_bytes = (total_throughput * 1_000_000 / 8) * 3600  # Mbps -> bytes/sec -> bytes/hour
        
        # Calculate correlation status
        # Allow 20% variance for accounting differences (headers, sampling, etc.)
        if netflow_total_bytes == 0 and snmp_total_bytes == 0:
            correlation_status = "aligned"
            correlation_hint = None
        elif netflow_total_bytes == 0:
            correlation_status = "interface_heavy"
            correlation_hint = "NetFlow shows no traffic"
        elif snmp_total_bytes == 0:
            correlation_status = "flow_heavy"
            correlation_hint = "SNMP shows no traffic"
        else:
            ratio = netflow_total_bytes / snmp_total_bytes if snmp_total_bytes > 0 else 0
            if 0.8 <= ratio <= 1.2:  # Within 20% variance
                correlation_status = "aligned"
                correlation_hint = None
            elif ratio > 1.2:
                correlation_status = "flow_heavy"
                correlation_hint = f"NetFlow {((ratio - 1) * 100):.0f}% higher"
            else:  # ratio < 0.8
                correlation_status = "interface_heavy"
                correlation_hint = f"SNMP {((1 - ratio) * 100):.0f}% higher"
    except Exception as e:
        # Fail gracefully - correlation is informational only
        correlation_status = "unknown"
        correlation_hint = None
        netflow_total_bytes = None
        snmp_total_bytes = None
    
    # Update interface utilization baselines and detect saturation risk
    import app.core.state as state
    import statistics
    from collections import deque
    
    for iface in interfaces:
        # Always initialize saturation_hint (even if None) so frontend can check for it
        iface["saturation_hint"] = None
        
        if iface.get("utilization") is not None and iface.get("utilization") >= 0:
            baseline_key = f"{iface['name'].lower()}_utilization"
            with state._baselines_lock:
                # Initialize baseline deque if it doesn't exist
                if baseline_key not in state._baselines:
                    state._baselines[baseline_key] = deque(maxlen=100)
                    state._baselines_last_update[baseline_key] = time.time()
                
                # Add current utilization to baseline window
                state._baselines[baseline_key].append(iface["utilization"])
                state._baselines_last_update[baseline_key] = time.time()
                
                # Calculate saturation risk (sustained high utilization vs baseline)
                baseline_window = list(state._baselines[baseline_key])
                current_util = iface["utilization"]
                
                # Add utilization history for sparkline (last 30 samples, ~1-2 hours at typical polling)
                # Limit to reasonable size for frontend rendering
                if len(baseline_window) > 0:
                    # Take last 30 samples for sparkline visualization
                    iface["utilization_history"] = baseline_window[-30:] if len(baseline_window) >= 30 else baseline_window
                else:
                    iface["utilization_history"] = []
                
                if len(baseline_window) >= 10:  # Need at least 10 samples for meaningful baseline
                    baseline_mean = statistics.mean(baseline_window)
                    baseline_std = statistics.stdev(baseline_window) if len(baseline_window) > 1 else 0
                    
                    # Check for sustained high utilization
                    # Risk if: current > 70% AND (current significantly above baseline OR consistently high)
                    recent_samples = baseline_window[-5:] if len(baseline_window) >= 5 else baseline_window
                    
                    # More lenient conditions: either significantly above baseline OR consistently high
                    is_significantly_above = current_util > baseline_mean + (1.5 * baseline_std) if baseline_std > 0 else False
                    is_consistently_high = (
                        current_util > 70 and  # Absolute threshold: >70% utilization
                        all(s > 60 for s in recent_samples)  # Last 5 samples all > 60%
                    )
                    
                    is_sustained_high = is_significantly_above or is_consistently_high
                    
                    if is_sustained_high:
                        # Calculate risk level (subtle, non-alarming)
                        deviation = current_util - baseline_mean
                        if current_util > 85 or deviation > 25:
                            iface["saturation_hint"] = "High utilization"
                        elif current_util > 75 or deviation > 15:
                            iface["saturation_hint"] = "Elevated utilization"
                elif len(baseline_window) >= 5:
                    # With fewer samples, use simpler threshold: show hint if utilization > 75%
                    if current_util is not None and current_util > 75:
                        iface["saturation_hint"] = "Elevated utilization"
    
    # Format response
    response = {
        "cpu_percent": snmp_data.get("cpu_percent", 0),
        "memory_percent": snmp_data.get("mem_percent", 0),
        "active_sessions": snmp_data.get("tcp_conns", 0),
        "total_throughput_mbps": round(total_throughput, 2),
        "uptime_formatted": snmp_data.get("sys_uptime_formatted", "Unknown"),
        "uptime_seconds": snmp_data.get("sys_uptime", 0),
        "interfaces": interfaces,
        "last_poll": time.time(),
        "poll_success": True,
        "traffic_correlation": {
            "status": correlation_status,
            "hint": correlation_hint,
            "snmp_bytes_1h": int(snmp_total_bytes) if snmp_total_bytes is not None else None,
            "netflow_bytes_1h": int(netflow_total_bytes) if netflow_total_bytes is not None else None
        }
    }
    
    return jsonify(response)


# ===== SNMP Integration =====

# SNMP Configuration (override with env vars)
SNMP_HOST = os.getenv("SNMP_HOST", "192.168.0.1")
SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "Phoboshomesnmp_3")

# SNMP OIDs
SNMP_OIDS = {
    "cpu_load_1min": ".1.3.6.1.4.1.2021.10.1.3.1",
    "cpu_load_5min": ".1.3.6.1.4.1.2021.10.1.3.2",
    "mem_total": ".1.3.6.1.4.1.2021.4.5.0",        # Total RAM KB
    "mem_avail": ".1.3.6.1.4.1.2021.4.6.0",        # Available RAM KB
    "mem_buffer": ".1.3.6.1.4.1.2021.4.11.0",       # Buffer memory KB
    "mem_cached": ".1.3.6.1.4.1.2021.4.15.0",       # Cached memory KB
    # Swap
    "swap_total": ".1.3.6.1.4.1.2021.4.3.0",       # Total swap KB
    "swap_avail": ".1.3.6.1.4.1.2021.4.4.0",       # Available swap KB
    "sys_uptime": ".1.3.6.1.2.1.1.3.0",            # Uptime timeticks
    "tcp_conns": ".1.3.6.1.2.1.6.9.0",             # tcpCurrEstab
    "tcp_active_opens": ".1.3.6.1.2.1.6.5.0",      # tcpActiveOpens
    "tcp_estab_resets": ".1.3.6.1.2.1.6.8.0",      # tcpEstabResets
    "proc_count": ".1.3.6.1.2.1.25.1.6.0",         # hrSystemProcesses
    "if_wan_status": ".1.3.6.1.2.1.2.2.1.8.1",     # igc0 status
    "if_lan_status": ".1.3.6.1.2.1.2.2.1.8.2",     # igc1 status
    "tcp_fails": ".1.3.6.1.2.1.6.7.0",             # tcpAttemptFails
    "tcp_retrans": ".1.3.6.1.2.1.6.12.0",          # tcpRetransSegs
    # IP stack
    "ip_in_discards": ".1.3.6.1.2.1.4.8.0",        # ipInDiscards
    "ip_in_hdr_errors": ".1.3.6.1.2.1.4.4.0",      # ipInHdrErrors
    "ip_in_addr_errors": ".1.3.6.1.2.1.4.5.0",     # ipInAddrErrors
    "ip_forw_datagrams": ".1.3.6.1.2.1.4.6.0",     # ipForwDatagrams
    "ip_in_delivers": ".1.3.6.1.2.1.4.9.0",        # ipInDelivers
    "ip_out_requests": ".1.3.6.1.2.1.4.10.0",      # ipOutRequests
    # ICMP
    "icmp_in_errors": ".1.3.6.1.2.1.5.2.0",        # icmpInErrors
    "wan_in": ".1.3.6.1.2.1.31.1.1.1.6.1",         # igc0 in
    "wan_out": ".1.3.6.1.2.1.31.1.1.1.10.1",       # igc0 out
    "lan_in": ".1.3.6.1.2.1.31.1.1.1.6.2",         # igc1 in
    "lan_out": ".1.3.6.1.2.1.31.1.1.1.10.2",       # igc1 out
    # Interface speeds (Mbps)
    "wan_speed": ".1.3.6.1.2.1.31.1.1.1.15.1",     # ifHighSpeed WAN
    "lan_speed": ".1.3.6.1.2.1.31.1.1.1.15.2",     # ifHighSpeed LAN
    # Interface errors/discards (32-bit but fine for error counters)
    "wan_in_err": ".1.3.6.1.2.1.2.2.1.14.1",
    "wan_out_err": ".1.3.6.1.2.1.2.2.1.20.1",
    "wan_in_disc": ".1.3.6.1.2.1.2.2.1.13.1",
    "wan_out_disc": ".1.3.6.1.2.1.2.2.1.19.1",
    "lan_in_err": ".1.3.6.1.2.1.2.2.1.14.2",
    "lan_out_err": ".1.3.6.1.2.1.2.2.1.20.2",
    "lan_in_disc": ".1.3.6.1.2.1.2.2.1.13.2",
    "lan_out_disc": ".1.3.6.1.2.1.2.2.1.19.2",
    "disk_read": ".1.3.6.1.4.1.2021.13.15.1.1.12.2", # nda0 read bytes
    "disk_write": ".1.3.6.1.4.1.2021.13.15.1.1.13.2", # nda0 write bytes
    "udp_in": ".1.3.6.1.2.1.7.1.0",                # udpInDatagrams
    "udp_out": ".1.3.6.1.2.1.7.4.0",               # udpOutDatagrams
}

_snmp_cache = {"data": None, "ts": 0}
_snmp_cache_lock = threading.Lock()
_snmp_prev_sample = {"ts": 0, "wan_in": 0, "wan_out": 0, "lan_in": 0, "lan_out": 0}

# Real-time SNMP polling controls
SNMP_POLL_INTERVAL = float(os.getenv("SNMP_POLL_INTERVAL", "2"))  # seconds
SNMP_CACHE_TTL = float(os.getenv("SNMP_CACHE_TTL", str(max(1.0, SNMP_POLL_INTERVAL))))
_snmp_thread_started = False

# SNMP exponential backoff state
_snmp_backoff = {
    "failures": 0,
    "max_failures": 5,
    "base_delay": 2,  # seconds
    "max_delay": 60,  # max backoff delay
    "last_failure": 0
}



@bp.route("/api/stats/firewall")
@throttle(5, 10)
def api_stats_firewall():
    """Firewall health stats from SNMP + syslog block data"""
    start_snmp_thread()
    snmp_data = get_snmp_data()

    # Add syslog block stats
    fw_stats = _get_firewall_block_stats(hours=1)

    # Merge syslog data into response
    if snmp_data:
        snmp_data['blocks_1h'] = fw_stats.get('blocks', 0)
        snmp_data['blocks_per_hour'] = fw_stats.get('blocks_per_hour', 0)
        snmp_data['unique_blocked_ips'] = fw_stats.get('unique_ips', 0)
        snmp_data['threats_blocked'] = fw_stats.get('threats_blocked', 0)
        with _syslog_stats_lock:
            snmp_data['syslog_active'] = _syslog_stats.get('parsed', 0) > 0
            snmp_data['syslog_stats'] = dict(_syslog_stats)

    return jsonify({"firewall": snmp_data})



@bp.route("/api/stats/firewall/stream")
def api_stats_firewall_stream():
    """Server-Sent Events stream for near real-time firewall stats."""
    start_snmp_thread()

    def event_stream():
        last_ts = 0
        while not _shutdown_event.is_set():
            with _snmp_cache_lock:
                data = _snmp_cache.get("data")
                ts = _snmp_cache.get("ts", 0)
            if ts and ts != last_ts and data is not None:
                # Merge syslog stats into SSE payload
                merged = dict(data) if data else {}
                fw_stats = _get_firewall_block_stats(hours=1)
                merged['blocks_1h'] = fw_stats.get('blocks', 0)
                merged['blocks_per_hour'] = fw_stats.get('blocks_per_hour', 0)
                merged['unique_blocked_ips'] = fw_stats.get('unique_ips', 0)
                merged['threats_blocked'] = fw_stats.get('threats_blocked', 0)
                with _syslog_stats_lock:
                    merged['syslog_active'] = _syslog_stats.get('parsed', 0) > 0
                    merged['syslog_stats'] = dict(_syslog_stats)
                payload = json.dumps({"firewall": merged})
                yield f"data: {payload}\n\n"
                last_ts = ts
            _shutdown_event.wait(timeout=max(0.2, SNMP_POLL_INTERVAL / 2.0))

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


@bp.route("/api/stats/blocklist_rate")
@throttle(5, 10)
def api_stats_blocklist_rate():
    """Blocklist match rate statistics (sparkline data)."""
    range_key = request.args.get('range', '1h')
    now = time.time()

    # Check if we have threat data
    threat_set = load_threatlist()
    threat_count = len(threat_set)

    # Determine bucket interval based on range
    # Target approx 15-20 buckets
    # 1h = 3600s / 15 = ~240s (4 min)
    range_seconds = {'15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '24h': 86400}.get(range_key, 3600)
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
        header = lines[0].split(',')
        try:
            ts_idx = header.index('ts')
            sa_idx = header.index('sa')
            da_idx = header.index('da')
        except:
            ts_idx, sa_idx, da_idx = 0, 3, 4

        for line in lines[1:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
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
                            ts_clean = ts_str.split('.')[0]
                            dt = datetime.strptime(ts_clean, '%Y-%m-%d %H:%M:%S')
                            ts_val = dt.timestamp()

                            if ts_val >= start_ts:
                                b_idx = int((ts_val - start_ts) // bucket_size)
                                if b_idx in buckets:
                                    buckets[b_idx] += 1
                        except:
                            # Fallback if parsing fails: ignore time distribution
                            pass
                except: pass

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
            cur.execute("""
                SELECT timestamp, COUNT(*) as cnt
                FROM fw_logs
                WHERE action = 'block' AND timestamp >= ?
                GROUP BY CAST(timestamp / ? AS INTEGER)
                ORDER BY timestamp
            """, (cutoff, bucket_size))

            for row in cur.fetchall():
                ts_val = row[0]
                cnt = row[1]
                total_blocked += cnt
                b_idx = int((ts_val - start_ts) // bucket_size)
                if 0 <= b_idx < len(series):
                    series[b_idx]['blocked'] = series[b_idx].get('blocked', 0) + cnt
            conn.close()
    except:
        pass

    return jsonify({
        "series": series,
        "current_rate": current_rate,
        "total_matches": total_matches,
        "total_blocked": total_blocked,
        "threat_count": threat_count,
        "has_fw_data": total_blocked > 0
    })


@bp.route("/api/stats/batch", methods=['POST'])
@throttle(10, 20)
def api_stats_batch():
    """Batch endpoint: accepts list of endpoint names, returns combined response."""
    try:
        data = request.get_json(force=True, silent=True) or {}
        requests_list = data.get('requests', [])
        range_key = request.args.get('range', '1h')

        if not requests_list:
            return jsonify({'error': 'No requests provided'}), 400

        results = {}
        errors = {}

        # Map endpoint names to handler functions
        handlers = {
            'summary': api_stats_summary,
            'sources': api_stats_sources,
            'destinations': api_stats_destinations,
            'ports': api_stats_ports,
            'protocols': api_stats_protocols,
            'bandwidth': api_bandwidth,
            'threats': api_threats,
            'alerts': api_alerts,
            'firewall': api_stats_firewall,
        }

        # Process each request using test_request_context with proper query string
        for req in requests_list:
            endpoint_name = req.get('endpoint')
            if not endpoint_name or endpoint_name not in handlers:
                if endpoint_name:
                    errors[endpoint_name] = 'Unknown endpoint'
                continue

            params = req.get('params', {})
            if 'range' not in params:
                params['range'] = range_key

            # Build query string for test_request_context
            from urllib.parse import urlencode
            query_string = urlencode(params)

            # Create test request context with query string
            with current_app.test_request_context(query_string=query_string):
                try:
                    handler = handlers[endpoint_name]
                    # Call handler and extract JSON from Response
                    response = handler()
                    if hasattr(response, 'get_json'):
                        result = response.get_json()
                    elif hasattr(response, 'json'):
                        result = response.json
                    else:
                        result = None

                    if result:
                        results[endpoint_name] = result
                except Exception as e:
                    errors[endpoint_name] = str(e)

        response_data = {'results': results}
        if errors:
            response_data['errors'] = errors

        return jsonify(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# Performance metrics endpoint

@bp.route("/api/performance/metrics")
@throttle(10, 60)
def api_performance_metrics():
    """Get performance metrics including observability data."""
    from app.utils.observability import check_cache_miss_rate
    
    # Check cache miss rate guardrail (triggers warning if threshold exceeded)
    check_cache_miss_rate()
    
    metrics = get_performance_metrics()

    # Calculate statistics
    avg_response_time = 0.0
    if metrics['request_count'] > 0:
        avg_response_time = metrics['total_response_time'] / metrics['request_count']

    # Calculate per-endpoint statistics
    endpoint_stats = {}
    for endpoint, times in metrics['endpoint_times'].items():
        if times:
            endpoint_stats[endpoint] = {
                'count': len(times),
                'avg_ms': round(sum(times) / len(times) * 1000, 2),
                'min_ms': round(min(times) * 1000, 2),
                'max_ms': round(max(times) * 1000, 2),
                'p95_ms': round(sorted(times)[int(len(times) * 0.95)] * 1000, 2) if len(times) > 1 else round(times[0] * 1000, 2)
            }

    cache_hit_rate = 0.0
    total_cache_requests = metrics['cache_hits'] + metrics['cache_misses']
    if total_cache_requests > 0:
        cache_hit_rate = metrics['cache_hits'] / total_cache_requests * 100

    error_rate = 0.0
    if metrics['request_count'] > 0:
        error_rate = metrics['error_count'] / metrics['request_count'] * 100
    
    # OBSERVABILITY: Subprocess metrics
    subprocess_stats = {}
    if metrics.get('subprocess_calls', 0) > 0:
        avg_subprocess_time = metrics['subprocess_total_time'] / metrics['subprocess_calls']
        subprocess_times = metrics.get('subprocess_times', [])
        subprocess_stats = {
            'total_calls': metrics['subprocess_calls'],
            'success_count': metrics.get('subprocess_success', 0),
            'failure_count': metrics.get('subprocess_failures', 0),
            'timeout_count': metrics.get('subprocess_timeouts', 0),
            'avg_ms': round(avg_subprocess_time * 1000, 2),
            'max_ms': round(max(subprocess_times) * 1000, 2) if subprocess_times else 0,
            'p95_ms': round(sorted(subprocess_times)[int(len(subprocess_times) * 0.95)] * 1000, 2) if len(subprocess_times) > 1 else (round(subprocess_times[0] * 1000, 2) if subprocess_times else 0),
            'success_rate_percent': round(metrics.get('subprocess_success', 0) / metrics['subprocess_calls'] * 100, 2)
        }
    
    # OBSERVABILITY: Service function metrics
    service_stats = {}
    for service_name, times in metrics.get('service_times', {}).items():
        if times:
            calls = metrics['service_calls'].get(service_name, 0)
            total_time = metrics['service_total_time'].get(service_name, 0.0)
            service_stats[service_name] = {
                'call_count': calls,
                'avg_ms': round((total_time / calls) * 1000, 2) if calls > 0 else 0,
                'total_time_ms': round(total_time * 1000, 2),
                'min_ms': round(min(times) * 1000, 2),
                'max_ms': round(max(times) * 1000, 2),
                'p95_ms': round(sorted(times)[int(len(times) * 0.95)] * 1000, 2) if len(times) > 1 else round(times[0] * 1000, 2)
            }

    return jsonify({
        'summary': {
            'total_requests': metrics['request_count'],
            'avg_response_time_ms': round(avg_response_time * 1000, 2),
            'error_count': metrics['error_count'],
            'error_rate_percent': round(error_rate, 2),
            'cache_hit_rate_percent': round(cache_hit_rate, 2),
            'cache_hits': metrics['cache_hits'],
            'cache_misses': metrics['cache_misses'],
            'slow_requests': metrics.get('slow_requests', 0)
        },
        'endpoints': endpoint_stats,
        'subprocess': subprocess_stats,
        'services': service_stats
    })


