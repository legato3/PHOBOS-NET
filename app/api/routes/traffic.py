from . import bp
"""Flask routes for PHOBOS-NET application.

This module contains all API routes extracted from netflow-dashboard.py.
Routes are organized in a single Flask Blueprint.
"""
from flask import Blueprint, render_template, jsonify, request, Response, stream_with_context, current_app
import time
import os
import json
import socket
import threading
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor
import sqlite3

# Import from service modules (already extracted)
from app.services.netflow.netflow import get_common_nfdump_data, run_nfdump, parse_csv, get_traffic_direction
from app.services.security.threats import (
    fetch_threat_feed, get_threat_info, update_threat_timeline, get_threat_timeline,
    load_watchlist, add_to_watchlist, remove_from_watchlist,
    detect_anomalies, run_all_detections,
    load_threatlist, get_feed_label, send_notifications,
    lookup_threat_intelligence, detect_ip_anomalies, generate_ip_anomaly_alerts,
    add_health_alert_to_history
)
from app.services.netflow.stats import calculate_security_score
from app.services.shared.metrics import track_performance, track_error, get_performance_metrics, get_performance_lock
from app.services.shared.snmp import get_snmp_data, start_snmp_thread
from app.services.shared.cpu import calculate_cpu_percent_from_stat
from app.core.background import start_threat_thread, start_trends_thread, start_agg_thread
from app.services.shared.helpers import is_internal, get_region, fmt_bytes, get_time_range, flag_from_iso, load_list, check_disk_space, format_duration
from app.core.app_state import (
    _shutdown_event,
    _lock_summary, _lock_sources, _lock_dests, _lock_ports, _lock_protocols,
    _lock_alerts, _lock_flags, _lock_asns, _lock_durations, _lock_bandwidth,
    _lock_flows, _lock_countries, _lock_worldmap,
    _lock_proto_hierarchy, _lock_noise, _lock_service_cache,
    _cache_lock, _mock_lock,
    _throttle_lock, _common_data_lock, _cpu_stat_lock,
    _stats_summary_cache, _stats_sources_cache, _stats_dests_cache,
    _stats_ports_cache, _stats_protocols_cache, _stats_alerts_cache,
    _stats_flags_cache, _stats_asns_cache, _stats_durations_cache,
    _stats_pkts_cache, _stats_countries_cache, _stats_talkers_cache,
    _stats_services_cache, _stats_hourly_cache, _stats_flow_stats_cache,
    _stats_proto_mix_cache, _stats_net_health_cache,
    _stats_proto_hierarchy_cache, _stats_noise_metrics_cache,
    _server_health_cache,
    _mock_data_cache, _bandwidth_cache, _bandwidth_history_cache,
    _flows_cache, _common_data_cache, _service_cache,
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
    _dns_resolver_executor, _rollup_executor,
    _flow_history, _flow_history_lock, _flow_history_ttl,
    _app_log_buffer, _app_log_buffer_lock, add_app_log,
)
# Import threats module to access threat state
import app.services.security.threats as threats_module
import app.core.app_state as state
from app.services.shared.config_helpers import load_notify_cfg, save_notify_cfg, load_thresholds, save_thresholds, load_config, save_config
from app.services.shared.formatters import format_time_ago, format_uptime
from app.services.shared.geoip import lookup_geo, load_city_db
import app.services.shared.geoip as geoip_module
from app.services.shared.dns import resolve_ip
import app.services.shared.dns as dns_module
from app.services.shared.decorators import throttle, cached_endpoint
from app.db.sqlite import _get_firewall_block_stats, _firewall_db_connect, _firewall_db_init, _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket, _trends_db_lock, _firewall_db_lock, _trends_db_connect
from app.config import (
    FIREWALL_DB_PATH, TRENDS_DB_PATH, PORTS, PROTOS, SUSPICIOUS_PORTS,
    NOTIFY_CFG_PATH, THRESHOLDS_CFG_PATH, CONFIG_PATH, THREAT_WHITELIST,
    LONG_LOW_DURATION_THRESHOLD, LONG_LOW_BYTES_THRESHOLD
)

# Create Blueprint

# Routes extracted from netflow-dashboard.py
# Changed @app.route() to @bp.route()

@bp.route("/api/stats/sources")
@throttle(5, 10)
@cached_endpoint(_stats_sources_cache, _lock_sources, key_params=['range', 'limit'])
def api_stats_sources():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except (ValueError, TypeError):
        limit = 10

    full_sources = get_common_nfdump_data("sources", range_key)
    sources = full_sources[:limit]

    for i in sources:
        i["hostname"] = resolve_ip(i["key"])
        i["internal"] = is_internal(i["key"])
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        geo = lookup_geo(i["key"])
        if geo:
            i.update({"country": geo.get("country"), "country_iso": geo.get("country_iso"), "flag": geo.get("flag"), "city": geo.get("city"), "asn": geo.get("asn"), "asn_org": geo.get("asn_org")})
        i["region"] = get_region(i["key"], i.get("country_iso"))
        i["threat"] = False

    return {"sources": sources}



@bp.route("/api/stats/destinations")
@throttle(5, 10)
@cached_endpoint(_stats_dests_cache, _lock_dests, key_params=['range', 'limit'])
def api_stats_destinations():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except (ValueError, TypeError):
        limit = 10

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

    return {"destinations": dests}



@bp.route("/api/stats/ports")
@throttle(5, 10)
@cached_endpoint(_stats_ports_cache, _lock_ports, key_params=['range', 'limit'])
def api_stats_ports():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except (ValueError, TypeError):
        limit = 10

    full_ports = get_common_nfdump_data("ports", range_key)
    ports = full_ports[:limit]

    for i in ports:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            port = int(i["key"])
            i["service"] = PORTS.get(port, "Unknown")
            i["suspicious"] = port in SUSPICIOUS_PORTS
        except (ValueError, TypeError):
            i["service"] = "Unknown"
            i["suspicious"] = False

    return {"ports": ports}


@bp.route("/api/stats/protocols")
@throttle(5, 10)
@cached_endpoint(_stats_protocols_cache, _lock_protocols, key_params=['range'])
def api_stats_protocols():
    range_key = request.args.get('range', '1h')

    protos_raw = get_common_nfdump_data("protos", range_key)[:10]

    for i in protos_raw:
        i["bytes_fmt"] = fmt_bytes(i["bytes"])
        try:
            proto = int(i["key"]) if i["key"].isdigit() else 0
            i["proto_name"] = PROTOS.get(proto, i["key"])
        except (ValueError, TypeError):
            i["proto_name"] = i["key"]

    return {"protocols": protos_raw}


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

    rows = []
    try:
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({"flags": []})
            
        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Identify 'flg' column index
        try:
            header_norm = [h.lower().strip() for h in header]
            if 'flg' in header_norm:
                flg_idx = header_norm.index('flg')
            elif 'flags' in header_norm:
                flg_idx = header_norm.index('flags')
            else:
                # Version-based fallback
                flg_idx = 8 if 'firstseen' not in header_norm else -1 # 1.7+ might not have flags in default CSV
        except (ValueError, IndexError):
             flg_idx = -1

        if flg_idx != -1:
            for line in lines[start_idx:]:
                line = line.strip()
                if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
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
@cached_endpoint(_stats_asns_cache, _lock_asns, key_params=['range'])
def api_stats_asns():
    range_key = request.args.get('range', '1h')
    sources = get_common_nfdump_data("sources", range_key)

    asn_counts = Counter()
    for i in sources:
        geo = lookup_geo(i["key"])
        org = geo.get('asn_org', 'Unknown') if geo else 'Unknown'
        if org == 'Unknown' and is_internal(i["key"]):
            org = "Internal Network"
        asn_counts[org] += i["bytes"]

    top = [{"asn": k, "bytes": v, "bytes_fmt": fmt_bytes(v)} for k, v in asn_counts.most_common(10)]
    return {"asns": top}


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

    output = run_nfdump(["-O", "duration", "-n", "100"], tf) # Get top flows by duration

    try:
        rows = []
        lines = output.strip().split("\n")
        if not lines:
             return jsonify({
                 "durations": [],
                 "stats": {
                     "avg_duration": 0,
                     "avg_duration_fmt": "0s",
                     "total_flows": 0,
                     "total_bytes": 0,
                     "total_bytes_fmt": "0 B",
                     "max_duration": 0,
                     "max_duration_fmt": "0s"
                 }
             })

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Normalize header for easier matching
        header_norm = [h.lower().strip() for h in header]
        try:
            # Robust mapping for source/destination addresses and other fields
            if 'sa' in header_norm:
                sa_idx = header_norm.index('sa')
            elif 'srcaddr' in header_norm:
                sa_idx = header_norm.index('srcaddr')
            
            if 'da' in header_norm:
                da_idx = header_norm.index('da')
            elif 'dstaddr' in header_norm:
                da_idx = header_norm.index('dstaddr')
            
            if 'proto' in header_norm:
                pr_idx = header_norm.index('proto')
            elif 'pr' in header_norm:
                pr_idx = header_norm.index('pr')
            
            if 'td' in header_norm:
                td_idx = header_norm.index('td')
            elif 'duration' in header_norm:
                td_idx = header_norm.index('duration')

            if 'ibyt' in header_norm:
                ibyt_idx = header_norm.index('ibyt')
            elif 'bytes' in header_norm:
                ibyt_idx = header_norm.index('bytes')
            elif 'byt' in header_norm:
                ibyt_idx = header_norm.index('byt')
        except ValueError:
            # Last resort fallbacks based on version hints
            if 'firstseen' in header_norm:
                 sa_idx, da_idx, pr_idx, td_idx, ibyt_idx = 3, 5, 2, 1, 8
            else:
                 sa_idx, da_idx, pr_idx, td_idx, ibyt_idx = 3, 4, 7, 2, 12

        seen_flows = set()  # Deduplicate flows
        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(sa_idx, da_idx, td_idx, pr_idx):
                try:
                    src_ip = parts[sa_idx].strip()
                    dst_ip = parts[da_idx].strip()
                    
                    # Skip IPv6 addresses (contain ':') - only show IPv4
                    if ':' in src_ip or ':' in dst_ip:
                        continue
                    
                    # Create unique key for deduplication
                    flow_key = (src_ip, dst_ip, parts[pr_idx].strip(), parts[td_idx].strip())
                    if flow_key in seen_flows: continue
                    seen_flows.add(flow_key)

                    rows.append({
                        "src": src_ip, "dst": dst_ip,
                        "proto": parts[pr_idx].strip(),
                        "duration": float(parts[td_idx]),
                        "bytes": int(float(parts[ibyt_idx])) if len(parts) > ibyt_idx else 0
                    })
                except (ValueError, IndexError, KeyError):
                    pass

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
    # Indices mapping for packet size distribution (defaults)
    ipkt_idx, ibyt_idx = 7, 8

    try:
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({"labels":[], "data":[]})

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback check
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices
        header_norm = [h.lower().strip() for h in header]
        try:
            ibyt_idx = header_norm.index('ibyt') if 'ibyt' in header_norm else (header_norm.index('bytes') if 'bytes' in header_norm else 8)
            ipkt_idx = header_norm.index('ipkt') if 'ipkt' in header_norm else (header_norm.index('packets') if 'packets' in header_norm else 7)
        except ValueError:
            pass

        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(ibyt_idx, ipkt_idx):
                try:
                    b = int(float(parts[ibyt_idx]))
                    p = int(float(parts[ipkt_idx]))
                    if p > 0:
                        avg = b / p
                        if avg < 64: dist["Tiny (<64B)"] += 1
                        elif avg < 512: dist["Small (64-511B)"] += 1
                        elif avg < 1024: dist["Medium (512-1023B)"] += 1
                        elif avg <= 1514: dist["Large (1024-1513B)"] += 1
                        else: dist["Jumbo (>1513B)"] += 1
                except (ValueError, IndexError, KeyError, ZeroDivisionError):
                    pass

        data = {
            "labels": list(dist.keys()),
            "data": list(dist.values())
        }
        with _cache_lock:
            _stats_pkts_cache["data"] = data
            _stats_pkts_cache["ts"] = now
            _stats_pkts_cache["key"] = range_key
        return jsonify(data)
    except (ValueError, IndexError, KeyError, TypeError, ZeroDivisionError):
        return jsonify({"labels":[], "data":[]})



@bp.route("/api/stats/countries")
@throttle(5, 10)
@cached_endpoint(_stats_countries_cache, _lock_countries, key_params=['range'])
def api_stats_countries():
    """Top countries by bytes using top sources and destinations."""
    range_key = request.args.get('range', '1h')

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

    sorted_countries = sorted(country_bytes.values(), key=lambda x: x["bytes"], reverse=True)
    top = sorted_countries[:15]

    labels = [f"{c['name']} ({c['iso']})" if c['iso'] != '??' else 'Unknown' for c in top]
    bytes_vals = [c['bytes'] for c in top]

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

    return {
        "labels": labels,
        "bytes": bytes_vals,
        "bytes_fmt": [fmt_bytes(v) for v in bytes_vals],
        "map_data": map_data,
        "total_bytes": total_bytes,
        "total_bytes_fmt": fmt_bytes(total_bytes),
        "country_count": len([c for c in sorted_countries if c['iso'] != '??'])
    }


@bp.route("/api/stats/worldmap")
@throttle(5, 10)
def api_stats_worldmap():
    """World map data endpoint with geo-located sources, destinations, and threats."""
    range_key = request.args.get('range', '1h')

    # Get source and destination data
    sources_raw = get_common_nfdump_data("sources", range_key)[:100]
    dests_raw = get_common_nfdump_data("dests", range_key)[:100]

    # Build sources with geo data
    sources = []
    source_countries = {}
    for item in sources_raw:
        ip = item.get("key")
        if not ip or is_internal(ip):
            continue
        b = item.get("bytes", 0)
        geo = lookup_geo(ip) or {}
        lat = geo.get('lat')
        lng = geo.get('lng')
        iso = geo.get('country_iso') or '??'
        country = geo.get('country') or 'Unknown'
        if lat and lng:
            sources.append({
                "ip": ip,
                "lat": lat,
                "lng": lng,
                "bytes": b,
                "bytes_fmt": fmt_bytes(b),
                "country": country,
                "iso": iso
            })
        # Aggregate by country
        if iso != '??':
            if iso not in source_countries:
                source_countries[iso] = {"name": country, "iso": iso, "bytes": 0, "flows": 0}
            source_countries[iso]["bytes"] += b
            source_countries[iso]["flows"] += 1

    # Build destinations with geo data
    destinations = []
    dest_countries = {}
    for item in dests_raw:
        ip = item.get("key")
        if not ip or is_internal(ip):
            continue
        b = item.get("bytes", 0)
        geo = lookup_geo(ip) or {}
        lat = geo.get('lat')
        lng = geo.get('lng')
        iso = geo.get('country_iso') or '??'
        country = geo.get('country') or 'Unknown'
        if lat and lng:
            destinations.append({
                "ip": ip,
                "lat": lat,
                "lng": lng,
                "bytes": b,
                "bytes_fmt": fmt_bytes(b),
                "country": country,
                "iso": iso
            })
        # Aggregate by country
        if iso != '??':
            if iso not in dest_countries:
                dest_countries[iso] = {"name": country, "iso": iso, "bytes": 0, "flows": 0}
            dest_countries[iso]["bytes"] += b
            dest_countries[iso]["flows"] += 1

    # Get threat data from threat timeline (populated by firewall blocks and netflow detections)
    threats = []
    threat_countries = {}
    now = time.time()

    # Calculate cutoff based on selected range
    range_seconds = {'15m': 900, '30m': 1800, '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800}.get(range_key, 3600)
    cutoff = now - range_seconds

    try:
        for ip, timeline in threats_module._threat_timeline.items():
            if timeline.get('last_seen', 0) < cutoff:
                continue
            geo = lookup_geo(ip) or {}
            lat = geo.get('lat')
            lng = geo.get('lng')
            iso = geo.get('country_iso') or '??'
            country = geo.get('country') or 'Unknown'
            info = threats_module.get_threat_info(ip)
            if lat and lng:
                threats.append({
                    "ip": ip,
                    "lat": lat,
                    "lng": lng,
                    "feed": info.get('feed', 'unknown'),
                    "category": info.get('category', 'UNKNOWN'),
                    "hits": timeline.get('hit_count', 1),
                    "country": country,
                    "iso": iso
                })
            if iso != '??':
                if iso not in threat_countries:
                    threat_countries[iso] = {"name": country, "iso": iso, "count": 0}
                threat_countries[iso]["count"] += timeline.get('hit_count', 1)
    except Exception as e:
        print(f"Worldmap threat data error: {e}")

    # Get blocked IPs from firewall database
    blocked = []
    blocked_countries = {}
    try:
        from app.db.sqlite import get_top_blocked_sources
        blocked_sources = get_top_blocked_sources(limit=50)
        for item in blocked_sources:
            ip = item.get('src_ip')
            if not ip:
                continue
            geo = lookup_geo(ip) or {}
            lat = geo.get('lat')
            lng = geo.get('lng')
            iso = geo.get('country_iso') or '??'
            country = geo.get('country') or 'Unknown'
            if lat and lng:
                blocked.append({
                    "ip": ip,
                    "lat": lat,
                    "lng": lng,
                    "count": item.get('count', 1),
                    "country": country,
                    "iso": iso
                })
            if iso != '??':
                if iso not in blocked_countries:
                    blocked_countries[iso] = {"name": country, "iso": iso, "count": 0}
                blocked_countries[iso]["count"] += item.get('count', 1)
    except Exception as e:
        print(f"Worldmap blocked data error: {e}")

    # Sort country lists by bytes/count and add formatted values
    source_countries_list = sorted(source_countries.values(), key=lambda x: x['bytes'], reverse=True)
    for c in source_countries_list:
        c['bytes_fmt'] = fmt_bytes(c['bytes'])

    dest_countries_list = sorted(dest_countries.values(), key=lambda x: x['bytes'], reverse=True)
    for c in dest_countries_list:
        c['bytes_fmt'] = fmt_bytes(c['bytes'])

    threat_countries_list = sorted(threat_countries.values(), key=lambda x: x['count'], reverse=True)
    blocked_countries_list = sorted(blocked_countries.values(), key=lambda x: x['count'], reverse=True)

    return jsonify({
        "sources": sources,
        "destinations": destinations,
        "threats": threats,
        "blocked": blocked,
        "source_countries": source_countries_list,
        "dest_countries": dest_countries_list,
        "threat_countries": threat_countries_list,
        "blocked_countries": blocked_countries_list,
        "summary": {
            "total_sources": len(sources),
            "total_destinations": len(destinations),
            "total_threats": len(threats),
            "total_blocked": len(blocked),
            "source_country_count": len(source_countries),
            "dest_country_count": len(dest_countries)
        }
    })
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
    # Sort by bytes (already sorted by nfdump, but we limit)
    # nfdump -O bytes -n 50 returns top 50 flows sorted by bytes
    output = run_nfdump(["-O", "bytes", "-n", "50"], tf)

    flows = []
    # NFDump CSV indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx = 0, 1, 2, 3, 4, 5, 6, 7, 8

    try:
        lines = output.strip().split("\n")
        if not lines:
            return jsonify({"flows": []})

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices with robust naming support
        try:
            header_norm = [h.lower().strip() for h in header]
            if 'ts' in header_norm:
                ts_idx = header_norm.index('ts')
            elif 'firstseen' in header_norm:
                ts_idx = header_norm.index('firstseen')

            if 'td' in header_norm:
                td_idx = header_norm.index('td')
            elif 'duration' in header_norm:
                td_idx = header_norm.index('duration')

            if 'pr' in header_norm:
                pr_idx = header_norm.index('pr')
            elif 'proto' in header_norm:
                pr_idx = header_norm.index('proto')

            if 'sa' in header_norm:
                sa_idx = header_norm.index('sa')
            elif 'srcaddr' in header_norm:
                sa_idx = header_norm.index('srcaddr')

            if 'da' in header_norm:
                da_idx = header_norm.index('da')
            elif 'dstaddr' in header_norm:
                da_idx = header_norm.index('dstaddr')

            if 'sp' in header_norm:
                sp_idx = header_norm.index('sp')
            elif 'srcport' in header_norm:
                sp_idx = header_norm.index('srcport')

            if 'dp' in header_norm:
                dp_idx = header_norm.index('dp')
            elif 'dstport' in header_norm:
                dp_idx = header_norm.index('dstport')

            if 'ipkt' in header_norm:
                ipkt_idx = header_norm.index('ipkt')
            elif 'packets' in header_norm:
                ipkt_idx = header_norm.index('packets')

            if 'ibyt' in header_norm:
                ibyt_idx = header_norm.index('ibyt')
            elif 'bytes' in header_norm:
                ibyt_idx = header_norm.index('bytes')
        except (ValueError, IndexError):
            pass

        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx):
                try:
                    ts_str = parts[ts_idx].strip()
                    duration = float(parts[td_idx])
                    proto_val = parts[pr_idx].strip()
                    src = parts[sa_idx].strip()
                    src_port = parts[sp_idx].strip()
                    dst = parts[da_idx].strip()
                    dst_port = parts[dp_idx].strip()
                    pkts = int(float(parts[ipkt_idx]))
                    b = int(float(parts[ibyt_idx]))

                    # Calculate Age
                    # ts format often: 2026-01-13 19:42:15.000
                    try:
                        # strip fractional seconds for parsing if needed, or simple str parse
                        # fast simplified parsing
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except (ValueError, TypeError):
                        age_sec = 0

                    # Enrich with Geo
                    src_geo = lookup_geo(src) or {}
                    dst_geo = lookup_geo(dst) or {}

                    # Resolve Service Name
                    try:
                        port_num = int(dst_port)
                        proto = 'tcp' if '6' in proto_val else 'udp'
                        service_key = (port_num, proto)

                        with _lock_service_cache:
                            svc = _service_cache.get(service_key)
                            if svc is None:
                                # Optimization: Check static PORTS first
                                if port_num in PORTS:
                                    svc = PORTS[port_num]
                                else:
                                    try:
                                        svc = socket.getservbyport(port_num, proto)
                                    except OSError:
                                        svc = str(port_num) # Fallback
                                _service_cache[service_key] = svc
                    except (ValueError, TypeError):
                        svc = dst_port # If not a valid integer, use the original string

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
                except (ValueError, IndexError, KeyError, TypeError):
                    pass

    except (ValueError, IndexError, KeyError, TypeError) as e:
        add_app_log(f"Error parsing talkers: {e}", 'WARN')
        pass

    with _cache_lock:
        _stats_talkers_cache["data"] = {"flows": flows}
        _stats_talkers_cache["ts"] = now
        _stats_talkers_cache["key"] = range_key
        _stats_talkers_cache["win"] = win
    return jsonify({"flows": flows})



@bp.route("/api/stats/protocol_hierarchy")
@throttle(5, 10)
def api_stats_protocol_hierarchy():
    """Hierarchy of protocols (L4 -> L7) for sunburst visualization."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)

    with _lock_proto_hierarchy:
        if _stats_proto_hierarchy_cache["data"] and _stats_proto_hierarchy_cache["key"] == range_key and _stats_proto_hierarchy_cache.get("win") == win:
            return jsonify(_stats_proto_hierarchy_cache["data"])

    tf = get_time_range(range_key)
    # Aggregation: proto, dstport.
    # Use -A proto,dstport -O bytes
    output = run_nfdump(["-A", "proto,dstport", "-O", "bytes", "-n", "100"], tf)

    hierarchy = {"name": "Root", "children": []}

    # Structure:
    # {
    #   "name": "Root",
    #   "children": [
    #     {
    #       "name": "TCP",
    #       "children": [ {"name": "HTTP", "value": 123}, ... ]
    #     },
    #     ...
    #   ]
    # }

    l4_groups = defaultdict(lambda: defaultdict(int))

    try:
        lines = output.strip().split("\n")
        if not lines:
            return jsonify(hierarchy)

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices
        header_norm = [h.lower().strip() for h in header]
        try:
            pr_idx = header_norm.index('pr') if 'pr' in header_norm else (header_norm.index('proto') if 'proto' in header_norm else 2)
            dp_idx = header_norm.index('dp') if 'dp' in header_norm else (header_norm.index('dstport') if 'dstport' in header_norm else 6)
            ibyt_idx = header_norm.index('ibyt') if 'ibyt' in header_norm else (header_norm.index('bytes') if 'bytes' in header_norm else 8)
        except ValueError:
            pass

        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(pr_idx, dp_idx, ibyt_idx):
                try:
                    proto_val = parts[pr_idx].strip()
                    port_val = int(float(parts[dp_idx].strip()))
                    bytes_val = int(float(parts[ibyt_idx].strip()))

                    # Map L4
                    proto_name = "Other"
                    if proto_val == "6" or proto_val.upper() == "TCP": proto_name = "TCP"
                    elif proto_val == "17" or proto_val.upper() == "UDP": proto_name = "UDP"
                    elif proto_val == "1" or proto_val.upper() == "ICMP": proto_name = "ICMP"

                    # Map L7 (Service)
                    service_name = PORTS.get(port_val, str(port_val))

                    l4_groups[proto_name][service_name] += bytes_val
                except (ValueError, TypeError, IndexError):
                    pass

        # Build hierarchy list
        for proto, services in l4_groups.items():
            children = []
            for svc, b in services.items():
                children.append({"name": svc, "value": b, "bytes_fmt": fmt_bytes(b)})

            # Sort children by bytes
            children.sort(key=lambda x: x["value"], reverse=True)

            hierarchy["children"].append({
                "name": proto,
                "children": children,
                "total_bytes": sum(c["value"] for c in children)
            })

        # Sort L4 by total bytes
        hierarchy["children"].sort(key=lambda x: x["total_bytes"], reverse=True)

    except Exception as e:
        print(f"Hierarchy parse error: {e}")

    with _lock_proto_hierarchy:
        _stats_proto_hierarchy_cache["data"] = hierarchy
        _stats_proto_hierarchy_cache["ts"] = now
        _stats_proto_hierarchy_cache["key"] = range_key
        _stats_proto_hierarchy_cache["win"] = win

    return jsonify(hierarchy)


@bp.route("/api/stats/noise")
@throttle(5, 10)
def api_noise_metrics():
    """Calculate Network Noise Score (Unproductive vs Productive Traffic)."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    win = int(now // 60)

    with _lock_noise:
        if _stats_noise_metrics_cache["data"] and _stats_noise_metrics_cache["key"] == range_key and _stats_noise_metrics_cache.get("win") == win:
            return jsonify(_stats_noise_metrics_cache["data"])

    # 1. Total Flows (Productive + Noise)
    tf = get_time_range(range_key)
    # We use a large limit to get a statistical sample for ratios
    output = run_nfdump(["-n", "2000"], tf)

    total_flows = 0
    syn_only = 0
    small_flows = 0

    try:
        lines = output.strip().split("\n")
        if not lines:
             return jsonify({
                 "score": 0,
                 "level": "Low",
                 "total_flows": 0,
                 "noise_flows": 0,
                 "breakdown": {
                     "scans": 0,
                     "blocked": 0,
                     "tiny": 0
                 }
             })

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices with robust fallbacks
        header_norm = [h.lower().strip() for h in header]
        try:
            flg_idx = header_norm.index('flg') if 'flg' in header_norm else (header_norm.index('flags') if 'flags' in header_norm else 9)
            pr_idx = header_norm.index('pr') if 'pr' in header_norm else (header_norm.index('proto') if 'proto' in header_norm else 2)
            ibyt_idx = header_norm.index('ibyt') if 'ibyt' in header_norm else (header_norm.index('bytes') if 'bytes' in header_norm else 8)
        except (ValueError, IndexError):
            pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,'): continue
            parts = line.split(',')
            total_flows += 1
            if len(parts) > max(flg_idx, pr_idx, ibyt_idx):
                try:
                    flags = parts[flg_idx].upper()
                    b = int(float(parts[ibyt_idx]))

                    if flags == 'S' or flags == '.S': syn_only += 1
                    if b < 64: small_flows += 1 # Strict tiny flows
                except (ValueError, IndexError, KeyError):
                    pass

    except (ValueError, IndexError, KeyError, TypeError):
        pass

    # 2. Blocked Flows (Definitely Noise)
    # NOTE: blocked_count comes from syslog/firewall, total_flows from NetFlow.
    # These may have different capture points (pre-firewall vs post-firewall).
    # The noise calculation assumes NetFlow captures traffic before firewall blocks.
    hours_map = {'15m': 0.25, '30m': 0.5, '1h': 1, '6h': 6, '24h': 24, '7d': 168}
    h = hours_map.get(range_key, 1)
    fw_stats_ranged = _get_firewall_block_stats(hours=h)
    blocked_count = fw_stats_ranged.get('blocks', 0)

    # 3. Threat Flows (Noise/Malicious)
    # Get from threats list matching
    threat_set = load_threatlist()
    threat_flows = 0
    # We could scan the flows list again or just use a ratio.
    # For now, let's use the blocked_count as a strong signal, and syn_only as another.

    # Calculate Noise Components
    # Note: blocked_count is from syslog, total_flows is from NetFlow. They might overlap or not depending on where NetFlow is captured.
    # Assuming NetFlow captures ingress BEFORE blocking (common on OPNsense promiscuous), blocked flows are part of total.
    # If NetFlow is on internal interface, blocked flows might not be seen.
    # We will assume Noise = (SYN_Only + Tiny + Blocked)
    # But SYN_Only/Tiny are subsets of Total. Blocked is separate source.

    # If total_flows is low (e.g. mock), we need to avoid div/0
    effective_total = total_flows + blocked_count

    noise_flows = syn_only + blocked_count # Simplified: Scans + Blocks

    noise_score = 0
    if effective_total > 0:
        noise_score = int((noise_flows / effective_total) * 100)

    # Cap at 100
    noise_score = min(100, noise_score)

    # Classification
    noise_level = "Low"
    if noise_score > 50: noise_level = "High"
    elif noise_score > 20: noise_level = "Moderate"

    data = {
        "score": noise_score,
        "level": noise_level,
        "total_flows": effective_total,
        "noise_flows": noise_flows,
        "breakdown": {
            "scans": syn_only,
            "blocked": blocked_count,
            "tiny": small_flows
        }
    }

    with _lock_noise:
        _stats_noise_metrics_cache["data"] = data
        _stats_noise_metrics_cache["ts"] = now
        _stats_noise_metrics_cache["key"] = range_key
        _stats_noise_metrics_cache["win"] = win

    return jsonify(data)


@bp.route("/api/stats/services")
@throttle(5, 10)
@cached_endpoint(_stats_services_cache, _cache_lock, key_params=['range'])
def api_stats_services():
    """Top services by bytes (aggregated by service name)."""
    range_key = request.args.get('range', '1h')
    ports_data = get_common_nfdump_data("ports", range_key)

    service_bytes = Counter()
    service_flows = Counter()
    for item in ports_data:
        port_str = item.get("key", "")
        try:
            port = int(port_str)
            service = PORTS.get(port, f"Port {port}")
        except (ValueError, TypeError):
            service = port_str
        service_bytes[service] += item.get("bytes", 0)
        service_flows[service] += item.get("flows", 0)

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

    return {"services": services, "maxBytes": max_bytes}



@bp.route("/api/stats/hourly")
@throttle(5, 10)
def api_stats_hourly():
    """Traffic distribution by hour for selected range."""
    range_key = request.args.get('range', '24h')
    now = time.time()
    win = int(now // 60)
    with _cache_lock:
        if _stats_hourly_cache["data"] and _stats_hourly_cache.get("key") == range_key and _stats_hourly_cache.get("win") == win:
            return jsonify(_stats_hourly_cache["data"])

    tf = get_time_range(range_key)
    # Sort by bytes to capture the top contributors
    output = run_nfdump(["-O", "bytes", "-n", "10000"], tf)

    # Initialize hourly buckets (0-23)
    hourly_bytes = {h: 0 for h in range(24)}
    hourly_flows = {h: 0 for h in range(24)}

    # NFDump CSV usually has no header
    # Indices: ts=0, td=1, pr=2, sa=3, sp=4, da=5, dp=6, ipkt=7, ibyt=8, fl=9
    ts_idx, ibyt_idx = 0, 8

    try:
        lines = output.strip().split("\n")
        if not lines:
             return jsonify({})

        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = lines[header_idx].split(',')
            start_idx = header_idx + 1
        else:
            # Fallback
            header = lines[0].split(',')
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices
        header_norm = [h.lower().strip() for h in header]
        try:
            ts_idx = header_norm.index('ts') if 'ts' in header_norm else (header_norm.index('firstseen') if 'firstseen' in header_norm else 0)
            ibyt_idx = header_norm.index('ibyt') if 'ibyt' in header_norm else (header_norm.index('bytes') if 'bytes' in header_norm else 8)
        except (ValueError, IndexError):
            pass

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
                    b = int(float(parts[ibyt_idx]))
                    hourly_bytes[hour] += b
                    hourly_flows[hour] += 1
                except (ValueError, IndexError, KeyError):
                    pass

        # Find peak hour
        peak_hour = max(hourly_bytes, key=hourly_bytes.get)
        peak_bytes = hourly_bytes[peak_hour]

        # Reorder chronologically: oldest hour (24h ago) on left, current hour on right
        # This prevents showing "future" hours with data from yesterday
        current_hour = datetime.now().hour
        # Order: (current_hour+1) ... 23, 0 ... current_hour
        # e.g., if current_hour is 9, order is: 10,11,12...23,0,1,2...8,9
        chronological_hours = [(current_hour + 1 + i) % 24 for i in range(24)]

        labels = [f"{h}:00" for h in chronological_hours]
        bytes_data = [hourly_bytes[h] for h in chronological_hours]
        flows_data = [hourly_flows[h] for h in chronological_hours]

        data = {
            "labels": labels,
            "bytes": bytes_data,
            "flows": flows_data,
            "bytes_fmt": [fmt_bytes(b) for b in bytes_data],
            "peak_hour": peak_hour,
            "peak_bytes": peak_bytes,
            "peak_bytes_fmt": fmt_bytes(peak_bytes),
            "total_bytes": sum(bytes_data),
            "total_bytes_fmt": fmt_bytes(sum(bytes_data)),
            "timezone": "local",  # Clarify that hours are in server local time
            "time_scope": range_key,  # Fixed window explicit declaration
            "current_hour": current_hour  # For frontend reference
        }
    except (ValueError, TypeError, IndexError, KeyError):
        data = {"labels": [], "bytes": [], "flows": [], "bytes_fmt": [], "peak_hour": 0, "peak_bytes": 0, "peak_bytes_fmt": "0 B", "total_bytes": 0, "total_bytes_fmt": "0 B", "time_scope": range_key}

    with _cache_lock:
        _stats_hourly_cache["data"] = data
        _stats_hourly_cache["ts"] = now
        _stats_hourly_cache["win"] = win
        _stats_hourly_cache["key"] = range_key
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
            except ValueError:
                pass

        for line in lines[start_idx:]:
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(td_idx, ibyt_idx, ipkt_idx):
                try:
                    durations.append(float(parts[td_idx]))
                    bytes_list.append(int(parts[ibyt_idx]))
                    packets_list.append(int(parts[ipkt_idx]))
                except (ValueError, IndexError, KeyError):
                    pass

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
    except (ValueError, TypeError, IndexError, KeyError):
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



@bp.route("/api/firewall/stats/overview")
@throttle(30, 10)
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
    from app.services.shared.baselines import update_baseline, calculate_trend
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
        },
        # TIME SCOPE METADATA: Fixed 24h window
        "time_scope": "24h"
    })


def _safe_ensure_rollup(bucket):
    """Wrapper to ensure background rollup exceptions are logged."""
    try:
        _ensure_rollup_for_bucket(bucket)
    except Exception as e:
        add_app_log(f"Background rollup failure: {e}", 'WARN')


@bp.route("/api/bandwidth")
@throttle(10,20)
def api_bandwidth():
    """
    Get bandwidth usage over the specified time range.

    Performance Note:
    Traffic rollups for missing buckets are computed asynchronously using a background
    thread pool (`_rollup_executor`). This ensures the API response is non-blocking and fast,
    even if historical data needs to be aggregated on-demand. Clients may initially see
    incomplete data (zeros) for missing buckets, which will be populated in subsequent requests
    once the background tasks complete.
    """
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
                # Offload to background executor (non-blocking) to prevent request timeout/latency
                # Client will see gaps (zeros) initially, which is acceptable for performance.
                try:
                    for bucket in missing_buckets:
                        _rollup_executor.submit(_safe_ensure_rollup, bucket)
                except Exception as e:
                    add_app_log(f"Bandwidth computation submission partial failure: {e}", 'WARN')

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
    except (ValueError, IndexError, KeyError, TypeError, sqlite3.Error) as e:
        add_app_log(f"Bandwidth API error: {e}", 'ERROR')
        return jsonify({"labels":[],"bandwidth":[],"flows":[]}), 500


@bp.route("/api/network/stats/overview")
@throttle(30, 10)
def api_network_stats_overview():
    """Get high-signal network stat box metrics respecting global time range."""
    # Get range from request, default to 1h for backward compatibility if not provided
    range_key = request.args.get('range', '1h')
    # Use requested range for all metrics
    tf_range = get_time_range(range_key)
    
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
        full_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-q"], tf_range)
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
        sample_output = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-n", "500"], tf_range)
        sample_count = 0
        sample_external = 0
        
        try:
            lines = sample_output.strip().split("\n")
            start_idx = 0
            sa_idx = 0
            da_idx = 0
            
            if lines:
                # Robust Header Detection
                header_idx = -1
                for i, line in enumerate(lines):
                    line_clean = line.strip().lower()
                    if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                        header_idx = i
                        break
                
                if header_idx != -1:
                    header = [c.strip().lower() for c in lines[header_idx].split(',')]
                    start_idx = header_idx + 1
                else:
                    header = [c.strip().lower() for c in lines[0].split(',')]
                    start_idx = 1 if len(header) > 1 else 0

                try:
                    sa_idx = header.index('sa') if 'sa' in header else (header.index('srcaddr') if 'srcaddr' in header else 3)
                    da_idx = header.index('da') if 'da' in header else (header.index('dstaddr') if 'dstaddr' in header else 5)
                except ValueError:
                    pass
            
            for line in lines[start_idx:]:
                line = line.strip()
                if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
                parts = line.split(',')
                if len(parts) > max(sa_idx, da_idx):
                    try:
                        # Safe access
                        src = parts[sa_idx].strip()
                        dst = parts[da_idx].strip()
                        
                        if src and dst:
                            sample_count += 1
                            
                            # Check if external connection (not internal-to-internal)
                            src_internal = is_internal(src)
                            dst_internal = is_internal(dst)
                            
                            if not (src_internal and dst_internal):
                                sample_external += 1
                    except (ValueError, TypeError, IndexError):
                        pass
            
            # Estimate external connections based on sample ratio
            if sample_count > 0:
                external_ratio = sample_external / sample_count
                external_connections_count = int(active_flows_count * external_ratio)
            else:
                external_connections_count = 0
        except (ValueError, TypeError, IndexError, KeyError):
            external_connections_count = 0
    else:
        external_connections_count = 0
    
    # Count anomalies (detections) over requested range
    # Fetch flows with detection criteria
    output_24h = run_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto"], tf_range)
    
    anomalies_24h = 0
    anomaly_alerts_sent = set()  # Track sent alerts to avoid duplicates
    
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
                except ValueError:
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
                            # Create alert for this anomaly (only once per hour per src-dst pair to avoid flooding)
                            anomaly_key = f"traffic_anomaly_{src}_{dst}"
                            if anomaly_key not in anomaly_alerts_sent:
                                anomaly_alerts_sent.add(anomaly_key)
                                add_health_alert_to_history(
                                    "traffic_anomaly",
                                    f"⚠️ Traffic Anomaly: Long-lived low-volume flow {src} → {dst} ({fmt_bytes(b)}, {duration:.1f}s)",
                                    severity="medium",
                                    ip=src,
                                    source=src,
                                    destination=dst
                                )
                except (ValueError, TypeError, IndexError):
                    pass
    except (ValueError, TypeError, IndexError, KeyError):
        pass
    
    # Update baselines (incremental, respects update interval)
    from app.services.shared.baselines import update_baseline, calculate_trend
    update_baseline('active_flows', active_flows_count)
    update_baseline('external_connections', external_connections_count)
    
    # Calculate anomalies rate (anomalies per hour)
    range_hours = {
        '15m': 0.25, '30m': 0.5, '1h': 1, '6h': 6, '24h': 24, '7d': 168
    }.get(range_key, 1)
    anomalies_rate = anomalies_24h / range_hours if anomalies_24h > 0 else 0.0
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
        },
        # TIME SCOPE METADATA: Documents fixed time windows used for each metric
        "time_scope": {
            "active_flows": range_key,
            "external_connections": range_key,
            "anomalies_24h": range_key
        }
    })


@bp.route("/api/network/intelligence")
@throttle(5, 10)
def api_network_intelligence():
    """Get network performance and behavior insights."""
    range_key = request.args.get('range', '1h')
    now = time.time()
    
    # Initialize response structure focused on network metrics
    intelligence = {
        "bandwidth_utilization": {
            "top_talker_pct": 0,
            "top_5_pct": 0,
            "distribution": "Balanced"
        },
        "protocol_diversity": {
            "primary_protocol": "TCP",
            "primary_pct": 0,
            "protocols_count": 0,
            "balance": "Diverse"
        },
        "connection_patterns": {
            "avg_duration": 0,
            "avg_duration_fmt": "0s",
            "short_lived_pct": 0,
            "long_lived_pct": 0,
            "pattern": "Normal"
        },
        "traffic_characteristics": {
            "avg_packet_size": 0,
            "avg_packet_size_fmt": "0 B",
            "total_flows": 0,
            "flows_per_minute": 0
        },
        "top_application": None
    }
    
    try:
        tf = get_time_range(range_key)
        
        # 1. Get flow data for analysis
        output = run_nfdump(["-n", "1000"], tf)
        
        total_flows = 0
        total_bytes = 0
        durations = []
        packet_sizes = []
        
        lines = output.strip().split("\n") if output else []
        if lines:
            # Robust Header Detection
            header_idx = -1
            for i, line in enumerate(lines):
                line_clean = line.strip().lower()
                if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                    header_idx = i
                    break
            
            if header_idx != -1:
                header = lines[header_idx].split(',')
                start_idx = header_idx + 1
            else:
                header = lines[0].split(',')
                start_idx = 1 if len(header) > 1 else 0
            
            # Map headers to indices
            header_norm = [h.lower().strip() for h in header]
            try:
                td_idx = header_norm.index('td') if 'td' in header_norm else (header_norm.index('duration') if 'duration' in header_norm else 1)
                ibyt_idx = header_norm.index('ibyt') if 'ibyt' in header_norm else (header_norm.index('bytes') if 'bytes' in header_norm else 8)
                ipkt_idx = header_norm.index('ipkt') if 'ipkt' in header_norm else (header_norm.index('packets') if 'packets' in header_norm else 7)
            except (ValueError, IndexError):
                td_idx, ibyt_idx, ipkt_idx = 1, 8, 7
            
            for line in lines[start_idx:]:
                if not line or line.startswith('ts,'): continue
                parts = line.split(',')
                total_flows += 1
                if len(parts) > max(td_idx, ibyt_idx, ipkt_idx):
                    try:
                        duration = float(parts[td_idx])
                        b = int(float(parts[ibyt_idx]))
                        pkts = int(float(parts[ipkt_idx]))
                        
                        total_bytes += b
                        durations.append(duration)
                        if pkts > 0:
                            packet_sizes.append(b / pkts)
                    except (ValueError, IndexError, KeyError):
                        pass
        
        # 2. Bandwidth Utilization Analysis
        try:
            sources_data = get_common_nfdump_data("sources", range_key)
            if sources_data and len(sources_data) > 0:
                top_talker_bytes = sources_data[0].get("bytes", 0)
                top_5_bytes = sum(s.get("bytes", 0) for s in sources_data[:5])
                
                if total_bytes > 0:
                    intelligence["bandwidth_utilization"]["top_talker_pct"] = round((top_talker_bytes / total_bytes) * 100, 1)
                    intelligence["bandwidth_utilization"]["top_5_pct"] = round((top_5_bytes / total_bytes) * 100, 1)
                
                # Classify distribution
                if intelligence["bandwidth_utilization"]["top_talker_pct"] > 50:
                    intelligence["bandwidth_utilization"]["distribution"] = "Concentrated"
                elif intelligence["bandwidth_utilization"]["top_talker_pct"] > 25:
                    intelligence["bandwidth_utilization"]["distribution"] = "Moderate"
                else:
                    intelligence["bandwidth_utilization"]["distribution"] = "Balanced"
        except Exception:
            pass
        
        # 3. Protocol Diversity
        try:
            # Protocol number to name mapping
            proto_map = {"1": "ICMP", "6": "TCP", "17": "UDP", "41": "IPv6", "47": "GRE", "50": "ESP", "51": "AH"}
            
            protocols_data = get_common_nfdump_data("protos", range_key)
            if protocols_data:
                intelligence["protocol_diversity"]["protocols_count"] = len(protocols_data)
                
                if len(protocols_data) > 0:
                    top_proto = protocols_data[0]
                    # Get protocol number from key field
                    proto_num = str(top_proto.get("key", "6"))
                    # Map to name, fallback to number if unknown
                    proto_name = proto_map.get(proto_num, f"Proto-{proto_num}")
                    intelligence["protocol_diversity"]["primary_protocol"] = proto_name
                    
                    proto_bytes = top_proto.get("bytes", 0)
                    if total_bytes > 0:
                        intelligence["protocol_diversity"]["primary_pct"] = round((proto_bytes / total_bytes) * 100, 1)
                
                # Classify balance
                if intelligence["protocol_diversity"]["primary_pct"] > 80:
                    intelligence["protocol_diversity"]["balance"] = "Homogeneous"
                elif intelligence["protocol_diversity"]["primary_pct"] > 60:
                    intelligence["protocol_diversity"]["balance"] = "Dominant"
                else:
                    intelligence["protocol_diversity"]["balance"] = "Diverse"
        except Exception:
            pass
        
        # 4. Connection Patterns
        if durations:
            avg_duration = sum(durations) / len(durations)
            intelligence["connection_patterns"]["avg_duration"] = round(avg_duration, 2)
            intelligence["connection_patterns"]["avg_duration_fmt"] = format_duration(avg_duration)
            
            short_lived = sum(1 for d in durations if d < 1)
            long_lived = sum(1 for d in durations if d > 60)
            
            intelligence["connection_patterns"]["short_lived_pct"] = round((short_lived / len(durations)) * 100, 1)
            intelligence["connection_patterns"]["long_lived_pct"] = round((long_lived / len(durations)) * 100, 1)
            
            # Classify pattern
            if intelligence["connection_patterns"]["short_lived_pct"] > 70:
                intelligence["connection_patterns"]["pattern"] = "Transient"
            elif intelligence["connection_patterns"]["long_lived_pct"] > 30:
                intelligence["connection_patterns"]["pattern"] = "Persistent"
            else:
                intelligence["connection_patterns"]["pattern"] = "Mixed"
        
        # 5. Traffic Characteristics
        intelligence["traffic_characteristics"]["total_flows"] = total_flows
        
        if packet_sizes:
            avg_pkt_size = sum(packet_sizes) / len(packet_sizes)
            intelligence["traffic_characteristics"]["avg_packet_size"] = round(avg_pkt_size)
            intelligence["traffic_characteristics"]["avg_packet_size_fmt"] = fmt_bytes(avg_pkt_size)
        
        # Calculate flows per minute
        range_minutes = {'15m': 15, '30m': 30, '1h': 60, '6h': 360, '24h': 1440, '7d': 10080}.get(range_key, 60)
        if range_minutes > 0:
            intelligence["traffic_characteristics"]["flows_per_minute"] = round(total_flows / range_minutes, 1)
        
        # 6. Top Application/Service
        try:
            ports_data = get_common_nfdump_data("ports", range_key)
            if ports_data and len(ports_data) > 0:
                top_port = ports_data[0]
                port_bytes = top_port.get("bytes", 0)
                
                intelligence["top_application"] = {
                    "port": top_port.get("key", "Unknown"),
                    "service": top_port.get("service", "Unknown"),
                    "bytes": port_bytes,
                    "bytes_fmt": fmt_bytes(port_bytes),
                    "percentage": round((port_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0
                }
        except Exception:
            pass
        
    except Exception as e:
        add_app_log(f"Error generating network intelligence: {e}", 'ERROR')
    
    return jsonify(intelligence)



@bp.route("/api/flows")
@throttle(10,30)
def api_flows():
    range_key = request.args.get('range', '1h')
    try:
        limit = int(request.args.get('limit', 10))
    except (ValueError, TypeError):
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
        # Robust Header Detection
        header_idx = -1
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            if line_clean.startswith('ts,') or line_clean.startswith('firstseen,'):
                header_idx = i
                break
        
        if header_idx != -1:
            header = [c.strip().lower() for c in lines[header_idx].split(',')]
            start_idx = header_idx + 1
        else:
            header = [c.strip().lower() for c in lines[0].split(',')]
            start_idx = 1 if len(header) > 1 else 0

        # Map headers to indices with robust naming support
        try:
            ts_idx = header.index('ts') if 'ts' in header else (header.index('firstseen') if 'firstseen' in header else 0)
            td_idx = header.index('td') if 'td' in header else (header.index('duration') if 'duration' in header else 1)
            pr_idx = header.index('pr') if 'pr' in header else (header.index('proto') if 'proto' in header else 2)
            sa_idx = header.index('sa') if 'sa' in header else (header.index('srcaddr') if 'srcaddr' in header else 3)
            da_idx = header.index('da') if 'da' in header else (header.index('dstaddr') if 'dstaddr' in header else 5)
            sp_idx = header.index('sp') if 'sp' in header else (header.index('srcport') if 'srcport' in header else 4)
            dp_idx = header.index('dp') if 'dp' in header else (header.index('dstport') if 'dstport' in header else 6)
            ipkt_idx = header.index('ipkt') if 'ipkt' in header else (header.index('packets') if 'packets' in header else 7)
            ibyt_idx = header.index('ibyt') if 'ibyt' in header else (header.index('bytes') if 'bytes' in header else 8)
        except (ValueError, IndexError):
            pass

        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('ts,') or line.startswith('firstseen,'): continue
            parts = line.split(',')
            if len(parts) > max(ts_idx, td_idx, pr_idx, sa_idx, sp_idx, da_idx, dp_idx, ipkt_idx, ibyt_idx):
                try:
                    ts_str = parts[ts_idx].strip()
                    duration = float(parts[td_idx])
                    proto_val = parts[pr_idx].strip()
                    src = parts[sa_idx].strip()
                    src_port = parts[sp_idx].strip()
                    dst = parts[da_idx].strip()
                    dst_port = parts[dp_idx].strip()
                    pkts = int(float(parts[ipkt_idx]))
                    b = int(float(parts[ibyt_idx]))

                    # Calculate Age
                    try:
                        if '.' in ts_str: ts_str = ts_str.split('.')[0]
                        flow_time = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp()
                        age_sec = now - flow_time
                    except (ValueError, TypeError):
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
                        port_num = int(dst_port)
                        proto = 'tcp' if '6' in proto_val else 'udp'
                        service_key = (port_num, proto)

                        with _lock_service_cache:
                            svc = _service_cache.get(service_key)
                            if svc is None:
                                # Optimization: Check static PORTS first
                                if port_num in PORTS:
                                    svc = PORTS[port_num]
                                else:
                                    try:
                                        svc = socket.getservbyport(port_num, proto)
                                    except OSError:
                                        svc = str(port_num) # Fallback
                                _service_cache[service_key] = svc
                    except (ValueError, TypeError):
                        svc = dst_port # If not a valid integer, use the original string
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
                            # Prevent unbounded memory growth
                            if len(_flow_history) > 10000:
                                _flow_history.clear()
                                add_app_log("Cleared flow history cache (size limit exceeded)", "WARN")
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
                except (ValueError, TypeError, IndexError, KeyError):
                    pass


    except (ValueError, TypeError, IndexError, KeyError):
        pass  # Parsing error
    data = {"flows":convs, "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")}
    with _lock_flows:
        _flows_cache["data"] = data
        _flows_cache["ts"] = now
        _flows_cache["key"] = cache_key_local
        _flows_cache["win"] = win
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


@bp.route('/api/firewall/snmp-status')
@throttle(5, 10)
def api_firewall_snmp_status():
    """Get firewall SNMP operational health data."""
    from app.services.shared.snmp import get_snmp_data, discover_interfaces
    from app.services.shared.config_helpers import load_config
    import time
    import subprocess
    from app.config import SNMP_HOST, SNMP_COMMUNITY

    # Load runtime config (supports settings UI changes)
    config = load_config()
    snmp_host = config.get('snmp_host', SNMP_HOST)
    snmp_community = config.get('snmp_community', SNMP_COMMUNITY)

    snmp_data = get_snmp_data()
    
    # Store cache timestamp for staleness checks
    import app.core.app_state as state
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
    except (KeyError, TypeError, AttributeError):
        # Discovery failed - continue without VPN interfaces
        pass

    # Fetch interface IP addresses via SNMP
    interface_ips = {}  # {interface_index: ip_address}
    default_gateway = None
    gateway_latency = None
    try:
        # Get IP addresses and their interface mappings
        ip_addr_cmd = ["snmpwalk", "-v2c", "-c", snmp_community, "-Oqn", snmp_host, ".1.3.6.1.2.1.4.20.1.1"]
        ip_idx_cmd = ["snmpwalk", "-v2c", "-c", snmp_community, "-Oqn", snmp_host, ".1.3.6.1.2.1.4.20.1.2"]

        ip_addr_output = subprocess.check_output(ip_addr_cmd, shell=False, stderr=subprocess.DEVNULL, timeout=3, text=True)
        ip_idx_output = subprocess.check_output(ip_idx_cmd, shell=False, stderr=subprocess.DEVNULL, timeout=3, text=True)

        # Parse IP addresses: .1.3.6.1.2.1.4.20.1.1.x.x.x.x -> x.x.x.x
        ip_addresses = {}
        for line in ip_addr_output.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    if ip and ip != '127.0.0.1':
                        ip_addresses[ip] = ip

        # Parse interface indexes: .1.3.6.1.2.1.4.20.1.2.x.x.x.x -> index
        for line in ip_idx_output.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    oid = parts[0]
                    idx = int(parts[1])
                    # Extract IP from OID suffix
                    ip_suffix = oid.split('.1.3.6.1.2.1.4.20.1.2.')[-1]
                    if ip_suffix in ip_addresses and ip_suffix != '127.0.0.1':
                        interface_ips[idx] = ip_suffix

        # Get default gateway (route for 0.0.0.0)
        gw_cmd = ["snmpget", "-v2c", "-c", snmp_community, "-Oqv", snmp_host, ".1.3.6.1.2.1.4.21.1.7.0.0.0.0"]
        gw_output = subprocess.check_output(gw_cmd, shell=False, stderr=subprocess.DEVNULL, timeout=3, text=True).strip()
        if gw_output and gw_output != '0.0.0.0':
            default_gateway = gw_output

            # Ping gateway to measure latency
            ping_cmd = ["ping", "-c", "1", "-W", "1", default_gateway]
            try:
                ping_output = subprocess.check_output(ping_cmd, shell=False, stderr=subprocess.DEVNULL, timeout=2, text=True)
                # Parse ping output for time=X.XXX ms
                import re
                match = re.search(r'time[=<](\d+\.?\d*)', ping_output)
                if match:
                    gateway_latency = float(match.group(1))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                gateway_latency = None  # Gateway unreachable
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError):
        # IP/gateway discovery failed - continue without
        pass

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
        
        # Traffic is authoritative - if data is flowing, interface is up
        # This handles VPN interfaces that report oper_status=2 when idle but functional
        if has_traffic:
            return "up"

        # If operStatus is explicitly available, use it
        if oper_status is not None:
            if oper_status == 1:
                return "up"
            elif oper_status == 2:
                # Only show DOWN if there's no traffic AND no sessions
                if not has_sessions:
                    return "down"
                else:
                    return "up"  # Sessions exist, interface is functional
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
        "ip_address": interface_ips.get(1),  # WAN is typically interface index 1
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
        "ip_address": interface_ips.get(2),  # LAN is typically interface index 2
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
            
            # Error and Discard OIDs (32-bit)
            vpn_in_err_oid = f".1.3.6.1.2.1.2.2.1.14.{vpn_idx}"
            vpn_out_err_oid = f".1.3.6.1.2.1.2.2.1.20.{vpn_idx}"
            vpn_in_disc_oid = f".1.3.6.1.2.1.2.2.1.13.{vpn_idx}"
            vpn_out_disc_oid = f".1.3.6.1.2.1.2.2.1.19.{vpn_idx}"
            
            # Common OID string for errors/discards
            err_oid_list = [vpn_in_err_oid, vpn_out_err_oid, vpn_in_disc_oid, vpn_out_disc_oid]
            
            # Try 64-bit counters first, fallback to 32-bit if not available
            try:
                cmd = ["snmpget", "-v2c", "-c", snmp_community, "-Oqv", snmp_host, vpn_in_oid_hc, vpn_out_oid_hc, vpn_status_oid, vpn_speed_oid] + err_oid_list
                output = subprocess.check_output(cmd, shell=False, stderr=subprocess.PIPE, timeout=3, text=True)
                values = output.strip().split("\n")
                if len(values) < 8 or "No Such" in output:
                    raise ValueError("64-bit counters not available")
            except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                # Fallback to 32-bit counters
                cmd = ["snmpget", "-v2c", "-c", snmp_community, "-Oqv", snmp_host, vpn_in_oid_32, vpn_out_oid_32, vpn_status_oid, vpn_speed_oid] + err_oid_list
                output = subprocess.check_output(cmd, shell=False, stderr=subprocess.PIPE, timeout=3, text=True)
                values = output.strip().split("\n")
            
            if len(values) >= 8:
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
                vpn_speed = int(values[3].strip().strip('"')) if values[3].strip().strip('"') else 0
                
                vpn_in_err = parse_counter(values[4])
                vpn_out_err = parse_counter(values[5])
                vpn_in_disc = parse_counter(values[6])
                vpn_out_disc = parse_counter(values[7])
                
                # Calculate rates (similar to WAN/LAN)
                # Import state at the top level to ensure it's accessible
                import app.core.app_state as state
                prev_in_key = f"{vpn_name}_in"
                prev_out_key = f"{vpn_name}_out"
                prev_ts_key = f"{vpn_name}_ts"
                
                # Keys for errors/discards
                prev_in_err_key = f"{vpn_name}_in_err"
                prev_out_err_key = f"{vpn_name}_out_err"
                prev_in_disc_key = f"{vpn_name}_in_disc"
                prev_out_disc_key = f"{vpn_name}_out_disc"
                
                # Get previous values BEFORE storing new ones
                with state._snmp_prev_sample_lock:
                    prev_in = state._snmp_prev_sample.get(prev_in_key)
                    prev_out = state._snmp_prev_sample.get(prev_out_key)
                    prev_ts = state._snmp_prev_sample.get(prev_ts_key, 0)
                    
                    # Error/Discard prev values
                    prev_in_err = state._snmp_prev_sample.get(prev_in_err_key)
                    prev_out_err = state._snmp_prev_sample.get(prev_out_err_key)
                    prev_in_disc = state._snmp_prev_sample.get(prev_in_disc_key)
                    prev_out_disc = state._snmp_prev_sample.get(prev_out_disc_key)

                    now = time.time()
                    from app.config import SNMP_POLL_INTERVAL
                    # Use VPN-specific timestamp for accurate delta calculation
                    dt = max(1.0, now - prev_ts) if prev_ts > 0 else SNMP_POLL_INTERVAL
                    
                    # Calculate RX/TX rates (similar to WAN/LAN logic in snmp.py)
                    vpn_rx_mbps = None
                    vpn_tx_mbps = None
                    
                    # Calculate Bandwidth rates
                    if prev_in is not None and prev_out is not None and dt > 0:
                        d_in = vpn_in - prev_in
                        d_out = vpn_out - prev_out
                        
                        # Guard against wrap or reset
                        if d_in < 0:
                            vpn_rx_mbps = None
                        else:
                            vpn_rx_mbps = round((d_in * 8.0) / (dt * 1_000_000), 2)
                        
                        if d_out < 0:
                            vpn_tx_mbps = None
                        else:
                            vpn_tx_mbps = round((d_out * 8.0) / (dt * 1_000_000), 2)
                    
                    # Calculate Error/Discard rates (/s)
                    vpn_rx_err_s = 0.0
                    vpn_tx_err_s = 0.0
                    vpn_rx_disc_s = 0.0
                    vpn_tx_disc_s = 0.0
                    
                    if dt > 0:
                        if prev_in_err is not None:
                            d = vpn_in_err - prev_in_err
                            vpn_rx_err_s = round(d / dt, 1) if d >= 0 else 0.0
                        if prev_out_err is not None:
                            d = vpn_out_err - prev_out_err
                            vpn_tx_err_s = round(d / dt, 1) if d >= 0 else 0.0
                        if prev_in_disc is not None:
                            d = vpn_in_disc - prev_in_disc
                            vpn_rx_disc_s = round(d / dt, 1) if d >= 0 else 0.0
                        if prev_out_disc is not None:
                            d = vpn_out_disc - prev_out_disc
                            vpn_tx_disc_s = round(d / dt, 1) if d >= 0 else 0.0
                    
                    # Always store current values AFTER calculating rates (for next poll)
                    state._snmp_prev_sample[prev_in_key] = vpn_in
                    state._snmp_prev_sample[prev_out_key] = vpn_out
                    state._snmp_prev_sample[prev_ts_key] = now
                    
                    # Store Error/Discard current values
                    state._snmp_prev_sample[prev_in_err_key] = vpn_in_err
                    state._snmp_prev_sample[prev_out_err_key] = vpn_out_err
                    state._snmp_prev_sample[prev_in_disc_key] = vpn_in_disc
                    state._snmp_prev_sample[prev_out_disc_key] = vpn_out_disc
                
                # Calculate utilization if speed is known
                vpn_util = None
                if vpn_speed and vpn_speed > 0 and vpn_rx_mbps is not None and vpn_tx_mbps is not None:
                    # For Full Duplex links, utilization is max(rx, tx) / speed
                    max_mbps = max(vpn_rx_mbps, vpn_tx_mbps)
                    vpn_util = round((max_mbps / vpn_speed) * 100, 1)
                elif vpn_rx_mbps is not None and vpn_tx_mbps is not None:
                    # If speed is 0/unknown, use a placeholder or None
                    vpn_util = None
                
                # Determine status
                # Check both rates AND raw counters - VPN interfaces may have traffic but no rate yet (first poll)
                vpn_has_traffic = (vpn_rx_mbps is not None and vpn_rx_mbps > 0) or (vpn_tx_mbps is not None and vpn_tx_mbps > 0)
                vpn_has_any_traffic = vpn_has_traffic or vpn_in > 0 or vpn_out > 0  # Raw counters indicate interface has been used
                vpn_status = determine_interface_status(vpn_status_raw, None, vpn_has_any_traffic, has_sessions, data_age)
                
                # Add VPN interface
                interfaces.append({
                    "name": vpn_name.upper(),
                    "status": vpn_status,
                    "ip_address": interface_ips.get(vpn_idx),  # VPN IP from discovered index
                    "rx_mbps": vpn_rx_mbps,
                    "tx_mbps": vpn_tx_mbps,
                    "rx_errors": vpn_rx_err_s,
                    "tx_errors": vpn_tx_err_s,
                    "rx_drops": vpn_rx_disc_s,
                    "tx_drops": vpn_tx_disc_s,
                    "utilization": vpn_util,
                    "speed_mbps": vpn_speed,
                    "saturation_hint": None
                })
        except (KeyError, ValueError, TypeError, IndexError, ZeroDivisionError):
            # VPN interface polling failed - add interface with error state
            interfaces.append({
                "name": vpn_name.upper(),
                "status": "unknown",
                "ip_address": None,
                "rx_mbps": None,
                "tx_mbps": None,
                "rx_errors": None,
                "tx_errors": None,
                "rx_drops": None,
                "tx_drops": None,
                "utilization": None,
                "speed_mbps": None,
                "saturation_hint": None
            })
    
    # Calculate aggregate throughput (handle None values)
    total_throughput = sum([(i.get("rx_mbps") or 0) + (i.get("tx_mbps") or 0) for i in interfaces])
    
    # Correlate SNMP throughput with NetFlow traffic volume
    # Use 1h window to match typical SNMP polling cadence
    # CRITICAL: This block must fail gracefully to avoid blocking SNMP status if nfdump is slow/down
    try:
        from app.services.netflow.netflow import get_common_nfdump_data
        
        # Get NetFlow total bytes for last hour
        range_key = "1h"
        
        # Use a short timeout/fail-fast approach for this correlation check if possible,
        # but since run_nfdump uses global timeout, we rely on the try/except here.
        netflow_sources = None
        try:
            # We wrap this specific call to ensure it doesn't kill the whole request
            netflow_sources = get_common_nfdump_data("sources", range_key)
        except Exception:
            netflow_sources = None
            
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
    import app.core.app_state as state
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
        },
        # Additional system metrics
        "swap_percent": snmp_data.get("swap_percent"),
        "process_count": snmp_data.get("proc_count"),
        "tcp_retrans_s": snmp_data.get("tcp_retrans_s"),
        "tcp_resets_s": snmp_data.get("tcp_estab_resets_s"),
        "ip_forwarding_s": snmp_data.get("ip_forw_datagrams_s"),
        "udp_in_s": snmp_data.get("udp_in_s"),
        "udp_out_s": snmp_data.get("udp_out_s"),
        # Gateway monitoring
        "gateway": {
            "ip": default_gateway,
            "latency_ms": gateway_latency,
            "status": "up" if gateway_latency is not None else ("down" if default_gateway else "unknown")
        }
    }
    
    return jsonify(response)


# ===== SNMP Integration =====

# SNMP Configuration imported from centralized config
# Use app.config.SNMP_HOST and app.config.SNMP_COMMUNITY instead of duplicating here

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
        # Use authoritative shared status for syslog active check
        deps = state.get_dependency_health()
        syslog_status = deps.get('syslog_515', {})
        snmp_data['syslog_active'] = syslog_status.get('listening', False)
        
        # Use shared stats if available (multi-worker support)
        snmp_data['syslog_stats'] = {
            "received": syslog_status.get('received', 0),
            "parsed": syslog_status.get('parsed', 0),
            "errors": syslog_status.get('errors', 0),
            "last_log": syslog_status.get('last_packet_time')
        }

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
                # Merge syslog data into response
                if data:
                    merged = dict(data)
                    fw_stats = _get_firewall_block_stats(hours=1)
                    merged['blocks_1h'] = fw_stats.get('blocks', 0)
                    merged['blocks_per_hour'] = fw_stats.get('blocks_per_hour', 0)
                    merged['unique_blocked_ips'] = fw_stats.get('unique_ips', 0)
                    merged['threats_blocked'] = fw_stats.get('threats_blocked', 0)
                    
                    # Use authoritative shared status for syslog active check
                    deps = state.get_dependency_health()
                    syslog_status = deps.get('syslog_515', {})
                    merged['syslog_active'] = syslog_status.get('listening', False)
                    
                    merged['syslog_stats'] = {
                        "received": syslog_status.get('received', 0),
                        "parsed": syslog_status.get('parsed', 0),
                        "errors": syslog_status.get('errors', 0),
                        "last_log": syslog_status.get('last_packet_time')
                    }
                    
                    payload = json.dumps({"firewall": merged})
                    yield f"data: {payload}\n\n"
                    last_ts = ts
            _shutdown_event.wait(timeout=max(0.2, SNMP_POLL_INTERVAL / 2.0))

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


def process_batch_request(app, endpoint_name, handler, query_string):
    """Helper to process a single batch request in a thread with app context."""
    with app.test_request_context(query_string=query_string):
        try:
            # Call handler and extract JSON from Response
            response = handler()
            if hasattr(response, 'get_json'):
                result = response.get_json()
            elif hasattr(response, 'json'):
                result = response.json
            else:
                result = None
            return endpoint_name, result, None
        except Exception as e:
            return endpoint_name, None, str(e)


@bp.route("/api/stats/batch", methods=['POST'])
@throttle(10, 20)
def api_stats_batch():
    """Batch endpoint: accepts list of endpoint names, returns combined response.

    Requests are processed in parallel using ThreadPoolExecutor to reduce total latency.
    """
    # Import handlers locally to avoid circular dependencies
    from app.api.routes.system import api_stats_summary
    from app.api.routes.security import api_threats, api_alerts

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

        # Process requests in parallel using ThreadPoolExecutor
        # Get the real app object to pass to threads (current_app is a proxy)
        app_obj = current_app._get_current_object()

        futures = []
        # Ensure at least 1 worker (though check above ensures requests_list is not empty)
        max_workers = max(min(len(requests_list), 10), 1)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
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

                handler = handlers[endpoint_name]
                futures.append(executor.submit(process_batch_request, app_obj, endpoint_name, handler, query_string))

            for future in futures:
                endpoint_name, result, error = future.result()
                if error:
                    errors[endpoint_name] = error
                elif result:
                    results[endpoint_name] = result

        response_data = {'results': results}
        if errors:
            response_data['errors'] = errors

        return jsonify(response_data)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# Performance metrics endpoint

