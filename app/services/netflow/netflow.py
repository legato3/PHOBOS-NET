"""NetFlow service for nfdump operations and CSV parsing."""
import os
import subprocess
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from app.config import DEFAULT_TIMEOUT, SAMPLE_DATA_PATH, COMMON_DATA_CACHE_MAX, NFCAPD_DIR
from app.services.shared.helpers import get_time_range

# Global state for nfdump service
# NOTE: Mock data functionality disabled for production use
# _mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
# _mock_lock = threading.Lock()
import app.core.app_state as state
from app.core.app_state import add_app_log
_common_data_cache = {}
_common_data_lock = threading.Lock()


# Mock nfdump function DISABLED for production
# The system should show real data only, not fake sample data
# If you need to test without nfdump, re-enable this function
"""
def mock_nfdump(args):
    # Mock nfdump function for development/testing when nfdump is not available.
    # DISABLED: This function provided fake data which could mask real issues.
    return ""
"""


def run_nfdump(args, tf=None):
    """Run nfdump command and return CSV output.

    OBSERVABILITY: Instrumented to track execution time, success/failure, and timeouts.
    """
    state._metric_nfdump_calls += 1
    
    # OBSERVABILITY: Track subprocess execution with timing
    from app.services.shared.observability import instrument_subprocess
    from app.services.shared.metrics import track_subprocess
    
    start_time = time.time()
    success = False
    timeout = False
    
    try:
        # PERFORMANCE: Check nfdump availability. Retry if previously failed.
        if state._has_nfdump is not True:
            try:
                subprocess.run(["nfdump", "-V"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
                state._has_nfdump = True
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                state._has_nfdump = False
        
        # Try running actual nfdump first
        if state._has_nfdump:
            try:
                cmd = ["nfdump", "-R", NFCAPD_DIR, "-o", "csv"]
                if tf:
                    cmd.extend(["-t", tf])
                cmd.extend(args)
                
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT)
                if r.returncode == 0:
                    # nfdump ran successfully - return stdout even if empty (no data for time range)
                    success = True
                    result = r.stdout if r.stdout else ""
                else:
                    # Subprocess ran but failed (non-zero exit code)
                    error_msg = r.stderr.strip() if r.stderr else "Unknown error"
                    add_app_log(f"nfdump failed (code {r.returncode}): {error_msg}", 'WARN')
                    result = None
            except subprocess.TimeoutExpired:
                timeout = True
                add_app_log(f"nfdump timed out after {DEFAULT_TIMEOUT}s: {' '.join(cmd)}", 'WARN')
                result = None
            except Exception as e:
                add_app_log(f"nfdump execution error: {e}", 'ERROR')
                result = None
        else:
            result = None
        
        # NOTE: Mock fallback DISABLED for production - return empty data instead
        # if result is None:
        #     result = mock_nfdump(args)
        #     if result:
        #         success = True
        
        # Ensure we always return a string, never None
        return result if result is not None else ""
    finally:
        # OBSERVABILITY: Track subprocess metrics
        duration = time.time() - start_time
        track_subprocess(duration, success, timeout)


def parse_csv(output, expected_key=None):
    """Parse nfdump CSV output into structured data."""
    results = []
    # Defensive check: ensure output is a string (handle None case)
    if output is None:
        return results
    if not output:
        return results
        
    lines = output.strip().split("\n")
    if not lines:
        return results
    
    # Header detection - Scan for the real CSV header (starts with ts,)
    # This skips warnings like "Command line switch -s overwrites -a"
    header_idx = -1
    for i, line in enumerate(lines):
        if line.lower().startswith('ts,'):
            header_idx = i
            break
            
    if header_idx != -1:
        header_line = lines[header_idx].lower()
        start_row_idx = header_idx + 1
    else:
        # Fallback to first line if no standard header found
        header_line = lines[0].lower()
        start_row_idx = 1
        
    cols = [c.strip() for c in header_line.split(',')]
    
    try:
        key_idx = -1
        
        # Priority check for expected key
        if expected_key:
            if 'val' in cols:
                key_idx = cols.index('val')
            elif expected_key in cols:
                key_idx = cols.index(expected_key)
            elif expected_key == 'proto' and 'pr' in cols:
                key_idx = cols.index('pr')
            elif expected_key == 'proto' and 'proto' in cols:
                key_idx = cols.index('proto')
        
        if key_idx == -1:
            if 'val' in cols:
                key_idx = cols.index('val')
            elif 'sa' in cols:
                key_idx = cols.index('sa')
            elif 'da' in cols:
                key_idx = cols.index('da')
            elif 'sp' in cols:
                key_idx = cols.index('sp')
            elif 'dp' in cols:
                key_idx = cols.index('dp')
            elif 'pr' in cols:
                key_idx = cols.index('pr')
            elif 'proto' in cols:
                key_idx = cols.index('proto')
        
        if key_idx == -1:
            key_idx = 4
        
        # Value columns
        bytes_idx = -1
        if 'ibyt' in cols:
            bytes_idx = cols.index('ibyt')
        elif 'byt' in cols:
            bytes_idx = cols.index('byt')
        elif 'bytes' in cols:
            bytes_idx = cols.index('bytes')
        elif 'obyt' in cols: 
            bytes_idx = cols.index('obyt')
        
        flows_idx = -1
        if 'fl' in cols:
            flows_idx = cols.index('fl')
        elif 'flows' in cols:
            flows_idx = cols.index('flows')
        
        packets_idx = -1
        if 'ipkt' in cols:
            packets_idx = cols.index('ipkt')
        elif 'pkt' in cols:
            packets_idx = cols.index('pkt')
        elif 'packets' in cols:
            packets_idx = cols.index('packets')
        elif 'opkt' in cols:
            packets_idx = cols.index('opkt')
        
        if bytes_idx == -1:
            bytes_idx = 12
        
    except ValueError as e:
        add_app_log(f"CSV Header Parse Error: {e}", "ERROR")
        return results
    
    seen_keys = set()

    # PERFORMANCE: Pre-calculate required length to avoid repetitive max() calls and len checks
    indices_to_check = [key_idx, bytes_idx]
    if flows_idx != -1: indices_to_check.append(flows_idx)
    if packets_idx != -1: indices_to_check.append(packets_idx)
    required_len = max(indices_to_check) + 1

    for line in lines[start_row_idx:]:
        if not line:
            continue
        if 'ts,' in line or 'te,' in line or 'Date first seen' in line:
            continue
        parts = line.split(",")

        # PERFORMANCE: Use pre-calculated length check
        if len(parts) < required_len:
            continue
        try:
            key = parts[key_idx]
            if not key or "/" in key or key == "any":
                continue
            if key in seen_keys:
                continue
            seen_keys.add(key)
            bytes_val = int(float(parts[bytes_idx]))
            # PERFORMANCE: Simplified checks using logic that required_len ensures existence
            flows_val = int(float(parts[flows_idx])) if flows_idx != -1 else 0
            packets_val = int(float(parts[packets_idx])) if packets_idx != -1 else 0
            if bytes_val > 0:
                # Extract timestamps (usually indexes 0 and 1 for -o csv)
                ts = parts[0]
                te = parts[1]
                # Validate they look like timestamps (simple check)
                # nfdump csv dates are usually strings "2023-..." which simple-json works with, 
                # or we keep them as provided string
                
                results.append({
                    "key": key, 
                    "bytes": bytes_val, 
                    "flows": flows_val, 
                    "packets": packets_val,
                    "ts": ts,
                    "te": te
                })
        except Exception:
            # Silent continue on individual row parse error is acceptable to skip bad rows
            continue
    
    # --- INGESTION METRICS ---
    try:
        if len(results) > 0:
            from app.services.shared.ingestion_metrics import ingestion_tracker
            ingestion_tracker.track_netflow(len(results))
    except Exception:
        pass
    # -------------------------
    
    return results


# PERFORMANCE: Cache traffic direction queries (IP + time range) to avoid redundant nfdump calls
_traffic_direction_cache = {}
_traffic_direction_lock = threading.Lock()
_TRAFFIC_DIRECTION_TTL = 60  # 1 minute cache


def get_traffic_direction(ip, tf):
    """Get upload/download traffic for an IP."""
    # PERFORMANCE: Cache result to avoid redundant nfdump subprocess calls
    now = time.time()
    cache_key = f"{ip}:{tf}"
    
    with _traffic_direction_lock:
        if cache_key in _traffic_direction_cache:
            entry = _traffic_direction_cache[cache_key]
            if now - entry["ts"] < _TRAFFIC_DIRECTION_TTL:
                return entry["data"]
    
    # Fetch data (two nfdump calls)
    # Filter must be LAST arguments
    # PERFORMANCE: Run queries in parallel to reduce latency
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_out = executor.submit(run_nfdump, ["-s", "srcip/bytes", "-n", "1", "src", "ip", ip], tf)
        future_in = executor.submit(run_nfdump, ["-s", "dstip/bytes", "-n", "1", "dst", "ip", ip], tf)

        out = future_out.result()
        in_data = future_in.result()

    out_parsed = parse_csv(out, expected_key='sa')
    in_parsed = parse_csv(in_data, expected_key='da')
    upload = out_parsed[0]["bytes"] if out_parsed else 0
    download = in_parsed[0]["bytes"] if in_parsed else 0
    result = {"upload": upload, "download": download, "ratio": round(upload / download, 2) if download > 0 else 0}
    
    # PERFORMANCE: Cache result before returning
    with _traffic_direction_lock:
        _traffic_direction_cache[cache_key] = {"data": result, "ts": now}
        # Prune cache if too large (keep last 100)
        if len(_traffic_direction_cache) > 100:
            # Remove oldest entries
            sorted_items = sorted(_traffic_direction_cache.items(), key=lambda kv: kv[1]["ts"])
            for k, _ in sorted_items[:max(1, len(sorted_items) - 100)]:
                _traffic_direction_cache.pop(k, None)
    
    return result


def get_common_nfdump_data(query_type, range_key):
    """Shared data fetcher for common queries (sources, ports, dests, protos)."""
    now = time.time()
    win = int(now // 60)
    cache_key = f"{query_type}:{range_key}:{win}"
    
    with _common_data_lock:
        entry = _common_data_cache.get(cache_key)
        if entry:
            return entry["data"]
    
    tf = get_time_range(range_key)
    data = []
    
    if query_type == "sources":
        data = parse_csv(run_nfdump(["-s", "srcip/bytes/flows/packets", "-n", "100"], tf), expected_key='sa')
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "ports":
        data = parse_csv(run_nfdump(["-s", "dstport/bytes/flows", "-n", "100"], tf), expected_key='dp')
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "dests":
        data = parse_csv(run_nfdump(["-s", "dstip/bytes/flows/packets", "-n", "100"], tf), expected_key='da')
        data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
    elif query_type == "protos":
        data = parse_csv(run_nfdump(["-s", "proto/bytes/flows/packets", "-n", "20"], tf), expected_key='proto')
    
    with _common_data_lock:
        _common_data_cache[cache_key] = {"data": data, "ts": now, "win": win}
        if len(_common_data_cache) > COMMON_DATA_CACHE_MAX:
            drop_count = max(1, COMMON_DATA_CACHE_MAX // 5)
            # Ensure ts is always a float for comparison
            oldest = sorted(_common_data_cache.items(), key=lambda kv: float(kv[1]["ts"]) if isinstance(kv[1]["ts"], (int, float)) else kv[1]["ts"].timestamp())[:drop_count]
            for k, _ in oldest:
                _common_data_cache.pop(k, None)
    
    return data


def get_merged_host_stats(range_key="24h", limit=1000):
    """Get aggregated host statistics (merged src/dst).
    
    Derived entirely from nfdump data.
    """
    # PERFORMANCE: Cache result to avoid heavy nfdump 48h queries
    now = time.time()
    cache_key = f"merged_host_stats:{range_key}"
    cache_ttl = 60  # seconds

    with _common_data_lock:
        cached = _common_data_cache.get(cache_key)
        if cached:
            # Ensure ts is always a float for comparison
            cached_ts = float(cached["ts"]) if isinstance(cached["ts"], (int, float)) else cached["ts"].timestamp()
            if (now - cached_ts) < cache_ttl:
                return cached["data"]
            
    tf = get_time_range(range_key)
    
    # Run two queries: Sources (TX) and Destinations (RX) in parallel
    # Fixed higher limit for traffic matrix cache efficiency
    query_limit = max(200, limit * 2)  # Minimum 200 for matrix, 2x for safety
    src_cmd = ["-s", "srcip/bytes/flows", "-n", str(query_limit)]
    dst_cmd = ["-s", "dstip/bytes/flows", "-n", str(query_limit)]
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_src = executor.submit(run_nfdump, src_cmd, tf)
        future_dst = executor.submit(run_nfdump, dst_cmd, tf)
        
        src_rows = parse_csv(future_src.result(), expected_key='sa')
        dst_rows = parse_csv(future_dst.result(), expected_key='da')
    
    hosts = {}
    
    def parse_time(t_str):
        if not t_str: return "0"
        # Handle "2023-01-01 12:00:00.123"
        # nfdump csv usually YYYY-MM-DD HH:MM:SS.msec
        # Lexical sort works for ISO-like dates nfdump uses.
        return t_str

    # Process TX (Source) - Host is sending
    for row in src_rows:
        ip = row.get("key")
        if not ip: continue
        
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "tx_bytes": 0, "rx_bytes": 0, "tx_flows": 0, "rx_flows": 0, "first_seen": row.get("ts"), "last_seen": row.get("te")}
            
        hosts[ip]["tx_bytes"] += row.get("bytes", 0)
        hosts[ip]["tx_flows"] += row.get("flows", 0)
        
        # Merge times
        if row.get("ts") and (not hosts[ip]["first_seen"] or row.get("ts") < hosts[ip]["first_seen"]):
             hosts[ip]["first_seen"] = row.get("ts")
        if row.get("te") and (not hosts[ip]["last_seen"] or row.get("te") > hosts[ip]["last_seen"]):
             hosts[ip]["last_seen"] = row.get("te")

    # Process RX (Destination) - Host is receiving
    for row in dst_rows:
        ip = row.get("key")
        if not ip: continue
        
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "tx_bytes": 0, "rx_bytes": 0, "tx_flows": 0, "rx_flows": 0, "first_seen": row.get("ts"), "last_seen": row.get("te")}
            
        hosts[ip]["rx_bytes"] += row.get("bytes", 0)
        hosts[ip]["rx_flows"] += row.get("flows", 0)
        
        # Merge times
        if row.get("ts") and (not hosts[ip]["first_seen"] or row.get("ts") < hosts[ip]["first_seen"]):
             hosts[ip]["first_seen"] = row.get("ts")
        if row.get("te") and (not hosts[ip]["last_seen"] or row.get("te") > hosts[ip]["last_seen"]):
             hosts[ip]["last_seen"] = row.get("te")
    
    # Update host memory with first_seen timestamps
    from app.db.sqlite import update_host_memory, get_hosts_memory

    # Run update synchronously to ensure persisted data is available for enrichment
    # This is critical for the "new hosts" baseline logic to work correctly
    update_host_memory(hosts)

    # Get persisted first_seen timestamps from memory (batch query)
    ip_list = list(hosts.keys())
    memory_data = get_hosts_memory(ip_list) if ip_list else {}
    
    # Convert to list and enrich
    import ipaddress
    from datetime import datetime, timedelta
    
    result = []
    now = datetime.now()
    cutoff_24h = now - timedelta(hours=24)
    
    for ip, data in hosts.items():
        # Determine Type (Internal/External)
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_internal = ip_obj.is_private
        except ValueError:
            is_internal = False
            
        data["type"] = "Internal" if is_internal else "External"
        data["total_bytes"] = data["tx_bytes"] + data["rx_bytes"]
        
        # Compute flows metric:
        # - 'flows': Approximate unique flows (max of TX/RX, since same flows appear in both)
        # - 'flow_contributions': Total TX + RX (for debugging/transparency, may double-count)
        data["flows"] = max(data.get("tx_flows", 0), data.get("rx_flows", 0))
        data["flow_contributions"] = data.get("tx_flows", 0) + data.get("rx_flows", 0)
        
        # Use persisted first_seen from memory if available, otherwise use flow-based first_seen
        memory = memory_data.get(ip)
        if memory:
            # Use persisted first_seen (first-ever-seen)
            data["first_seen"] = memory["first_seen_iso"]
            # Parse to determine if new (first seen within 24h)
            try:
                timestamp_str = memory["first_seen_iso"].split('.')[0] if '.' in memory["first_seen_iso"] else memory["first_seen_iso"]
                first_seen_dt = datetime.strptime(timestamp_str.strip(), '%Y-%m-%d %H:%M:%S')
                data["is_new"] = first_seen_dt > cutoff_24h
            except (ValueError, AttributeError):
                data["is_new"] = False
        else:
            # No memory yet - use flow-based first_seen and mark as potentially new
            # (will be persisted on next update)
            if data.get("first_seen"):
                try:
                    timestamp_str = data["first_seen"].split('.')[0] if '.' in data["first_seen"] else data["first_seen"]
                    first_seen_dt = datetime.strptime(timestamp_str.strip(), '%Y-%m-%d %H:%M:%S')
                    data["is_new"] = first_seen_dt > cutoff_24h
                except (ValueError, AttributeError):
                    data["is_new"] = False
            else:
                data["is_new"] = False
        
        result.append(data)
        
    # Sort by total volume
    result.sort(key=lambda x: x["total_bytes"], reverse=True)
    
    with _common_data_lock:
        # Cache the full result (not limit-sliced) for reuse
        _common_data_cache[cache_key] = {"data": result, "ts": now}
        
    return result[:limit]


def get_raw_flows(tf, limit=2000):
    """Fetch and parse raw flows for detection (sa, da, sp, dp, proto)."""
    try:
        # Request raw flows with specific fields if possible, or standard CSV
        # nfdump -o csv provides fixed columns.
        raw_flows_output = run_nfdump(["-o", "csv", "-n", str(limit)], tf)
        flow_data = []

        if raw_flows_output:
            lines = raw_flows_output.strip().split("\n")
            if len(lines) > 1:
                # Find header line
                header_idx = -1
                for i, line in enumerate(lines):
                    if 'ts,' in line.lower() or 'sa,' in line.lower():
                        header_idx = i
                        break

                if header_idx != -1:
                    header = lines[header_idx].lower().split(',')
                    try:
                        sa_idx = -1
                        if 'sa' in header: sa_idx = header.index('sa')
                        elif 'srcaddr' in header: sa_idx = header.index('srcaddr')

                        da_idx = -1
                        if 'da' in header: da_idx = header.index('da')
                        elif 'dstaddr' in header: da_idx = header.index('dstaddr')

                        sp_idx = -1
                        if 'sp' in header: sp_idx = header.index('sp')
                        elif 'srcport' in header: sp_idx = header.index('srcport')

                        dp_idx = -1
                        if 'dp' in header: dp_idx = header.index('dp')
                        elif 'dstport' in header: dp_idx = header.index('dstport')

                        pr_idx = -1
                        if 'pr' in header: pr_idx = header.index('pr')
                        elif 'proto' in header: pr_idx = header.index('proto')

                        ibyt_idx = -1
                        if 'ibyt' in header: ibyt_idx = header.index('ibyt')
                        elif 'bytes' in header: ibyt_idx = header.index('bytes')
                        elif 'byt' in header: ibyt_idx = header.index('byt')

                        if sa_idx != -1 and da_idx != -1:
                            # PERFORMANCE: Pre-calculate minimum required length (just sa/da)
                            # We can't enforce full length for optional fields to preserve original permissive behavior
                            min_required_len = max(sa_idx, da_idx) + 1

                            for line in lines[header_idx+1:]:
                                if not line or 'sys:' in line or 'summary' in line: continue
                                parts = line.split(',')
                                if len(parts) < min_required_len: continue

                                # Use local length variable to avoid repeated len() calls
                                p_len = len(parts)

                                flow_data.append({
                                    "src_ip": parts[sa_idx],
                                    "dst_ip": parts[da_idx],
                                    "src_port": parts[sp_idx] if sp_idx != -1 and p_len > sp_idx else "0",
                                    "dst_port": parts[dp_idx] if dp_idx != -1 and p_len > dp_idx else "0",
                                    "proto": parts[pr_idx] if pr_idx != -1 and p_len > pr_idx else "0",
                                    "bytes": int(float(parts[ibyt_idx])) if ibyt_idx != -1 and p_len > ibyt_idx else 0,
                                    "flows": 1
                                })
                    except Exception as e:
                        add_app_log(f"Flow parsing error: {e}", "ERROR")
        return flow_data
    except Exception as e:
        add_app_log(f"Error fetching raw flows: {e}", "ERROR")
        return []