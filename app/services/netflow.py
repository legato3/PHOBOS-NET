"""NetFlow service for nfdump operations and CSV parsing."""
import os
import subprocess
import threading
import time
from collections import defaultdict
from app.config import DEFAULT_TIMEOUT, SAMPLE_DATA_PATH, COMMON_DATA_CACHE_MAX
from app.utils.helpers import get_time_range

# Global state for nfdump service
_mock_data_cache = {"mtime": 0, "rows": [], "output_cache": {}}
_mock_lock = threading.Lock()
import app.core.state as state
_common_data_cache = {}
_common_data_lock = threading.Lock()
_metric_nfdump_calls = 0


def mock_nfdump(args):
    """Mock nfdump function for development/testing when nfdump is not available."""
    global _mock_data_cache
    
    with _mock_lock:
        cache_key = tuple(args)
        if "output_cache" in _mock_data_cache and cache_key in _mock_data_cache["output_cache"]:
            return _mock_data_cache["output_cache"][cache_key]
        
        rows = []
        try:
            mtime = os.path.getmtime(SAMPLE_DATA_PATH)
            if mtime != _mock_data_cache["mtime"]:
                new_rows = []
                with open(SAMPLE_DATA_PATH, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        parts = line.strip().split(',')
                        if len(parts) > 12:
                            try:
                                row = {
                                    "ts": parts[0], "te": parts[1], "td": float(parts[2]),
                                    "sa": parts[3], "da": parts[4], "sp": parts[5], "dp": parts[6],
                                    "proto": parts[7], "flg": parts[8],
                                    "pkts": int(parts[11]), "bytes": int(parts[12])
                                }
                                new_rows.append(row)
                            except:
                                pass
                _mock_data_cache["rows"] = new_rows
                _mock_data_cache["mtime"] = mtime
                _mock_data_cache["output_cache"] = {}
            rows = _mock_data_cache["rows"]
        except Exception as e:
            print(f"Mock error: {e}")
            return ""
    
    # Check aggregation
    agg_key = None
    if "-s" in args:
        idx = args.index("-s") + 1
        stat = args[idx]
        if "srcip" in stat:
            agg_key = "sa"
        elif "dstip" in stat:
            agg_key = "da"
        elif "dstport" in stat:
            agg_key = "dp"
        elif "proto" in stat:
            agg_key = "proto"
    
    limit = 20
    if "-n" in args:
        idx = args.index("-n") + 1
        try:
            limit = int(args[idx])
        except:
            pass
    
    out = ""
    
    # If asking for raw flows with limit
    if not agg_key and "-n" in args and "-s" not in args:
        output_lines = ["ts,te,td,sa,da,sp,dp,proto,flg,fwd,stos,ipkt,ibyt"]
        for r in rows[:limit]:
            output_lines.append(f"{r['ts']},{r['te']},{r['td']},{r['sa']},{r['da']},{r['sp']},{r['dp']},{r['proto']},{r['flg']},0,0,{r['pkts']},{r['bytes']}")
        out = "\n".join(output_lines) + "\n"
        with _mock_lock:
            if "output_cache" not in _mock_data_cache:
                _mock_data_cache["output_cache"] = {}
            _mock_data_cache["output_cache"][cache_key] = out
        return out
    
    if agg_key:
        counts = defaultdict(lambda: {"bytes": 0, "flows": 0, "packets": 0})
        for r in rows:
            k = r.get(agg_key, "other")
            counts[k]["bytes"] += r["bytes"]
            counts[k]["flows"] += 1
            counts[k]["packets"] += r["pkts"]
        
        sorted_keys = sorted(counts.keys(), key=lambda k: counts[k]["bytes"], reverse=True)[:limit]
        output_lines = ["ts,te,td,sa,da,sp,dp,proto,flg,flows,stos,ipkt,ibyt"]
        col_map = {"sa": 3, "da": 4, "sp": 5, "dp": 6, "proto": 7}
        target_idx = col_map.get(agg_key, 4)
        
        for k in sorted_keys:
            d = counts[k]
            row = ["0"] * 13
            row[target_idx] = str(k)
            row[9] = str(d['flows'])
            row[11] = str(d['packets'])
            row[12] = str(d['bytes'])
            output_lines.append(",".join(row))
        
        out = "\n".join(output_lines) + "\n"
        with _mock_lock:
            if "output_cache" not in _mock_data_cache:
                _mock_data_cache["output_cache"] = {}
            _mock_data_cache["output_cache"][cache_key] = out
        return out
    
    return ""


def run_nfdump(args, tf=None):
    """Run nfdump command and return CSV output.
    
    OBSERVABILITY: Instrumented to track execution time, success/failure, and timeouts.
    """
    global _metric_nfdump_calls
    _metric_nfdump_calls += 1
    
    # OBSERVABILITY: Track subprocess execution with timing
    from app.utils.observability import instrument_subprocess
    from app.services.metrics import track_subprocess
    
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
                cmd = ["nfdump", "-R", "/var/cache/nfdump", "-o", "csv"]
                if tf:
                    cmd.extend(["-t", tf])
                cmd.extend(args)
                
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT)
                if r.returncode == 0 and r.stdout:
                    success = True
                    result = r.stdout
                else:
                    # Subprocess ran but failed
                    result = None
            except subprocess.TimeoutExpired:
                timeout = True
                result = None
            except Exception:
                result = None
        else:
            result = None
        
        # Fallback to mock if nfdump failed or unavailable
        if result is None:
            result = mock_nfdump(args)
            if result:
                success = True
        
        return result
    finally:
        # OBSERVABILITY: Track subprocess metrics
        duration = time.time() - start_time
        track_subprocess(duration, success, timeout)


def parse_csv(output, expected_key=None):
    """Parse nfdump CSV output into structured data."""
    results = []
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
        
    except ValueError:
        return results
    
    seen_keys = set()
    for line in lines[start_row_idx:]:
        if not line:
            continue
        if 'ts,' in line or 'te,' in line or 'Date first seen' in line:
            continue
        parts = line.split(",")
        if len(parts) <= max(key_idx, bytes_idx, flows_idx if flows_idx != -1 else 0, packets_idx if packets_idx != -1 else 0):
            continue
        try:
            key = parts[key_idx]
            if not key or "/" in key or key == "any":
                continue
            if key in seen_keys:
                continue
            seen_keys.add(key)
            bytes_val = int(float(parts[bytes_idx]))
            flows_val = int(float(parts[flows_idx])) if flows_idx != -1 and len(parts) > flows_idx else 0
            packets_val = int(float(parts[packets_idx])) if packets_idx != -1 and len(parts) > packets_idx else 0
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
            continue
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
    out = run_nfdump(["-s", "srcip/bytes", "-n", "1", "src", "ip", ip], tf)
    in_data = run_nfdump(["-s", "dstip/bytes", "-n", "1", "dst", "ip", ip], tf)
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
    cache_key = f"{query_type}:{range_key}"
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
            oldest = sorted(_common_data_cache.items(), key=lambda kv: kv[1]["ts"])[:drop_count]
            for k, _ in oldest:
                _common_data_cache.pop(k, None)
    
    return data


def get_merged_host_stats(range_key="24h", limit=1000):
    """Get aggregated host statistics (merged src/dst).
    
    Derived entirely from nfdump data.
    """
    # PERFORMANCE: Cache result to avoid heavy nfdump 48h queries
    now = time.time()
    win = int(now // 60)
    # Different cache key for different limits, though larger limit could satisfy smaller one.
    # For now, keep it simple.
    cache_key = f"merged_host_stats:{range_key}:{limit}:{win}"
    
    with _common_data_lock:
        if cache_key in _common_data_cache:
            return _common_data_cache[cache_key]["data"]
            
    tf = get_time_range(range_key)
    
    # Run two queries: Sources (TX) and Destinations (RX)
    # We ask for a higher limit to handle merging
    src_rows = parse_csv(run_nfdump(["-s", "srcip/bytes/flows", "-n", str(limit * 2)], tf), expected_key='sa')
    dst_rows = parse_csv(run_nfdump(["-s", "dstip/bytes/flows", "-n", str(limit * 2)], tf), expected_key='da')
    
    hosts = {}
    
    def parse_time(t_str):
        if not t_str: return 0
        try:
            # Handle "2023-01-01 12:00:00.123"
            # Return naive string comparison or epoch if possible
            # nfdump csv usually YYYY-MM-DD HH:MM:SS.msec
            # Just keeping string is fine for UI, but for comparison min/max we might need logic.
            # Lexical sort works for ISO-like dates nfdump uses.
            return t_str
        except:
            return "0"

    # Process TX (Source) - Host is sending
    for row in src_rows:
        ip = row.get("key")
        if not ip: continue
        
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "tx_bytes": 0, "rx_bytes": 0, "tx_flows": 0, "rx_flows": 0, "flows": 0, "first_seen": row.get("ts"), "last_seen": row.get("te")}
            
        hosts[ip]["tx_bytes"] += row.get("bytes", 0)
        hosts[ip]["tx_flows"] += row.get("flows", 0)
        hosts[ip]["flows"] += row.get("flows", 0)
        
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
            hosts[ip] = {"ip": ip, "tx_bytes": 0, "rx_bytes": 0, "tx_flows": 0, "rx_flows": 0, "flows": 0, "first_seen": row.get("ts"), "last_seen": row.get("te")}
            
        hosts[ip]["rx_bytes"] += row.get("bytes", 0)
        hosts[ip]["rx_flows"] += row.get("flows", 0)
        hosts[ip]["flows"] += row.get("flows", 0)
        
        # Merge times
        if row.get("ts") and (not hosts[ip]["first_seen"] or row.get("ts") < hosts[ip]["first_seen"]):
             hosts[ip]["first_seen"] = row.get("ts")
        if row.get("te") and (not hosts[ip]["last_seen"] or row.get("te") > hosts[ip]["last_seen"]):
             hosts[ip]["last_seen"] = row.get("te")
    
    # Convert to list and enrich
    import ipaddress
    
    result = []
    for ip, data in hosts.items():
        # Determine Type (Internal/External)
        try:
            ip_obj = ipaddress.ip_address(ip)
            is_internal = ip_obj.is_private
        except ValueError:
            is_internal = False
            
        data["type"] = "Internal" if is_internal else "External"
        data["total_bytes"] = data["tx_bytes"] + data["rx_bytes"]
        result.append(data)
        
    # Sort by total volume
    result.sort(key=lambda x: x["total_bytes"], reverse=True)
    
    final_result = result[:limit]
    
    with _common_data_lock:
        _common_data_cache[cache_key] = {"data": final_result, "ts": now}
        
    return final_result