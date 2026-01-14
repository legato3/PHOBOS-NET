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
_has_nfdump = None
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
    """Run nfdump command and return CSV output."""
    global _metric_nfdump_calls, _has_nfdump
    _metric_nfdump_calls += 1
    
    # Try running actual nfdump first
    try:
        cmd = ["nfdump", "-R", "/var/cache/nfdump", "-o", "csv"]
        if tf:
            cmd.extend(["-t", tf])
        cmd.extend(args)
        
        if _has_nfdump is None:
            _has_nfdump = (subprocess.call(["which", "nfdump"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0)
        
        if _has_nfdump:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=DEFAULT_TIMEOUT)
            if r.returncode == 0 and r.stdout:
                return r.stdout
    except Exception:
        pass
    
    # Fallback to mock
    return mock_nfdump(args)


def parse_csv(output, expected_key=None):
    """Parse nfdump CSV output into structured data."""
    results = []
    lines = output.strip().split("\n")
    if not lines:
        return results
    
    # Header detection
    header_line = lines[0].lower()
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
        
        if bytes_idx == -1:
            bytes_idx = 12
        
    except ValueError:
        return results
    
    seen_keys = set()
    for line in lines[1:]:
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
                results.append({"key": key, "bytes": bytes_val, "flows": flows_val, "packets": packets_val})
        except Exception:
            continue
    return results


def get_traffic_direction(ip, tf):
    """Get upload/download traffic for an IP."""
    out = run_nfdump(["-a", f"src ip {ip}", "-s", "srcip/bytes", "-n", "1"], tf)
    in_data = run_nfdump(["-a", f"dst ip {ip}", "-s", "dstip/bytes", "-n", "1"], tf)
    out_parsed = parse_csv(out, expected_key='sa')
    in_parsed = parse_csv(in_data, expected_key='da')
    upload = out_parsed[0]["bytes"] if out_parsed else 0
    download = in_parsed[0]["bytes"] if in_parsed else 0
    return {"upload": upload, "download": download, "ratio": round(upload / download, 2) if download > 0 else 0}


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