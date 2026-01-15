"""SNMP service module for PROX_NFDUMP application.

This module handles SNMP polling of OPNsense firewall for health metrics.
"""
import subprocess
import threading
import time

# Import state module to modify SNMP state
import app.core.state as state
from app.core.state import _shutdown_event

# Import config
from app.config import SNMP_HOST, SNMP_COMMUNITY, SNMP_OIDS, SNMP_POLL_INTERVAL, SNMP_CACHE_TTL

# Import formatters
from app.utils.formatters import format_uptime
from app.utils.observability import instrument_service


@instrument_service('get_snmp_data')
def get_snmp_data():
    """Fetch SNMP data from OPNsense firewall with exponential backoff.
    
    OBSERVABILITY: Instrumented to track execution time and call frequency.
    """
    now = time.time()
    
    with state._snmp_cache_lock:
        if state._snmp_cache["data"] and now - state._snmp_cache["ts"] < SNMP_CACHE_TTL:
            return state._snmp_cache["data"]
    
    # Check if we're in backoff period
    if state._snmp_backoff["failures"] > 0:
        backoff_delay = min(
            state._snmp_backoff["base_delay"] * (2 ** (state._snmp_backoff["failures"] - 1)),
            state._snmp_backoff["max_delay"]
        )
        if now - state._snmp_backoff["last_failure"] < backoff_delay:
            # Return cached data if available, otherwise empty
            with state._snmp_cache_lock:
                return state._snmp_cache.get("data") or {"error": "SNMP unreachable", "backoff": True}
    
    try:
        result = {}
        oids = " ".join(SNMP_OIDS.values())
        cmd = f"snmpget -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} {oids}"
        
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5, text=True)
        values = output.strip().split("\n")
        
        oid_keys = list(SNMP_OIDS.keys())
        for i, value in enumerate(values):
            if i < len(oid_keys):
                key = oid_keys[i]
                clean_val = value.strip().strip("\"")
                
                if key.startswith("cpu_load"):
                    result[key] = float(clean_val)
                elif key.startswith("mem_") or key.startswith("swap_") or key in (
                    "tcp_conns", "tcp_active_opens", "tcp_estab_resets",
                    "proc_count",
                    "tcp_fails", "tcp_retrans",
                    "ip_in_discards", "ip_in_hdr_errors", "ip_in_addr_errors", "ip_forw_datagrams", "ip_in_delivers", "ip_out_requests",
                    "icmp_in_errors",
                    "wan_in", "wan_out", "lan_in", "lan_out",
                    "wan_speed", "lan_speed",
                    "wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                    "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc",
                    "disk_read", "disk_write", "udp_in", "udp_out"
                ):
                    # Handle Counter64 prefix if present
                    if "Counter64:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    # Handle Counter32 prefix if present
                    if "Counter32:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    try:
                        result[key] = int(clean_val)
                    except:
                        result[key] = 0
                else:
                    result[key] = clean_val
        
        if "mem_total" in result and "mem_avail" in result:
            # FreeBSD memory calculation: total - available - buffer - cached
            # Using OID .15 (memShared/Cached ~3GB) gives better accuracy
            # This should be close to OPNsense's Active+Wired memory calculation
            # Expected: ~60-65% vs OPNsense ~55-60%
            mem_buffer = result.get("mem_buffer", 0)
            mem_cached = result.get("mem_cached", 0)
            mem_used = result["mem_total"] - result["mem_avail"] - mem_buffer - mem_cached
            result["mem_used"] = mem_used
            try:
                result["mem_percent"] = round((mem_used / result["mem_total"]) * 100, 1) if result["mem_total"] > 0 else 0
            except Exception:
                result["mem_percent"] = 0

        # Swap usage
        if result.get("swap_total") not in (None, 0) and "swap_avail" in result:
            swap_used = max(result["swap_total"] - result["swap_avail"], 0)
            result["swap_used"] = swap_used
            try:
                result["swap_percent"] = round((swap_used / result.get("swap_total", 1)) * 100, 1) if result.get("swap_total", 0) > 0 else 0
            except Exception:
                result["swap_percent"] = 0
        
        if "cpu_load_1min" in result:
            result["cpu_percent"] = min(round((result["cpu_load_1min"] / 4.0) * 100, 1), 100)
        
        # Interface speeds (Mbps)
        if "wan_speed" in result:
            result["wan_speed_mbps"] = int(result.get("wan_speed", 0))
        if "lan_speed" in result:
            result["lan_speed_mbps"] = int(result.get("lan_speed", 0))

        # Compute interface rates (Mbps) using 64-bit counters and previous sample
        prev_ts = state._snmp_prev_sample.get("ts", 0)
        dt = max(1.0, now - prev_ts) if prev_ts > 0 else SNMP_POLL_INTERVAL
        
        # Calculate interface rates if we have previous sample
        if prev_ts > 0 and dt > 0:
            for prefix in ("wan", "lan"):
                in_key = f"{prefix}_in"
                out_key = f"{prefix}_out"
                if in_key in result and out_key in result:
                    prev_in = state._snmp_prev_sample.get(in_key, 0)
                    prev_out = state._snmp_prev_sample.get(out_key, 0)
                    d_in = result[in_key] - prev_in
                    d_out = result[out_key] - prev_out
                    # Guard against wrap or reset (allow small negative due to counter wrap)
                    if d_in < 0:
                        # Counter wrapped - use current value as estimate
                        d_in = result[in_key]
                    if d_out < 0:
                        d_out = result[out_key]
                    # Calculate rates in Mbps
                    rx_mbps = (d_in * 8.0) / (dt * 1_000_000)
                    tx_mbps = (d_out * 8.0) / (dt * 1_000_000)
                    result[f"{prefix}_rx_mbps"] = round(rx_mbps, 2)
                    result[f"{prefix}_tx_mbps"] = round(tx_mbps, 2)
                    # Utilization if speed known
                    spd = result.get(f"{prefix}_speed_mbps") or result.get(f"{prefix}_speed")
                    if spd and spd > 0:
                        util = ((rx_mbps + tx_mbps) / (spd)) * 100.0
                        result[f"{prefix}_util_percent"] = round(util, 1)
                else:
                    # Counters not available - mark rates as None
                    result[f"{prefix}_rx_mbps"] = None
                    result[f"{prefix}_tx_mbps"] = None
                    result[f"{prefix}_util_percent"] = None

            # Generic counter rates (/s) for selected counters
            rate_keys = [
                "tcp_active_opens", "tcp_estab_resets",
                "tcp_fails", "tcp_retrans",
                "ip_in_discards", "ip_in_hdr_errors", "ip_in_addr_errors",
                "ip_forw_datagrams", "ip_in_delivers", "ip_out_requests",
                "icmp_in_errors",
                "udp_in", "udp_out",
                # Interface errors/discards (compute deltas for /s)
                "wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc"
            ]
            for k in rate_keys:
                if k in result:
                    prev_v = state._snmp_prev_sample.get(k, result[k])
                    d = result[k] - prev_v
                    if d < 0:
                        # Counter wrapped or reset - use current value
                        d = result[k]
                    result[f"{k}_s"] = round(d / dt, 2) if dt > 0 else 0
                else:
                    # Counter not available
                    result[f"{k}_s"] = None
        else:
            # First poll or no previous sample - mark rates as unavailable
            for prefix in ("wan", "lan"):
                result[f"{prefix}_rx_mbps"] = None
                result[f"{prefix}_tx_mbps"] = None
                result[f"{prefix}_util_percent"] = None
            # Mark error/discard rates as unavailable
            for k in ["wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                     "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc"]:
                result[f"{k}_s"] = None
        
        # Update previous sample - always store current values for next calculation
        state._snmp_prev_sample = {
            "ts": now,
            "wan_in": result.get("wan_in", 0),
            "wan_out": result.get("wan_out", 0),
            "lan_in": result.get("lan_in", 0),
            "lan_out": result.get("lan_out", 0),
            # Persist counter snapshots for rate calc next tick
            "tcp_active_opens": result.get("tcp_active_opens", 0),
            "tcp_estab_resets": result.get("tcp_estab_resets", 0),
            "tcp_fails": result.get("tcp_fails", 0),
            "tcp_retrans": result.get("tcp_retrans", 0),
            "ip_in_discards": result.get("ip_in_discards", 0),
            "ip_in_hdr_errors": result.get("ip_in_hdr_errors", 0),
            "ip_in_addr_errors": result.get("ip_in_addr_errors", 0),
            "ip_forw_datagrams": result.get("ip_forw_datagrams", 0),
            "ip_in_delivers": result.get("ip_in_delivers", 0),
            "ip_out_requests": result.get("ip_out_requests", 0),
            "icmp_in_errors": result.get("icmp_in_errors", 0),
            "udp_in": result.get("udp_in", 0),
            "udp_out": result.get("udp_out", 0),
            # Store error/discard counters for rate calculation
            "wan_in_err": result.get("wan_in_err", 0),
            "wan_out_err": result.get("wan_out_err", 0),
            "wan_in_disc": result.get("wan_in_disc", 0),
            "wan_out_disc": result.get("wan_out_disc", 0),
            "lan_in_err": result.get("lan_in_err", 0),
            "lan_out_err": result.get("lan_out_err", 0),
            "lan_in_disc": result.get("lan_in_disc", 0),
            "lan_out_disc": result.get("lan_out_disc", 0),
        }

        # Format uptime for readability
        if "sys_uptime" in result:
            result["sys_uptime_formatted"] = format_uptime(result["sys_uptime"])
        
        # Reset backoff on success
        state._snmp_backoff["failures"] = 0
        
        with state._snmp_cache_lock:
            state._snmp_cache["data"] = result
            state._snmp_cache["ts"] = now
        
        return result
        
    except Exception as e:
        # Increment backoff on failure
        state._snmp_backoff["failures"] = min(state._snmp_backoff["failures"] + 1, state._snmp_backoff["max_failures"])
        state._snmp_backoff["last_failure"] = now
        backoff_delay = min(
            state._snmp_backoff["base_delay"] * (2 ** (state._snmp_backoff["failures"] - 1)),
            state._snmp_backoff["max_delay"]
        )
        print(f"SNMP Error: {e} (backoff: {backoff_delay}s, failures: {state._snmp_backoff['failures']})")
        # Return cached data if available
        with state._snmp_cache_lock:
            return state._snmp_cache.get("data") or {"error": str(e), "backoff": True}


def start_snmp_thread():
    """Start background SNMP polling to enable near real-time updates."""
    if state._snmp_thread_started:
        return
    state._snmp_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            try:
                # This will update the cache and compute deltas
                get_snmp_data()
            except Exception:
                pass
            _shutdown_event.wait(timeout=max(0.2, SNMP_POLL_INTERVAL))

    t = threading.Thread(target=loop, daemon=True, name='SNMPPollerThread')
    t.start()
