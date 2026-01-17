"""SNMP service module for PROX_NFDUMP application.

This module handles SNMP polling of OPNsense firewall for health metrics.
"""
import subprocess
import threading
import time

# Import state module to modify SNMP state
import app.core.app_state as state
from app.core.app_state import _shutdown_event

# Import config
from app.config import SNMP_HOST, SNMP_COMMUNITY, SNMP_OIDS, SNMP_POLL_INTERVAL, SNMP_CACHE_TTL

# Import formatters
from app.services.shared.formatters import format_uptime
from app.services.shared.observability import instrument_service


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
        
        # Debug: Log interface counter retrieval
        interface_keys = ["wan_in", "wan_out", "lan_in", "lan_out", 
                         "wan_in_err", "wan_out_err", "wan_in_disc", "wan_out_disc",
                         "lan_in_err", "lan_out_err", "lan_in_disc", "lan_out_disc"]
        
        for i, value in enumerate(values):
            if i < len(oid_keys):
                key = oid_keys[i]
                clean_val = value.strip().strip("\"")
                
                # Skip empty or error responses
                if not clean_val or clean_val.startswith("No Such") or clean_val.startswith("No more variables"):
                    if key in interface_keys:
                        print(f"SNMP Warning: {key} (OID {SNMP_OIDS[key]}) returned: {clean_val}")
                    continue
                
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
                    "disk_read", "disk_write", "udp_in", "udp_out",
                    "if_wan_status", "if_lan_status", "if_wan_admin", "if_lan_admin"
                ):
                    # Handle Counter64 prefix if present
                    if "Counter64:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    # Handle Counter32 prefix if present
                    if "Counter32:" in clean_val:
                        clean_val = clean_val.split(":")[-1].strip()
                    try:
                        result[key] = int(clean_val)
                    except (ValueError, TypeError):
                        # Don't default to 0 for interface counters - use None to indicate missing
                        if key in interface_keys:
                            result[key] = None
                            print(f"SNMP Warning: {key} could not be parsed as integer: {clean_val}")
                        else:
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
                
                # Only calculate if we have valid counter values (not None)
                if in_key in result and result[in_key] is not None and out_key in result and result[out_key] is not None:
                    prev_in = state._snmp_prev_sample.get(in_key)
                    prev_out = state._snmp_prev_sample.get(out_key)
                    
                    # Need previous values to calculate delta
                    if prev_in is not None and prev_out is not None:
                        d_in = result[in_key] - prev_in
                        d_out = result[out_key] - prev_out
                        # Guard against wrap or reset
                        if d_in < 0:
                            result[f"{prefix}_rx_mbps"] = None
                        else:
                            # Calculate rates in Mbps
                            rx_mbps = (d_in * 8.0) / (dt * 1_000_000)
                            result[f"{prefix}_rx_mbps"] = round(rx_mbps, 2)
                        
                        if d_out < 0:
                            result[f"{prefix}_tx_mbps"] = None
                        else:
                            tx_mbps = (d_out * 8.0) / (dt * 1_000_000)
                            result[f"{prefix}_tx_mbps"] = round(tx_mbps, 2)
                        
                        # Utilization if speed known and rates calculated
                        if result.get(f"{prefix}_rx_mbps") is not None and result.get(f"{prefix}_tx_mbps") is not None:
                            spd = result.get(f"{prefix}_speed_mbps") or result.get(f"{prefix}_speed")
                            if spd and spd > 0:
                                util = ((result[f"{prefix}_rx_mbps"] + result[f"{prefix}_tx_mbps"]) / (spd)) * 100.0
                                result[f"{prefix}_util_percent"] = round(util, 1)
                            else:
                                result[f"{prefix}_util_percent"] = None
                        else:
                            result[f"{prefix}_util_percent"] = None
                    else:
                        # No previous sample - can't calculate rates yet
                        result[f"{prefix}_rx_mbps"] = None
                        result[f"{prefix}_tx_mbps"] = None
                        result[f"{prefix}_util_percent"] = None
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
                if k in result and result[k] is not None:
                    prev_v = state._snmp_prev_sample.get(k)
                    if prev_v is not None:
                        d = result[k] - prev_v
                        if d < 0:
                            result[f"{k}_s"] = None
                        else:
                            result[f"{k}_s"] = round(d / dt, 2) if dt > 0 else None
                    else:
                        # No previous sample - can't calculate rate yet
                        result[f"{k}_s"] = None
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
        
        # Update previous sample - store current values (preserve None for missing counters)
        # Only store valid counter values, don't default to 0
        # Preserve existing previous sample values if current values are None
        with state._snmp_prev_sample_lock:
            new_prev_sample = {"ts": now}
            for key in ["wan_in", "wan_out", "lan_in", "lan_out"]:
                if result.get(key) is not None:
                    new_prev_sample[key] = result[key]
                elif key in state._snmp_prev_sample:
                    # Preserve previous value if current is None
                    new_prev_sample[key] = state._snmp_prev_sample[key]
            
            # Store other counters
            new_prev_sample.update({
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
                # Store error/discard counters for rate calculation (preserve None)
                "wan_in_err": result.get("wan_in_err") if result.get("wan_in_err") is not None else state._snmp_prev_sample.get("wan_in_err"),
                "wan_out_err": result.get("wan_out_err") if result.get("wan_out_err") is not None else state._snmp_prev_sample.get("wan_out_err"),
                "wan_in_disc": result.get("wan_in_disc") if result.get("wan_in_disc") is not None else state._snmp_prev_sample.get("wan_in_disc"),
                "wan_out_disc": result.get("wan_out_disc") if result.get("wan_out_disc") is not None else state._snmp_prev_sample.get("wan_out_disc"),
                "lan_in_err": result.get("lan_in_err") if result.get("lan_in_err") is not None else state._snmp_prev_sample.get("lan_in_err"),
                "lan_out_err": result.get("lan_out_err") if result.get("lan_out_err") is not None else state._snmp_prev_sample.get("lan_out_err"),
                "lan_in_disc": result.get("lan_in_disc") if result.get("lan_in_disc") is not None else state._snmp_prev_sample.get("lan_in_disc"),
                "lan_out_disc": result.get("lan_out_disc") if result.get("lan_out_disc") is not None else state._snmp_prev_sample.get("lan_out_disc"),
            })
            # Preserve VPN interface previous samples when updating state
            # (VPN samples are stored by API route, not by background SNMP thread)
            vpn_keys_to_preserve = [k for k in state._snmp_prev_sample.keys() 
                                    if ('tailscale' in k.lower() or 'wireguard' in k.lower())]
            for key in vpn_keys_to_preserve:
                new_prev_sample[key] = state._snmp_prev_sample.get(key)
            
            state._snmp_prev_sample = new_prev_sample

        # Format uptime for readability
        if "sys_uptime" in result:
            result["sys_uptime_formatted"] = format_uptime(result["sys_uptime"])
        
        # Reset backoff on success
        state._snmp_backoff["failures"] = 0
        
        with state._snmp_cache_lock:
            state._snmp_cache["data"] = result
            state._snmp_cache["ts"] = now
        
        # Update Health Baselines (CPU/Mem/Interface Util)
        # Use existing _baselines in state to track deviation over time
        with state._baselines_lock:
            # CPU Load
            if "cpu_percent" in result:
                state._baselines["cpu_load"].append(result["cpu_percent"])
            
            # Memory Usage
            if "mem_percent" in result:
                state._baselines["mem_usage"].append(result["mem_percent"])
                
            # Interface Utilization (WAN/LAN)
            if result.get("wan_util_percent") is not None:
                state._baselines["wan_utilization"].append(result["wan_util_percent"])
            if result.get("lan_util_percent") is not None:
                state._baselines["lan_utilization"].append(result["lan_util_percent"])
        
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


def discover_interfaces():
    """Discover SNMP interfaces and map them to logical names (WAN/LAN/VPN).
    
    Returns a dict mapping logical names to interface indexes:
    {'wan': 1, 'lan': 2, 'wireguard': 3, 'tailscale': 4} or None if discovery fails.
    """
    try:
        # Walk interface descriptions
        cmd = f"snmpwalk -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} .1.3.6.1.2.1.2.2.1.2"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5, text=True)
        if_descr = output.strip().split("\n")
        
        # Walk interface operational status to filter only UP interfaces
        cmd = f"snmpwalk -v2c -c {SNMP_COMMUNITY} -Oqv {SNMP_HOST} .1.3.6.1.2.1.2.2.1.8"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5, text=True)
        if_status = output.strip().split("\n")
        
        mapping = {}
        for idx, (descr, status) in enumerate(zip(if_descr, if_status), 1):
            descr_clean = descr.strip().strip('"').lower()
            # Only consider UP interfaces (status == 1)
            if status.strip() == "1":
                # Map common interface names
                if descr_clean in ["igc0", "em0", "eth0", "wan"]:
                    mapping["wan"] = idx
                elif descr_clean in ["igc1", "em1", "eth1", "lan"]:
                    mapping["lan"] = idx
                elif "wg" in descr_clean or "wireguard" in descr_clean:
                    # WireGuard interface (e.g., wg0, wg1, wireguard0)
                    if "wireguard" not in mapping:  # Use first WireGuard interface found
                        mapping["wireguard"] = idx
                elif "tailscale" in descr_clean or "ts" in descr_clean:
                    # TailScale interface (e.g., tailscale0, ts0)
                    if "tailscale" not in mapping:  # Use first TailScale interface found
                        mapping["tailscale"] = idx
        
        return mapping if mapping else None
    except Exception:
        return None


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
