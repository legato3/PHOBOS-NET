"""Thread management functions for PROX_NFDUMP application.

This module contains functions to start background threads that perform
periodic tasks like fetching threat feeds, aggregating data, and managing trends.
"""
import threading
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Import state module to modify thread flags
import app.core.state as state
from app.core.state import (
    _shutdown_event,
    _common_data_lock,
    _common_data_cache,
    add_app_log,
)

# Import config
from app.config import CACHE_TTL_THREAT, CACHE_TTL_SHORT

# Import service functions
from app.services.threats import fetch_threat_feed
from app.services.netflow import parse_csv, run_nfdump
from app.utils.helpers import get_time_range
from app.db.sqlite import _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket, update_db_size_history
from app.config import TRENDS_DB_PATH, FIREWALL_DB_PATH


def start_threat_thread():
    """Start the threat feed update thread."""
    if state._threat_thread_started:
        return
    state._threat_thread_started = True
    def loop():
        while not _shutdown_event.is_set():
            fetch_threat_feed()
            # Use wait instead of sleep for faster shutdown
            _shutdown_event.wait(timeout=CACHE_TTL_THREAT)
    t = threading.Thread(target=loop, daemon=True, name='ThreatFeedThread')
    t.start()


def start_trends_thread():
    """Start the trends aggregation thread."""
    if state._trends_thread_started:
        return
    state._trends_thread_started = True
    _trends_db_init()

    def loop():
        while not _shutdown_event.is_set():
            try:
                # Work on the last completed bucket (avoid partial current)
                now_dt = datetime.now()
                current_end = _get_bucket_end(now_dt)
                last_completed_end = current_end - timedelta(minutes=5)
                _ensure_rollup_for_bucket(last_completed_end)
            except Exception:
                pass
            _shutdown_event.wait(timeout=CACHE_TTL_SHORT)

    t = threading.Thread(target=loop, daemon=True, name='TrendsThread')
    t.start()


def start_agg_thread():
    """Background aggregator to precompute common nfdump data for 1h range every 60s."""
    if state._agg_thread_started:
        return
    state._agg_thread_started = True

    def loop():
        while not _shutdown_event.is_set():
            try:
                range_key = '1h'
                tf = get_time_range(range_key)
                now_ts = time.time()
                win = int(now_ts // 60)

                # Parallelize nfdump calls to speed up aggregation
                def fetch_sources():
                    data = parse_csv(run_nfdump(["-s","srcip/bytes/flows/packets","-n","100"], tf), expected_key='sa')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_ports():
                    data = parse_csv(run_nfdump(["-s","dstport/bytes/flows","-n","100"], tf), expected_key='dp')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_dests():
                    data = parse_csv(run_nfdump(["-s","dstip/bytes/flows/packets","-n","100"], tf), expected_key='da')
                    data.sort(key=lambda x: x.get("bytes", 0), reverse=True)
                    return data

                def fetch_protos():
                    return parse_csv(run_nfdump(["-s","proto/bytes/flows/packets","-n","20"], tf), expected_key='proto')

                with ThreadPoolExecutor(max_workers=4) as executor:
                    f_sources = executor.submit(fetch_sources)
                    f_ports = executor.submit(fetch_ports)
                    f_dests = executor.submit(fetch_dests)
                    f_protos = executor.submit(fetch_protos)

                    sources = f_sources.result()
                    ports = f_ports.result()
                    dests = f_dests.result()
                    protos = f_protos.result()

                with _common_data_lock:
                    _common_data_cache[f"sources:{range_key}:{win}"] = {"data": sources, "ts": now_ts, "win": win}
                    _common_data_cache[f"ports:{range_key}:{win}"] = {"data": ports, "ts": now_ts, "win": win}
                    _common_data_cache[f"dests:{range_key}:{win}"] = {"data": dests, "ts": now_ts, "win": win}
                    _common_data_cache[f"protos:{range_key}:{win}"] = {"data": protos, "ts": now_ts, "win": win}
            except Exception as e:
                add_app_log(f"Agg thread error: {e}", 'ERROR')

            # Align next run to the minute boundary to prevent drift
            now = time.time()
            next_minute = (int(now) // 60 + 1) * 60
            sleep_time = max(1, next_minute - now)
            _shutdown_event.wait(timeout=sleep_time)

    t = threading.Thread(target=loop, daemon=True)
    t.start()


def start_db_size_sampler_thread():
    """Start the database file size sampling thread.
    
    Samples database file sizes at fixed intervals (60s) and stores them
    in a bounded buffer. This runs independently of API requests to avoid
    write operations during GET handlers.
    """
    if state._db_size_sampler_thread_started:
        return
    state._db_size_sampler_thread_started = True
    
    def loop():
        while not _shutdown_event.is_set():
            try:
                import os
                
                # Sample Trends database
                if TRENDS_DB_PATH and os.path.exists(TRENDS_DB_PATH):
                    try:
                        file_size = os.stat(TRENDS_DB_PATH).st_size
                        update_db_size_history('Trends', TRENDS_DB_PATH, file_size)
                    except Exception:
                        pass  # Silently skip if sampling fails
                
                # Sample Firewall database
                if FIREWALL_DB_PATH and os.path.exists(FIREWALL_DB_PATH):
                    try:
                        file_size = os.stat(FIREWALL_DB_PATH).st_size
                        update_db_size_history('Firewall', FIREWALL_DB_PATH, file_size)
                    except Exception:
                        pass  # Silently skip if sampling fails
                        
            except Exception:
                pass  # Silently skip on any error
            
            # Fixed 60-second interval
            _shutdown_event.wait(timeout=60)
    
    t = threading.Thread(target=loop, daemon=True, name='DbSizeSamplerThread')
    t.start()
