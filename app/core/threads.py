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
)

# Import config
from app.config import CACHE_TTL_THREAT, CACHE_TTL_SHORT

# Import service functions
from app.services.threats import fetch_threat_feed
from app.services.netflow import parse_csv, run_nfdump
from app.utils.helpers import get_time_range
from app.db.sqlite import _trends_db_init, _get_bucket_end, _ensure_rollup_for_bucket


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
            except Exception:
                pass
            time.sleep(60)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
