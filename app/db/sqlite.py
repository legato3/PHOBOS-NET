"""SQLite database operations for PROX_NFDUMP application."""
import sqlite3
import threading
import time
import os
from datetime import datetime, timedelta
from app.config import TRENDS_DB_PATH, FIREWALL_DB_PATH, FIREWALL_RETENTION_DAYS
from app.services.netflow import run_nfdump, parse_csv

# Database locks
_trends_db_lock = threading.Lock()
_firewall_db_lock = threading.Lock()


def _trends_db_connect():
    conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _trends_db_init():
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traffic_rollups (
                    bucket_end INTEGER PRIMARY KEY,
                    bytes INTEGER NOT NULL,
                    flows INTEGER NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_rollups_bucket ON traffic_rollups(bucket_end);")
            conn.commit()
        finally:
            conn.close()


def _firewall_db_connect():
    """Connect to firewall SQLite database."""
    conn = sqlite3.connect(FIREWALL_DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _firewall_db_init():
    """Initialize firewall log database schema."""
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fw_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    timestamp_iso TEXT,
                    action TEXT NOT NULL,
                    direction TEXT,
                    interface TEXT,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    proto TEXT,
                    rule_id TEXT,
                    length INTEGER,
                    country_iso TEXT,
                    is_threat INTEGER DEFAULT 0,
                    raw_log TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_timestamp ON fw_logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_action ON fw_logs(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_src_ip ON fw_logs(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_dst_port ON fw_logs(dst_port)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fw_action_ts ON fw_logs(action, timestamp)")
            
            # Hourly aggregates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fw_stats_hourly (
                    hour_ts INTEGER PRIMARY KEY,
                    blocks INTEGER DEFAULT 0,
                    passes INTEGER DEFAULT 0,
                    unique_blocked_ips INTEGER DEFAULT 0,
                    top_blocked_port INTEGER,
                    top_blocked_country TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()


def _get_firewall_block_stats(hours=1):
    """Get firewall block statistics for the last N hours."""
    try:
        cutoff = time.time() - (hours * 3600)
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                # Combined query for total blocks, unique IPs, and threat blocks
                # Optimized to reduce DB round-trips from 3 to 1
                cur = conn.execute("""
                    SELECT
                        COUNT(*),
                        COUNT(DISTINCT src_ip),
                        SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END)
                    FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                """, (cutoff,))
                
                row = cur.fetchone()
                blocks = row[0] or 0
                unique_ips = row[1] or 0
                threats_blocked = row[2] or 0
                
                return {
                    'blocks': blocks,
                    'unique_ips': unique_ips,
                    'threats_blocked': threats_blocked,
                    'blocks_per_hour': round(blocks / hours, 1)
                }
            finally:
                conn.close()
    except Exception:
        return {'blocks': 0, 'unique_ips': 0, 'threats_blocked': 0, 'blocks_per_hour': 0}


def _cleanup_old_fw_logs():
    """Remove firewall logs older than retention period."""
    cutoff = time.time() - (FIREWALL_RETENTION_DAYS * 86400)
    with _firewall_db_lock:
        conn = _firewall_db_connect()
        try:
            conn.execute("DELETE FROM fw_logs WHERE timestamp < ?", (cutoff,))
            conn.execute("VACUUM")
            conn.commit()
        finally:
            conn.close()


def _get_bucket_end(dt=None):
    """Get the end datetime for the current 5-minute bucket."""
    dt = dt or datetime.now()
    # Align to nearest 5 minutes upper boundary
    remainder = dt.minute % 5
    current_bucket_end = dt.replace(minute=dt.minute - remainder, second=0, microsecond=0) + timedelta(minutes=5)
    return current_bucket_end


def _ensure_rollup_for_bucket(bucket_end_dt):
    """Ensure we have a rollup for the given completed bucket end (datetime)."""
    bucket_end_ts = int(bucket_end_dt.timestamp())
    # Check if exists
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute("SELECT 1 FROM traffic_rollups WHERE bucket_end=?", (bucket_end_ts,))
            row = cur.fetchone()
            if row:
                return
        finally:
            conn.close()
    
    # Compute using nfdump over the 5-min interval ending at bucket_end_dt
    st = bucket_end_dt - timedelta(minutes=5)
    tf_key = f"{st.strftime('%Y/%m/%d.%H:%M:%S')}-{bucket_end_dt.strftime('%Y/%m/%d.%H:%M:%S')}"
    
    output = run_nfdump(["-s", "proto/bytes/flows", "-n", "100"], tf_key)
    stats = parse_csv(output, expected_key='proto')
    total_b = sum(s.get("bytes", 0) for s in stats)
    total_f = sum(s.get("flows", 0) for s in stats)
    
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            conn.execute("INSERT OR REPLACE INTO traffic_rollups(bucket_end, bytes, flows) VALUES (?,?,?)",
                        (bucket_end_ts, int(total_b), int(total_f)))
            conn.commit()
        finally:
            conn.close()