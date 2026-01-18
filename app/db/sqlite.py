"""SQLite database operations for PROX_NFDUMP application."""
import sqlite3
import threading
import time
import os
from datetime import datetime, timedelta
from app.config import TRENDS_DB_PATH, FIREWALL_DB_PATH, FIREWALL_RETENTION_DAYS
from app.services.netflow.netflow import run_nfdump, parse_csv

# Database locks
_trends_db_lock = threading.Lock()
_firewall_db_lock = threading.Lock()

# Initialization flags
_trends_db_initialized = False
_firewall_db_initialized = False


def _trends_db_connect():
    conn = sqlite3.connect(TRENDS_DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _trends_db_init():
    global _trends_db_initialized
    if _trends_db_initialized:
        return

    with _trends_db_lock:
        if _trends_db_initialized:
            return

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
            
            # Host memory table: persistent first-ever-seen timestamps
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS host_memory (
                    ip TEXT PRIMARY KEY,
                    first_seen_ts REAL NOT NULL,
                    first_seen_iso TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_host_memory_first_seen ON host_memory(first_seen_ts);")
            
            # Database file size history: bounded historical samples for growth trend
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS db_size_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    db_name TEXT NOT NULL,
                    db_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_db_size_history_db_path ON db_size_history(db_path, timestamp);")
            
            # Top sources table for traffic trends
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS top_sources (
                    bucket_end INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    flows INTEGER NOT NULL,
                    PRIMARY KEY (bucket_end, ip)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_top_sources_bucket_end ON top_sources(bucket_end);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_top_sources_ip ON top_sources(ip);")
            
            # Top destinations table for traffic trends
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS top_dests (
                    bucket_end INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    flows INTEGER NOT NULL,
                    PRIMARY KEY (bucket_end, ip)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_top_dests_bucket_end ON top_dests(bucket_end);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_top_dests_ip ON top_dests(ip);")
            
            conn.commit()
            _trends_db_initialized = True
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
    global _firewall_db_initialized
    if _firewall_db_initialized:
        return

    with _firewall_db_lock:
        if _firewall_db_initialized:
            return

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
            _firewall_db_initialized = True
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


def get_top_blocked_sources(hours=24, limit=50):
    """Get top blocked source IPs by count."""
    try:
        cutoff = time.time() - (hours * 3600)
        with _firewall_db_lock:
            conn = _firewall_db_connect()
            try:
                cur = conn.execute("""
                    SELECT src_ip, COUNT(*) as count
                    FROM fw_logs
                    WHERE timestamp > ? AND action IN ('block', 'reject')
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT ?
                """, (cutoff, limit))
                return [{'src_ip': row[0], 'count': row[1]} for row in cur.fetchall()]
            finally:
                conn.close()
    except Exception:
        return []


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
    """Get the end datetime for the current 5-minute bucket.
    
    Note: Uses naive datetime (local time) for consistency with nfdump output.
    Bucket alignment is stable as long as system timezone doesn't change.
    """
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
    
    # Remove -n limit to get true total traffic stats
    output = run_nfdump(["-s", "proto/bytes/flows"], tf_key)
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


def update_host_memory(hosts_dict):
    """Update host memory with first-ever-seen timestamps.
    
    Args:
        hosts_dict: Dict mapping IP -> {first_seen: ISO timestamp string, ...}
    """
    if not hosts_dict:
        return
    
    _trends_db_init()  # Ensure table exists
    
    now = time.time()
    all_ips = list(hosts_dict.keys())

    # Pre-process hosts_dict to extract parsed timestamps
    parsed_hosts = {}
    for ip, host_data in hosts_dict.items():
        first_seen_iso = host_data.get('first_seen')
        if not first_seen_iso:
            continue
        try:
            # Parse nfdump format: "2023-01-01 12:00:00.123" or "2023-01-01 12:00:00"
            timestamp_str = first_seen_iso.split('.')[0] if '.' in first_seen_iso else first_seen_iso
            dt = datetime.strptime(timestamp_str.strip(), '%Y-%m-%d %H:%M:%S')
            first_seen_ts = dt.timestamp()
            parsed_hosts[ip] = (first_seen_ts, first_seen_iso)
        except (ValueError, AttributeError):
            continue

    if not parsed_hosts:
        return

    to_insert = []
    to_update = []

    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            # Batch fetch existing IPs to minimize SELECTs
            existing_data = {}
            batch_size = 500
            for i in range(0, len(all_ips), batch_size):
                batch = all_ips[i:i+batch_size]
                if not batch:
                    continue
                placeholders = ','.join('?' * len(batch))
                cur = conn.execute(
                    f"SELECT ip, first_seen_ts FROM host_memory WHERE ip IN ({placeholders})",
                    batch
                )
                for row in cur.fetchall():
                    existing_data[row[0]] = row[1]

            # Determine inserts and updates
            for ip, (first_seen_ts, first_seen_iso) in parsed_hosts.items():
                if ip not in existing_data:
                    to_insert.append((ip, first_seen_ts, first_seen_iso, now))
                else:
                    existing_ts = existing_data[ip]
                    if first_seen_ts < existing_ts:
                        to_update.append((first_seen_ts, first_seen_iso, now, ip))

            # Execute batch writes
            if to_insert:
                conn.executemany(
                    "INSERT INTO host_memory (ip, first_seen_ts, first_seen_iso, updated_at) VALUES (?, ?, ?, ?)",
                    to_insert
                )

            if to_update:
                conn.executemany(
                    "UPDATE host_memory SET first_seen_ts = ?, first_seen_iso = ?, updated_at = ? WHERE ip = ?",
                    to_update
                )
            
            conn.commit()
        finally:
            conn.close()


def get_host_memory(ip):
    """Get persisted first-ever-seen timestamp for a host.
    
    Args:
        ip: IP address string
        
    Returns:
        Dict with 'first_seen_ts' (Unix timestamp) and 'first_seen_iso' (ISO string), or None
    """
    _trends_db_init()  # Ensure table exists
    
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT first_seen_ts, first_seen_iso FROM host_memory WHERE ip = ?",
                (ip,)
            )
            row = cur.fetchone()
            if row:
                return {
                    'first_seen_ts': row[0],
                    'first_seen_iso': row[1]
                }
            return None
        finally:
            conn.close()


def get_hosts_memory(ip_list):
    """Get persisted first-ever-seen timestamps for multiple hosts.
    
    Args:
        ip_list: List of IP address strings
        
    Returns:
        Dict mapping IP -> {first_seen_ts, first_seen_iso}
    """
    if not ip_list:
        return {}
    
    _trends_db_init()  # Ensure table exists
    
    result = {}
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            batch_size = 500
            for i in range(0, len(ip_list), batch_size):
                batch = ip_list[i:i+batch_size]
                if not batch:
                    continue
                placeholders = ','.join('?' * len(batch))
                cur = conn.execute(
                    f"SELECT ip, first_seen_ts, first_seen_iso FROM host_memory WHERE ip IN ({placeholders})",
                    batch
                )
                for row in cur.fetchall():
                    result[row[0]] = {
                        'first_seen_ts': row[1],
                        'first_seen_iso': row[2]
                    }
        finally:
            conn.close()
    
    return result


def update_db_size_history(db_name, db_path, file_size):
    """Update database file size history with a new sample.
    
    Args:
        db_name: Database name (e.g., 'Trends', 'Firewall')
        db_path: Database file path
        file_size: Current file size in bytes
    """
    if not db_path:
        return
    
    _trends_db_init()  # Ensure table exists
    
    now = time.time()
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            # Insert new sample
            conn.execute(
                "INSERT INTO db_size_history (db_name, db_path, file_size, timestamp) VALUES (?, ?, ?, ?)",
                (db_name, db_path, file_size, now)
            )
            
            # Keep only last 100 samples per database (bounded storage)
            conn.execute("""
                DELETE FROM db_size_history
                WHERE db_path = ? AND id NOT IN (
                    SELECT id FROM db_size_history
                    WHERE db_path = ?
                    ORDER BY timestamp DESC
                    LIMIT 100
                )
            """, (db_path, db_path))
            
            conn.commit()
        finally:
            conn.close()


def get_db_size_history(db_path, limit=100):
    """Get historical file size samples for a database.
    
    Args:
        db_path: Database file path
        limit: Maximum number of samples to return (default 100)
        
    Returns:
        List of dicts with 'file_size' and 'timestamp' keys, sorted by timestamp ascending
    """
    if not db_path:
        return []
    
    _trends_db_init()  # Ensure table exists
    
    with _trends_db_lock:
        conn = _trends_db_connect()
        try:
            cur = conn.execute(
                "SELECT file_size, timestamp FROM db_size_history WHERE db_path = ? ORDER BY timestamp ASC LIMIT ?",
                (db_path, limit)
            )
            return [{'file_size': row[0], 'timestamp': row[1]} for row in cur.fetchall()]
        finally:
            conn.close()