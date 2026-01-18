from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from app.services.firewall.store import firewall_store

# Import firewall syslog stats (isolated listener metrics)
try:
    from app.services.syslog.firewall_listener import get_firewall_syslog_stats
except ImportError:
    get_firewall_syslog_stats = None

bp = Blueprint('firewall_decisions', __name__)

@bp.route('/api/firewall/decisions', methods=['GET'])
def get_decisions():
    """
    Retrieve raw firewall decision events.
    SCOPE: Read-only, time-windowed retrieval.
    NO correlation or alerting.
    
    Params:
        since_seconds (int): Optional lookback window in seconds (default: 300)
    """
    try:
        # Input validation for simple time window
        seconds = request.args.get('since_seconds', default=300, type=int)
        if seconds <= 0:
            seconds = 300 # Fail safe default
            
        since_dt = datetime.now() - timedelta(seconds=seconds)
        
        events = firewall_store.get_events(limit=500, since=since_dt)
        
        return jsonify({
            "window_seconds": seconds,
            "count": len(events),
            "events": events
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/api/firewall/summary', methods=['GET'])
def get_summary():
    """
    Retrieve descriptive statistics of firewall decisions.
    SCOPE: Basic counting (total, action, interface, direction).
    NO interpretation of risk or severity.
    
    Params:
        since_seconds (int): Optional lookback window in seconds (default: 300)
    """
    try:
        seconds = request.args.get('since_seconds', default=300, type=int)
        if seconds <= 0:
            seconds = 300
            
        since_dt = datetime.now() - timedelta(seconds=seconds)
        
        stats = firewall_store.get_counts(since=since_dt)
        
        # Include firewall syslog listener stats (isolated ingestion counter)
        syslog_ingestion = None
        if get_firewall_syslog_stats:
            syslog_ingestion = get_firewall_syslog_stats()
        
        return jsonify({
            "window_seconds": seconds,
            "timestamp": datetime.now().isoformat(),
            "stats": stats,
            "syslog_ingestion": syslog_ingestion
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
