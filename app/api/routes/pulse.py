from flask import jsonify, request

from . import bp
from app.services.pulse.feed import get_pulse_store


@bp.route("/api/pulse/feed")
def api_pulse_feed():
    try:
        limit = min(int(request.args.get("limit", 200)), 400)
    except (TypeError, ValueError):
        limit = 200
    source = request.args.get("source")
    kind = request.args.get("kind")
    query = request.args.get("q")
    try:
        range_s = int(request.args.get("range_s", 3600))
    except (TypeError, ValueError):
        range_s = 3600

    store = get_pulse_store()
    events = store.list_events(
        limit=limit, source=source, kind=kind, query=query, range_s=range_s
    )
    return jsonify(
        {
            "events": events,
            "limit": limit,
            "source": source or "all",
            "kind": kind or "all",
            "range_s": range_s,
        }
    )


@bp.route("/api/pulse/stats")
def api_pulse_stats():
    store = get_pulse_store()
    events = store.list_events(limit=800, range_s=3600)
    counts = {"source": {}, "severity": {}}
    for ev in events:
        counts["source"][ev["source"]] = counts["source"].get(ev["source"], 0) + 1
        counts["severity"][ev["severity"]] = (
            counts["severity"].get(ev["severity"], 0) + 1
        )
    return jsonify({"counts": counts})
