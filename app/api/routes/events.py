from flask import jsonify, request

from . import bp
from app.services.events.context import build_event_context
from app.services.events.store import fetch_event_detail, fetch_events
from app.services.timeline.store import get_timeline_store


_RANGE_MAP = {
    "1h": 3600,
    "24h": 86400,
}


def _parse_range(range_key: str) -> int:
    return _RANGE_MAP.get(range_key, 3600)


@bp.route("/api/events/notable")
def api_events_notable():
    range_key = request.args.get("range", "1h")
    try:
        limit = min(int(request.args.get("limit", 200)), 500)
    except (TypeError, ValueError):
        limit = 200
    source = request.args.get("source")
    range_sec = _parse_range(range_key)
    events = fetch_events("notable", range_sec=range_sec, limit=limit, source=source)
    return jsonify(
        {
            "events": events,
            "range": range_key,
            "limit": limit,
        }
    )


@bp.route("/api/events/activity")
def api_events_activity():
    range_key = request.args.get("range", "1h")
    try:
        limit = min(int(request.args.get("limit", 200)), 500)
    except (TypeError, ValueError):
        limit = 200
    source = request.args.get("source")
    range_sec = _parse_range(range_key)
    events = fetch_events("activity", range_sec=range_sec, limit=limit, source=source)
    suppression = get_timeline_store().suppression_stats(range_sec)
    return jsonify(
        {
            "events": events,
            "suppressed": suppression,
            "range": range_key,
            "limit": limit,
        }
    )


@bp.route("/api/events/detail")
def api_events_detail():
    event_id = request.args.get("id")
    if not event_id:
        return jsonify({"error": "Missing id"}), 400
    event = fetch_event_detail(event_id)
    if not event:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"event": event})


@bp.route("/api/events/context")
def api_events_context():
    event_id = request.args.get("id")
    if not event_id:
        return jsonify({"error": "Missing id"}), 400
    context = build_event_context(event_id)
    if not context:
        return jsonify({"error": "Not found"}), 404
    return jsonify(context)
