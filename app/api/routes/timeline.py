from datetime import datetime

from flask import jsonify, request

from . import bp
from app.services.timeline.emitters import check_stale_transitions
from app.services.timeline.store import get_timeline_store


@bp.route("/api/timeline/events")
def api_timeline_events():
    try:
        range_s = int(request.args.get("range", 3600))
    except (TypeError, ValueError):
        range_s = 3600
    try:
        limit = min(int(request.args.get("limit", 200)), 200)
    except (TypeError, ValueError):
        limit = 200
    types_param = request.args.get("types")
    types = (
        [t.strip() for t in types_param.split(",") if t.strip()]
        if types_param
        else None
    )

    range_s = max(0, range_s)
    limit = max(0, limit)

    check_stale_transitions()

    store = get_timeline_store()
    events = store.list_events(range_s=range_s, limit=limit, types=types)
    summary = store.summary(range_s=range_s)
    now_ts = int(datetime.utcnow().timestamp())

    return jsonify(
        {
            "events": events,
            "summary": summary,
            "now_ts": now_ts,
            "range_s": range_s,
            "limit": limit,
        }
    )


@bp.route("/api/timeline/summary")
def api_timeline_summary():
    try:
        range_s = int(request.args.get("range", 3600))
    except (TypeError, ValueError):
        range_s = 3600
    range_s = max(0, range_s)

    check_stale_transitions()
    store = get_timeline_store()
    summary = store.summary(range_s=range_s)
    now_ts = int(datetime.utcnow().timestamp())

    return jsonify({"summary": summary, "now_ts": now_ts, "range_s": range_s})
