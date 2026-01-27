from datetime import datetime

from flask import jsonify, request

from . import bp
from app.services.change_timeline import list_changes


@bp.route("/api/change-timeline")
def api_change_timeline():
    try:
        limit = int(request.args.get("limit", 8))
    except (TypeError, ValueError):
        limit = 8

    items = list_changes(limit=limit)
    return jsonify({"items": items, "limit": min(max(limit, 0), 8)})
