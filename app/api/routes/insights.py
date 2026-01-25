
from flask import Blueprint, jsonify, request
from app.services.insights.personality import generate_personality_profile
from app.services.insights.overlays import generate_overlays
from app.services.insights.radar import get_radar_snapshot

bp = Blueprint('insights', __name__, url_prefix='/api/insights')

@bp.route('/personality', methods=['GET'])
def get_personality():
    window = request.args.get('window', '24h')
    if window not in ['24h', '7d']:
        window = '24h'
    profile = generate_personality_profile(window)
    return jsonify(profile)

@bp.route('/overlays', methods=['GET'])
def get_overlays():
    window = request.args.get('window', '1h')
    # Sanitize window input to be safe
    if window not in ['1h', '6h', '24h']:
        window = '1h'
    overlays = generate_overlays(window)
    overlays = generate_overlays(window)
    return jsonify(overlays)

@bp.route('/radar', methods=['GET'])
def get_radar():
    debug = request.args.get('debug', '0') == '1'
    snapshot = get_radar_snapshot(window_minutes=15, debug_mode=debug)
    return jsonify(snapshot)
