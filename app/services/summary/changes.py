"""Deterministic change detection for last-hour summary."""

def _pct_change(now_val, prev_val):
    if prev_val is None or prev_val == 0:
        return None
    return ((now_val - prev_val) / prev_val) * 100.0


def compute_last_hour_changes(now_stats, prev_stats):
    """Compute deltas between current and previous-hour snapshots."""
    if not isinstance(now_stats, dict) or not isinstance(prev_stats, dict):
        return {"data_ready": False}

    changes = {"data_ready": True}

    # Traffic / activity
    if now_stats.get("traffic_bytes_per_hour") is not None and prev_stats.get("traffic_bytes_per_hour") is not None:
        now_t = now_stats["traffic_bytes_per_hour"]
        prev_t = prev_stats["traffic_bytes_per_hour"]
        changes["traffic_mode"] = "traffic"
        changes["traffic_delta"] = now_t - prev_t
        changes["traffic_pct"] = _pct_change(now_t, prev_t)
    elif now_stats.get("active_flows") is not None and prev_stats.get("active_flows") is not None:
        now_a = now_stats["active_flows"]
        prev_a = prev_stats["active_flows"]
        changes["traffic_mode"] = "activity"
        changes["traffic_delta"] = now_a - prev_a
        changes["traffic_pct"] = _pct_change(now_a, prev_a)

    # External connections
    if now_stats.get("external_connections") is not None and prev_stats.get("external_connections") is not None:
        changes["external_delta"] = now_stats["external_connections"] - prev_stats["external_connections"]

    # Firewall blocks
    if now_stats.get("firewall_blocks") is not None and prev_stats.get("firewall_blocks") is not None:
        changes["firewall_block_delta"] = now_stats["firewall_blocks"] - prev_stats["firewall_blocks"]
        changes["firewall_block_pct"] = _pct_change(now_stats["firewall_blocks"], prev_stats["firewall_blocks"])

    # Unusual activity (anomalies)
    if now_stats.get("unusual_count") is not None and prev_stats.get("unusual_count") is not None:
        changes["unusual_delta"] = now_stats["unusual_count"] - prev_stats["unusual_count"]
    changes["unusual_now"] = now_stats.get("unusual_count")

    # Alerts
    if now_stats.get("alerts_active") is not None and prev_stats.get("alerts_active") is not None:
        changes["alerts_delta"] = now_stats["alerts_active"] - prev_stats["alerts_active"]
    if now_stats.get("alerts_critical") is not None and prev_stats.get("alerts_critical") is not None:
        changes["critical_alerts_delta"] = now_stats["alerts_critical"] - prev_stats["alerts_critical"]

    return changes


def format_change_sentence(changes):
    """Build a calm, concise sentence describing last-hour changes."""
    if not isinstance(changes, dict) or not changes.get("data_ready"):
        return "Learning changes… check back in a few minutes."

    critical_delta = changes.get("critical_alerts_delta", 0) or 0
    if critical_delta > 0:
        clauses = ["Attention required.", "Critical alerts increased."]
        # Add up to one more clause if useful
        traffic_clause = _traffic_clause(changes)
        unusual_clause = _unusual_clause(changes)
        if traffic_clause:
            clauses.append(traffic_clause)
        elif unusual_clause:
            clauses.append(unusual_clause)
        return " ".join(clauses[:3])

    clauses = []

    traffic_clause = _traffic_clause(changes)
    if traffic_clause and not traffic_clause.endswith("steady."):
        clauses.append(traffic_clause)

    external_clause = _external_clause(changes)
    if external_clause:
        clauses.append(external_clause)

    unusual_clause = _unusual_clause(changes)
    if unusual_clause:
        clauses.append(unusual_clause)

    firewall_clause = _firewall_clause(changes)
    if firewall_clause:
        clauses.append(firewall_clause)

    # If nothing significant, return a calm default
    if not clauses:
        return "Mostly stable. No meaningful changes detected in the last hour."

    # Keep concise: max 3 short clauses
    return " ".join(clauses[:3])


def _traffic_clause(changes):
    mode = changes.get("traffic_mode")
    pct = changes.get("traffic_pct")
    if mode is None or pct is None:
        return None
    noun = "Traffic" if mode == "traffic" else "Activity"
    if -10 <= pct <= 10:
        return f"{noun} is steady."
    if pct > 35:
        return f"{noun} increased notably."
    if pct > 10:
        return f"{noun} increased."
    if pct < -35:
        return f"{noun} decreased notably."
    if pct < -10:
        return f"{noun} decreased."
    return None


def _external_clause(changes):
    delta = changes.get("external_delta")
    if delta is None:
        return None
    if delta <= 2:
        return None
    if 3 <= delta <= 5:
        return f"{delta} new external destinations appeared."
    if 6 <= delta <= 10:
        return "More external destinations than usual."
    if delta > 10:
        return "External destination spread increased."
    if delta < -5:
        return "External destination spread decreased."
    return None


def _firewall_clause(changes):
    delta = changes.get("firewall_block_delta")
    pct = changes.get("firewall_block_pct")
    if delta is None:
        return None
    if delta <= 0:
        return "Firewall blocks are normal."
    if pct is not None and pct > 30 and delta > 10:
        return "Firewall blocks increased; likely background scanning noise."
    if delta > 20:
        return "Firewall blocks increased; likely background scanning noise."
    return "Firewall blocks are normal."


def _unusual_clause(changes):
    now_count = changes.get("unusual_now")
    delta = changes.get("unusual_delta")
    if now_count is None:
        return None
    if now_count <= 0:
        return "No unusual patterns detected."
    if delta is not None and delta <= 1:
        return "Minor unusual patterns observed."
    if delta is not None and delta > 1:
        return "Unusual patterns increased."
    return "Minor unusual patterns observed."
