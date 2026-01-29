"""Deterministic network summary generator.

Pure function: takes aggregated stats and returns a single sentence.
No I/O, no side effects.
"""

def _traffic_classification(traffic_ratio, traffic_bytes_per_hour):
    """Classify traffic into Low/Normal/Elevated/High with conservative thresholds."""
    if traffic_ratio is not None:
        if traffic_ratio < 0.7:
            return "low", "Traffic levels are low."
        if traffic_ratio < 1.2:
            return "normal", "Traffic levels are normal."
        if traffic_ratio < 1.8:
            return "elevated", "Traffic is elevated compared to typical patterns."
        return "high", "Traffic is high compared to typical patterns."

    if traffic_bytes_per_hour is None:
        return None, None

    # Conservative absolute thresholds (bytes/hour)
    if traffic_bytes_per_hour < 100 * 1024 * 1024:
        return "low", "Traffic levels are low."
    if traffic_bytes_per_hour < 1 * 1024 * 1024 * 1024:
        return "normal", "Traffic levels are normal."
    if traffic_bytes_per_hour < 5 * 1024 * 1024 * 1024:
        return "elevated", "Traffic is elevated."
    return "high", "Traffic is high."


def _unusual_activity_sentence(unusual_count, unusual_spike=False):
    if unusual_count is None and not unusual_spike:
        return None
    if unusual_spike:
        return "Unusual traffic patterns detected."
    if unusual_count <= 0:
        return "No unusual activity detected."
    if unusual_count <= 2:
        return "Minor traffic spikes observed."
    return "Unusual traffic patterns detected."


def _firewall_sentence(blocked_events):
    if blocked_events is None:
        return None
    if blocked_events >= 10:
        return "Firewall is actively blocking background internet noise."
    if blocked_events > 0:
        return "Firewall is quietly filtering background noise."
    return "Firewall activity is quiet."


def generate_network_summary(stats):
    """Generate a concise, human-readable network summary sentence.

    Args:
        stats (dict): Aggregated stats and flags, e.g.:
            alerts_active, alerts_critical, health_degraded,
            traffic_ratio, traffic_bytes_per_hour,
            unusual_count, unusual_spike, firewall_blocks
    """
    if not isinstance(stats, dict):
        return "Network status is currently being assessed."
    if stats.get("data_ready") is False:
        return "Network status is currently being assessed."

    alerts_active = stats.get("alerts_active")
    alerts_critical = stats.get("alerts_critical")
    health_degraded = bool(stats.get("health_degraded"))
    traffic_ratio = stats.get("traffic_ratio")
    traffic_bytes_per_hour = stats.get("traffic_bytes_per_hour")
    unusual_count = stats.get("unusual_count")
    unusual_spike = bool(stats.get("unusual_spike"))
    firewall_blocks = stats.get("firewall_blocks")

    attention_threshold = stats.get("alert_attention_threshold", 5)

    sentences = []

    # State (highest priority)
    if alerts_critical and alerts_critical > 0:
        sentences.append("Attention required.")
        sentences.append("Critical alerts detected.")
    else:
        if alerts_active is not None and alerts_active >= attention_threshold:
            sentences.append("Your network requires attention.")
        elif unusual_spike:
            sentences.append("Your network is showing unusual patterns.")
        elif health_degraded:
            sentences.append("Your network is operating in a degraded state.")
        else:
            sentences.append("Your network is stable.")

    # Traffic interpretation
    _, traffic_sentence = _traffic_classification(traffic_ratio, traffic_bytes_per_hour)
    if traffic_sentence:
        sentences.append(traffic_sentence)

    # Unusual activity interpretation
    unusual_sentence = _unusual_activity_sentence(unusual_count, unusual_spike)
    if unusual_sentence:
        sentences.append(unusual_sentence)

    # Firewall interpretation (lower priority than unusual activity)
    firewall_sentence = _firewall_sentence(firewall_blocks)
    if firewall_sentence:
        sentences.append(firewall_sentence)

    # Fail-safe
    if not sentences:
        return "Network status is currently being assessed."

    # Keep to 3–4 short statements
    return " ".join(sentences[:4])
