import time
from app.services.events.store import fetch_events
from app.services.netflow.netflow import get_common_nfdump_data

# Simple robust cache
_overlay_cache = {}  # Keyed by window
_LAST_CACHE_TS = 0
_CACHE_TTL = 15


def generate_overlays(window="1h"):
    global _overlay_cache, _LAST_CACHE_TS

    now = time.time()
    if now - _LAST_CACHE_TS < _CACHE_TTL and window in _overlay_cache:
        return _overlay_cache[window]

    range_sec = 3600
    if window == "24h":
        range_sec = 86400

    # 1. Fetch Recent "Notable" Events acting as triggers
    # We look for "notable" events to attach hints to.
    events = fetch_events(kind="notable", range_sec=range_sec, limit=20)

    overlays = []

    for evt in events:
        # Rule 1: FIREWALL BLOCK SPIKE or High Volume Block
        # We look for title/tags indicating block spike
        if "Firewall" in evt["source"] and (
            "Spike" in evt["title"] or "High" in evt["title"]
        ):
            # Correlation: Get top NetFlow destinations in same window?
            # Ideally we want "now", but we'll use '1h' aggregate as a "Related" hint
            try:
                top_dests = get_common_nfdump_data("dests", "1h")
                # Filter top 3
                evidence_dests = [
                    {"ip": d["key"], "bytes": d["bytes"]} for d in top_dests[:3]
                ]

                overlays.append(
                    {
                        "kind": "hint",
                        "source_event_id": evt["id"],
                        "label": "Correlate with Top Traffic Destinations",
                        "confidence": "medium",
                        "links": [
                            {
                                "title": "View Traffic",
                                "href": "/#section-worldmap;network",
                            },
                            {
                                "title": "Firewall Logs",
                                "href": "/#section-summary;security",
                            },
                        ],
                        "evidence": {"top_destinations": evidence_dests},
                    }
                )
            except:
                pass

        # Rule 3: SNMP Interface Utilization
        if "SNMP" in evt["source"] and "Utilization" in evt["title"]:
            try:
                top_talkers = get_common_nfdump_data("sources", "1h")
                evidence_talkers = [
                    {"ip": d["key"], "bytes": d["bytes"]} for d in top_talkers[:3]
                ]

                overlays.append(
                    {
                        "kind": "hint",
                        "source_event_id": evt["id"],
                        "label": "Top Talkers during high utilization",
                        "confidence": "high",
                        "links": [{"title": "View Top Sources", "href": "/#network"}],
                        "evidence": {"top_talkers": evidence_talkers},
                    }
                )
            except:
                pass

        # Rule 5: New Destination (Generic 'New' tag handling)
        if "New" in evt["title"] and "Destination" in evt["title"]:
            overlays.append(
                {
                    "kind": "hint",
                    "source_event_id": evt["id"],
                    "label": "Check for firewall blocks to this destination",
                    "confidence": "low",
                    "links": [{"title": "Check Firewall", "href": "/#firewall"}],
                    "evidence": {
                        "note": "Cross-reference newly visited IP with block logs"
                    },
                }
            )

    # Generic loop for ANY high severity event to just show system health
    # (Fallback rule)
    if not overlays and len(events) > 0:
        # Just pick the latest one
        evt = events[0]
        overlays.append(
            {
                "kind": "hint",
                "source_event_id": evt["id"],
                "label": "System Status Check",
                "confidence": "low",
                "links": [{"title": "System Health", "href": "/#section-summary"}],
                "evidence": {},
            }
        )

    _overlay_cache[window] = overlays
    _LAST_CACHE_TS = now

    return overlays
