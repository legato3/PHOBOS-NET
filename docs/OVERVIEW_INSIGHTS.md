# Overview Insights API

Endpoint: `GET /api/overview/insights`

Optional query:
- `tf`: `15m | 30m | 1h | 4h | 6h | 12h` (default `1h`)

Purpose: provide a single bundle for Overview stat boxes (current values + 1h deltas) and stat detail modal content.

## Windows

- `now_range`: current window (default last 60 minutes)
- `prev_range`: previous window of the same duration
- `seconds`: window length in seconds (default 3600)

## Response Shape

```
{
  "window": {
    "now_range": "YYYY/MM/DD.HH:MM:SS-YYYY/MM/DD.HH:MM:SS",
    "prev_range": "YYYY/MM/DD.HH:MM:SS-YYYY/MM/DD.HH:MM:SS",
    "seconds": 3600,
    "label": "last 60m vs previous 60m"
  },
  "stats": {
    "<key>": {
      "value": "string|number",
      "delta_1h": "number|string|null",
      "delta_pct_1h": "number|null",
      "trend": "up|down|flat|unknown",
      "severity": "info|notice|warn",
      "detail": {
        "headline": "string",
        "breakdowns": [{ "label": "string", "value": "string|number", "hint": "string" }],
        "top": [{ "label": "string", "value": "string|number", "meta": {} }],
        "explanations": {
          "why": "string",
          "what_changed": "string",
          "next_checks": ["string", "..."]
        }
      }
    }
  }
}
```

## Stat Keys

- `networkStatus`
- `activeAlerts`
- `trafficLevel`
- `protectedConnections`
- `internetExposure`
- `unusualActivity`

## Notes

- Deltas compare **current window vs previous window**.
- If a prior window is unavailable, deltas may be `null` and `trend` will be `"unknown"`.
- Values are derived from existing aggregated telemetry and cached sources; no heavy new pipelines.
