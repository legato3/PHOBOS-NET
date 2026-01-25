# Timeline (Phase 1)

This timeline is a calm, read-only change log. It records factual state transitions only.

## Event Model

Each event is a `TimelineEvent` with:
- `ts`: Unix seconds
- `type`: stable identifier
- `severity`: `info` | `notice` | `warn`
- `title`: short, human-readable
- `detail`: optional detail string
- `source`: `netflow` | `syslog` | `firewall` | `snmp` | `system`
- `meta`: JSON-safe primitives only

## Emission Rules

Events are emitted only on state transitions. No alerts, scoring, or automation.

### NetFlow
- `netflow_active` (info): first ingestion after inactive/unknown
- `netflow_inactive` (notice): no ingestion for > 1h

### Syslog Receivers
- `syslog_active` (info): port 514 or 515 becomes active
- `syslog_inactive` (notice): no logs for > 1h on port 514 or 515

### Firewall Decisions
- `firewall_stream_active` (notice): first firewall decision after empty/stale

### SNMP
- `snmp_reachable` (notice): reachable transition
- `snmp_unreachable` (warn): unreachable transition

### System
- `system_start` (info): service start
- `system_stop` (info): service stop

### Rate Limiting
- `rate_limited` (notice): emitted once when the event stream exceeds 30 events/min

## Guardrails

- Dedupe identical `title + source + meta` within 60s.
- Global rate limit: 30 events/minute; overflow is dropped.
- No raw syslog lines are stored in `meta`.
