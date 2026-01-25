# Timeline and Events

The Timeline captures calm, read-only state transitions. The Events log adds notable detections on top of existing activity. Both are read-only and do not change alerts, health, or scoring.

## Timeline (State Changes)

Each timeline entry is a `TimelineEvent`:
- `ts`: Unix seconds
- `type`: stable identifier
- `severity`: `info` | `notice` | `warn`
- `title`: short, human-readable
- `detail`: optional detail string
- `source`: `netflow` | `syslog` | `firewall` | `snmp` | `system`
- `meta`: JSON-safe primitives only

Emission rules (state transitions only):
- NetFlow: `netflow_active`, `netflow_inactive`
- Syslog: `syslog_active`, `syslog_inactive` (ports 514/515)
- Firewall: `firewall_stream_active`
- SNMP: `snmp_reachable`, `snmp_unreachable`
- System: `system_start`, `system_stop`
- Rate limiting: `rate_limited`

Guardrails:
- Dedupe identical `title + source + meta` within 60s.
- Global rate limit: 30 events/minute; overflow is dropped.
- No raw syslog lines stored in `meta`.

## Events (Notable + Activity)

Events are normalized records used by the Events widget and API.

Event model:
- `id`: unique id
- `ts`: Unix seconds
- `source`: `netflow` | `filterlog` | `firewall` | `syslog` | `snmp` | `system`
- `severity`: `info` | `notice` | `warn`
- `title`: short label
- `summary`: one-sentence why it matters
- `tags`: list of short tags
- `evidence`: structured JSON-safe fields
- `rule_id`: rule identifier
- `dedupe_key`: rule + primary entity
- `window_sec`: analysis window
- `count`: aggregated count
- `kind`: `activity` | `notable`

### Activity

Activity events are derived from timeline events (state changes) and stored as read-only history.

### Notable Rules (Phase 1)

NetFlow:
- `NEW_EXTERNAL_DESTINATION`: new public destination not seen in last 24h
- `TOP_TALKER_CHANGED`: top src/dst changes vs prior 5m
- `PORT_SPIKE`: dst port spikes >= 3x baseline

Firewall / Filterlog:
- `BLOCK_SPIKE`: block rate spikes >= 3x baseline
- `NEW_INBOUND_WAN_SOURCE`: new inbound WAN source not seen in 24h
- `RULE_HIT_SPIKE`: rule hit spikes >= 3x baseline

Syslog (DNS if available):
- `NXDOMAIN_BURST`: NXDOMAIN spikes >= 3x baseline
- `NEW_DOMAIN_TO_MANY_HOSTS`: new domain queried by many hosts

System:
- `SOURCE_STALE`: data source stops producing
- `PARSER_ERROR_SPIKE`: parse errors spike >= 3x baseline

### Notable Guardrails

- Dedupe key = `rule_id + primary entity`.
- Cooldown: 10 minutes per dedupe key.
- Max notable per hour: 8 (drop lower severity first).
- If an event persists, update `count` instead of creating new rows.
