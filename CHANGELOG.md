# Changelog

All notable changes to PHOBOS-NET are documented in this file.

This project follows a **calm, conservative release philosophy**:
- No breaking changes without clear justification
- No silent behavior changes
- Truthfulness and observability take precedence over features

---

## [1.2.0] — 2026-01-19

### Added
- Public open-source release
- Docker Hub distribution (`legato3/phobos-net`)
- OPNsense firewall visibility via normalized `filterlog` parsing
- Dedicated firewall event ingestion pipeline (parser → store → API)
- SNMP-based system and interface monitoring (required)
- Clear separation between:
  - System Health (operability)
  - Alerts (actionable, persistent)
  - Indicators (contextual signals)
- Secondary syslog stream support (UDP 515)

### Changed
- Health scoring now reflects monitoring operability only
- Alert escalation requires stricter persistence
- UI explicitly distinguishes unavailable data (`—`) from zero values
- Docker image hardened (non-root, OCI-compliant)

### Documentation
- GitHub README aligned with Docker Hub README
- Added CONTRIBUTING.md, SECURITY.md, AGENTS.md
- Added OPNsense Quick Start and full configuration guide
- Added release checklist for maintainability

---

## [Unreleased]

### Planned (Intentionally Modest)
- Timeline-based correlation (non-escalating)
- Historical context and trend visualizations
- UI clarity and documentation refinements

No automatic response or enforcement features are planned.
