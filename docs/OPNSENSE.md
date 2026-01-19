# OPNsense Configuration Guide for PHOBOS-NET

This document explains how to configure **OPNsense** to export data to **PHOBOS-NET**.

PHOBOS-NET is **read-only and observational**.
It does not enforce policy, block traffic, or modify firewall behavior.
Correct configuration ensures the dashboard reflects reality accurately.

---

## Overview

PHOBOS-NET can observe the following data streams from OPNsense:

| Data Source | Purpose | Required |
|------------|--------|----------|
| Syslog (filterlog) | Firewall packet decisions (pass/block) | Yes |
| Syslog (firewall/admin) | Firewall & system events | Optional |
| NetFlow | Traffic flows & volume | Yes |
| SNMP | Interface & system metrics | Optional |

Each stream is independent.
Missing streams will show as “—”, not as errors.

---

## 1. Syslog Configuration (Required)

Syslog provides packet-level firewall decisions via filterlog.

Navigate to:
System → Settings → Logging / targets

Add Syslog Target:
- Transport: UDP
- Target: PHOBOS-NET host IP
- Port: 514
- Applications: filter (filterlog)
- Format: BSD

---

## 2. NetFlow Configuration (Required)

Navigate to:
Reporting → NetFlow

- Enable NetFlow
- Export Host: PHOBOS-NET IP
- Port: 2055
- Interfaces: WAN
- Active Timeout: 60s

---

## 3. SNMP Configuration (Optional)

Navigate to:
Services → SNMP

- Enable SNMP
- Community: read-only
- Version: v2c
- Bind Interface: LAN

---

## Validation

After configuration:
- Syslog receiver active
- NetFlow active
- SNMP metrics populated or shown as “—”

---

PHOBOS-NET — Observe calmly. Decide confidently.
