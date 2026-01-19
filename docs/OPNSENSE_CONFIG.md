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
| Syslog (firewall/admin) | Firewall & system events | Yes |
| NetFlow | Traffic flows & volume | Yes |
| SNMP | Interface & system metrics | Yes |

Each stream is independent.
Missing streams will show as “—”, not as errors.

---

## 1. Syslog Configuration

Syslog provides packet-level firewall decisions via filterlog.

Navigate to:
System → Settings → Logging / Remote

Add Syslog Target:
- Transport: UDP
- Applications: filter (filterlog)
- Levels: info
- Facilities: locally used (0)
- Target: PHOBOS-NET host IP
- Port: 514
- Format: RFC5424

Add Second Target:
- Transport: UDP
- Applications: all except filter (filterlog)
- Levels: info
- Facilities: all
- Target: PHOBOS-NET host IP
- Port: 515
- Format: RFC5424
---

## 2. NetFlow Configuration

Navigate to:
Reporting → NetFlow

- Enable NetFlow
- Destination: PHOBOS-NET IP
- Port: 2055
- Interfaces: WAN, LAN
- Version: v9
- Active Timeout: 60s

---

## 3. SNMP Configuration

Navigate to:
Services → Net-SNMP

- Enable SNMP Service
  
Fill in according to your preferences:

- SNMP Community
- SNMP Location
- SNMP Contact
- Listen IPs: OPNSense LAN IP

---

## Validation

After configuration:
- Syslog receiver active
- NetFlow active
- SNMP metrics populated or shown as “—”

---

PHOBOS-NET — Observe calmly. Decide confidently.
