# OPNsense Quick Start — PHOBOS-NET (Docker)

This one-page guide helps you get **PHOBOS-NET** working with **OPNsense** as quickly as possible.
It is intended for **Docker Hub users** who want results without reading full documentation.

PHOBOS-NET is **read-only and observational**.  
It does not change firewall behavior.

---

## What You Need (Required)

PHOBOS-NET expects **all four** data streams:

1. Syslog — Firewall packet decisions (filterlog)
2. Syslog — Firewall / admin events
3. NetFlow — Traffic flows
4. SNMP — System & interface metrics

If a stream is missing, PHOBOS-NET will show **“—”** instead of guessing.

---

## Step 1: Syslog (Packet Decisions)

**OPNsense path:**
System → Settings → Logging / targets

Add a syslog target:

- Transport: UDP
- Target: IP of PHOBOS-NET host
- Port: **514**
- Applications: **filter (filterlog)**
- Format: BSD

This is the most important data source.

---

## Step 2: Syslog (Firewall / Admin Events)

Add a second syslog target:

- Transport: UDP
- Target: IP of PHOBOS-NET host
- Port: **515**
- Applications: **firewall (firewall)**
- Format: BSD

Notes:
- Low volume is normal
- Used for config changes and service events

---

## Step 3: NetFlow

**OPNsense path:**
Reporting → NetFlow

Configure:

- Enable NetFlow
- Export Host: PHOBOS-NET host IP
- Export Port: **2055**
- Version: v9 or IPFIX
- Interfaces: WAN (minimum)
- Active Timeout: 60s

Flow data may appear with a short delay.

---

## Step 4: SNMP

**OPNsense path:**
Services → SNMP

Configure:

- Enable SNMP
- Version: v2c
- Community: read-only
- Bind Interface: LAN
- Firewall rule: allow SNMP from PHOBOS-NET host

SNMP is required for:
- Interface throughput
- Interface status
- System health signals

PHOBOS-NET does not infer these metrics.

---

## Step 5: Verify in PHOBOS-NET

Open the web UI and check:

**Server / Health page**
- Syslog (514): Active
- Firewall Syslog (515): Active
- NetFlow: Active
- SNMP: Active

**Firewall / Network pages**
- Data appears gradually
- No sudden alert spikes
- “—” means missing data, not failure

---

## Common Notes

- Flow counts ≠ host counts
- Low firewall-admin log volume is normal
- PHOBOS-NET never guesses missing data
- Calm dashboards are expected

---

For full details, see:
`docs/OPNSENSE.md`

**PHOBOS-NET — Observe calmly. Decide confidently.**
