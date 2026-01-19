# Getting Started with PHOBOS-NET

This guide is intentionally minimal.

PHOBOS-NET is not packaged as a turnkey product.
It assumes familiarity with networking tools and self-hosting.

---

## Requirements

- Linux host
- Python 3.10+
- nfdump installed
- NetFlow exporter configured
- SNMP enabled on firewall or router

---

## Basic Steps

1. Clone the repository
2. Install Python dependencies
3. Configure NetFlow input directory
4. Configure SNMP targets
5. Start the backend
6. Open the web UI

Exact commands are intentionally not prescribed;
this project is meant to be explored, not deployed blindly.

---

## First Launch Expectations

- Baselines will warm up over time
- Insights may be sparse initially
- Normal behavior will be stated explicitly

This is expected.
