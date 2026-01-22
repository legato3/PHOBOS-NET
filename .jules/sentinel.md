## 2024-03-24 - SNMP Command Injection
**Vulnerability:** Command Injection in SNMP service helpers (`app/services/shared/snmp.py` and `app/api/routes/traffic.py`) via interpolated configuration strings passed to `subprocess.check_output(..., shell=True)`.
**Learning:** `shell=True` was used for convenience to handle shell redirection (`2>/dev/null`) and space-separated argument strings. This exposed the application to injection if configuration values (like community string) were compromised or user-controlled.
**Prevention:** Always use `subprocess.run/check_output` with `shell=False` (default) and pass arguments as a list. Replace shell redirection with Python's `stderr=subprocess.DEVNULL` or `stderr=subprocess.PIPE`.
