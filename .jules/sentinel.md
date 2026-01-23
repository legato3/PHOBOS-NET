## 2025-02-14 - Unsafe SNMP Subprocess Execution
**Vulnerability:** Found multiple instances of `subprocess.check_output(cmd, shell=True)` where `cmd` was constructed using f-strings containing variables like `snmp_community` and `snmp_host`. This allows for Command Injection if these variables are compromised or malicious.
**Learning:** The application relies heavily on external binaries (`snmpwalk`, `snmpget`, `nfdump`) and used shell execution for convenience (argument string construction, redirection like `2>/dev/null`).
**Prevention:** Mandate `shell=False` for all `subprocess` calls. Construct command arguments as lists. Replace shell features like redirection with Python equivalents (e.g., `stderr=subprocess.DEVNULL`).
