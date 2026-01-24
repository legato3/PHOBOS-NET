## 2025-02-14 - Unsafe SNMP Subprocess Execution
**Vulnerability:** Found multiple instances of `subprocess.check_output(cmd, shell=True)` where `cmd` was constructed using f-strings containing variables like `snmp_community` and `snmp_host`. This allows for Command Injection if these variables are compromised or malicious.
**Learning:** The application relies heavily on external binaries (`snmpwalk`, `snmpget`, `nfdump`) and used shell execution for convenience (argument string construction, redirection like `2>/dev/null`).
**Prevention:** Mandate `shell=False` for all `subprocess` calls. Construct command arguments as lists. Replace shell features like redirection with Python equivalents (e.g., `stderr=subprocess.DEVNULL`).

## 2025-02-15 - Argument Injection in Network Tools
**Vulnerability:** `dns_lookup`, `ping_host`, and `whois_lookup` allowed user input starting with `-` to be passed to `dig`, `ping`, and `whois` commands. Although `shell=False` was used, `subprocess` passes these arguments directly to the binaries, which interpret them as flags (Argument Injection).
**Learning:** Sanitizing for shell metacharacters (`|`, `;`, etc.) is not enough when invoking binaries that take flags. Input starting with `-` must also be handled, either by validation or using `--` delimiter.
**Prevention:** Explicitly validate that user input does not start with `-` when passing it as a positional argument to external tools, or use `--` to signify end of options where supported.
