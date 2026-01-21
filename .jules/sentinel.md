## 2025-01-21 - [CRITICAL] Remote Code Execution via "Network Diagnostics" Endpoint

**Vulnerability:** Found an unauthenticated endpoint `/api/tools/shell` that accepted arbitrary shell commands via JSON payload and executed them using `subprocess.run(shell=True)`. It attempted to use a denylist for sanitization, but it was trivially bypassable (e.g., `id`, `ls`).

**Learning:** The feature was intended for "network diagnostics" but was implemented as a generic shell execution tool. This highlights the danger of "convenience" features that bypass standard security boundaries. A denylist approach for shell commands is almost always insufficient.

**Prevention:** Never allow arbitrary shell execution. If specific tools are needed (ping, dig), wrap them in specific functions with strict argument validation (allowlists, not denylists). Do not expose "shell" endpoints.
