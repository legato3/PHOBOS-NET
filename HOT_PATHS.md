# Hot Paths Analysis

This document identifies performance bottlenecks and "hot paths" in the backend codebase. These areas involve per-request loops, blocking operations, or repeated calculations that may impact scalability.

## 1. `app/api/routes/traffic.py`: `api_network_stats_overview`

**Risk Level:** HIGH
**Type:** Per-flow Loop, Large Dataset Iteration

The `api_network_stats_overview` function retrieves *all* flows for the requested time range to count active flows. This involves iterating over a potentially massive stream of lines in Python.

*   **Code Location:** `app/api/routes/traffic.py`
*   **Operation:**
    ```python
    stream = stream_nfdump(["-O", "bytes", "-A", "srcip,dstip,srcport,dstport,proto", "-q"], tf_range)
    for line in stream:
        # ...
        if line.count(',') >= 7:
            active_flows_count += 1
    ```
*   **Issue:** Iterating millions of lines in Python is slow. This scales linearly with traffic volume.
*   **Additional Risk:** It calls `run_nfdump` *two more times* (sampling and anomalies) within the same request.

## 2. `app/api/routes/traffic.py`: `api_flows`

**Risk Level:** HIGH
**Type:** Per-flow Enrichment Loop

The `api_flows` endpoint enriches flow data with GeoIP, DNS, and Threat Intelligence. While some lookups are cached, the sheer volume of operations per request (even with limit=100) is significant.

*   **Code Location:** `app/api/routes/traffic.py`
*   **Operation:**
    ```python
    for line in lines[start_idx:]:
        # ...
        src_geo = lookup_geo(src) or {}
        dst_geo = lookup_geo(dst) or {}
        src_hostname = resolve_ip(src)
        dst_hostname = resolve_ip(dst)
        # ...
        threat_info = get_threat_info(threat_ip)
    ```
*   **Issue:** `lookup_geo` involves cache checks and potential MMDB lookups. `resolve_ip` involves cache checks and lock acquisition. Repeated for every flow row.

## 3. `app/services/netflow/netflow.py`: `parse_csv`

**Risk Level:** CRITICAL
**Type:** Core Parsing Loop

This utility is used by almost every statistics endpoint (`sources`, `destinations`, `ports`, `protos`). It parses CSV output from `nfdump` line-by-line.

*   **Code Location:** `app/services/netflow/netflow.py`
*   **Operation:**
    ```python
    for i, line in enumerate(lines_iter):
        # ...
        parts = line.split(",")
        # ...
        key = parts[key_idx].strip()
        bytes_val = int(float(parts[bytes_idx]))
    ```
*   **Issue:** String manipulation (`split`, `strip`, `lower`) and type conversion (`int`, `float`) in Python are CPU-intensive for large datasets. This is the primary bottleneck for data visualization endpoints.

## 4. `app/api/routes/security.py`: `api_alerts` / `run_all_detections`

**Risk Level:** MEDIUM-HIGH
**Type:** Repeated Iteration over Flow Data

The `api_alerts` endpoint calls `run_all_detections`, which in turn calls multiple detection functions (`detect_port_scan`, `detect_brute_force`, etc.).

*   **Code Location:** `app/services/security/threats.py`
*   **Operation:**
    ```python
    def run_all_detections(...):
        # ...
        all_alerts.extend(detect_port_scan(flow_data))
        all_alerts.extend(detect_brute_force(flow_data))
        all_alerts.extend(detect_data_exfiltration(sources_data, destinations_data))
        # ...
    ```
*   **Issue:** `flow_data` (up to 2000 items) is iterated multiple times (once per detector). While N=2000 is manageable, adding more detectors increases latency linearly.

## 5. `app/api/routes/traffic.py`: `api_stats_batch`

**Risk Level:** MEDIUM
**Type:** Parallel Execution Overhead

This endpoint executes multiple other endpoints in parallel using a thread pool.

*   **Code Location:** `app/api/routes/traffic.py`
*   **Operation:**
    ```python
    futures.append(state._batch_executor.submit(process_batch_request, ...))
    ```
*   **Issue:** While parallelization helps total latency, it causes a burst of CPU usage (GIL contention) and `nfdump` subprocess spawning. If 10 requests are batched, 10+ `nfdump` processes might be spawned simultaneously, potentially starving the system.

## 6. Blocking Operations

*   **`run_nfdump`**: Uses `subprocess.run` (synchronous blocking). Even though it's in a separate process, the Python thread waits. In `api_flows` and `api_network_stats_overview`, this blocks the request thread.
*   **`api_bandwidth` (Mock Mode)**: If `state._has_nfdump` is False, it executes synchronous SQLite writes inside the request handler for simulation, which is a significant blocking operation.
