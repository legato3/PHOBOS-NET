"""CPU stats helpers for PROX_NFDUMP."""
import time

import app.core.state as state


def read_cpu_stat():
    """Read CPU times from /proc/stat. Returns dict with cpu_id -> [times]."""
    cpu_times = {}
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('cpu'):
                    parts = line.split()
                    cpu_id = parts[0]
                    times = [int(x) for x in parts[1:8]]  # user, nice, system, idle, iowait, irq, softirq
                    if len(times) >= 4:
                        cpu_times[cpu_id] = times
    except Exception:
        pass
    return cpu_times


def calculate_cpu_percent_from_stat():
    """Calculate CPU percentage using /proc/stat with cached previous reading."""
    now = time.time()

    with state._cpu_stat_lock:
        current_times = read_cpu_stat()
        if not current_times or 'cpu' not in current_times:
            return None, None, None

        # If we have previous data and it's recent (< 5 seconds old)
        if state._cpu_stat_prev['times'] and 'cpu' in state._cpu_stat_prev['times'] and (now - state._cpu_stat_prev['ts']) < 5:
            prev = state._cpu_stat_prev['times']['cpu']
            curr = current_times['cpu']

            # Calculate deltas
            prev_total = sum(prev[:4])  # user, nice, system, idle
            curr_total = sum(curr[:4])
            total_delta = curr_total - prev_total

            if total_delta > 0:
                idle_delta = curr[3] - prev[3]  # idle is index 3
                cpu_percent = 100.0 * (1.0 - (idle_delta / total_delta))
                cpu_percent = max(0.0, min(100.0, cpu_percent))

                # Calculate per-core percentages
                per_core = []
                core_ids = [k for k in current_times.keys() if k.startswith('cpu') and k != 'cpu']
                core_ids.sort(key=lambda x: int(x[3:]) if len(x) > 3 and x[3:].isdigit() else 999)

                for core_id in core_ids:
                    if core_id in current_times and core_id in state._cpu_stat_prev['times']:
                        p = state._cpu_stat_prev['times'][core_id]
                        c = current_times[core_id]
                        p_total = sum(p[:4])
                        c_total = sum(c[:4])
                        c_delta = c_total - p_total
                        if c_delta > 0:
                            c_idle_delta = c[3] - p[3]
                            core_percent = 100.0 * (1.0 - (c_idle_delta / c_delta))
                            per_core.append(max(0.0, min(100.0, core_percent)))

                # Count cores
                num_cores = len(core_ids)

                # Update cache
                state._cpu_stat_prev = {'times': current_times, 'ts': now}
                return round(cpu_percent, 1), per_core if per_core else None, num_cores

        # First run or cache expired - store current and return None
        state._cpu_stat_prev = {'times': current_times, 'ts': now}
        # Count cores for first run
        core_ids = [k for k in current_times.keys() if k.startswith('cpu') and k != 'cpu']
        num_cores = len(core_ids)
        return None, None, num_cores
