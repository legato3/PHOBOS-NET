import time
import socket
import threading
import random
from concurrent.futures import ThreadPoolExecutor

# Mocks
PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS",
    3306: "MySQL", 6379: "Redis"
}
_service_cache = {}
_lock_service_cache = threading.Lock()

def lookup_current(port_num, proto):
    service_key = (port_num, proto)
    if port_num in PORTS:
        svc = PORTS[port_num]
    else:
        with _lock_service_cache:
            svc = _service_cache.get(service_key)
            if svc is None:
                try:
                    svc = socket.getservbyport(port_num, proto)
                except OSError:
                    svc = str(port_num)
                _service_cache[service_key] = svc
    return svc

def lookup_optimized(port_num, proto):
    service_key = (port_num, proto)
    if port_num in PORTS:
        svc = PORTS[port_num]
    else:
        svc = _service_cache.get(service_key)
        if svc is None:
            with _lock_service_cache:
                svc = _service_cache.get(service_key)
                if svc is None:
                    try:
                        svc = socket.getservbyport(port_num, proto)
                    except OSError:
                        svc = str(port_num)
                    _service_cache[service_key] = svc
    return svc

def run_benchmark(lookup_func, name, num_threads=4, num_iterations=10000):
    # Reset cache for fair comparison?
    # Actually, we want to measure the steady state performance (cache hits),
    # because that's where the lock contention hurts most.
    # So we should pre-populate the cache or let it fill up.

    global _service_cache
    _service_cache = {}

    # Generate test data
    # Mix of PORTS hits, Cache hits (repeated unknown ports), and Misses (new unknown ports - unlikely in loop but possible)
    # We simulate a scenario where many flows use the same set of ports.

    ports_to_query = []
    # 50% hits in PORTS
    # 40% hits in Cache (non-static ports, but repeated)
    # 10% misses (new ports - initially)

    known_ports = list(PORTS.keys())
    # Some ports that are not in PORTS but resolve (e.g. 53 DNS is missing in my mock above but common)
    resolvable_ports = [53, 25, 110, 143, 993, 995]
    # Some ports that don't resolve
    unresolvable_ports = [12345, 12346, 12347, 12348]

    dynamic_ports = resolvable_ports + unresolvable_ports

    for _ in range(num_iterations):
        r = random.random()
        if r < 0.5:
            p = random.choice(known_ports)
        else:
            p = random.choice(dynamic_ports)
        ports_to_query.append((p, 'tcp'))

    start_time = time.time()

    def worker(chunk):
        for p, proto in chunk:
            lookup_func(p, proto)

    # Split work into chunks
    chunk_size = num_iterations // num_threads
    chunks = [ports_to_query[i:i + chunk_size] for i in range(0, len(ports_to_query), chunk_size)]

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        list(executor.map(worker, chunks))

    end_time = time.time()
    duration = end_time - start_time
    print(f"{name}: {duration:.4f} seconds ({num_threads} threads, {num_iterations} ops)")
    return duration

if __name__ == "__main__":
    print("Running Benchmark...")
    # Warm up ?

    # Single thread comparison
    print("\n--- Single Threaded ---")
    t1 = run_benchmark(lookup_current, "Current", num_threads=1, num_iterations=20000)
    t2 = run_benchmark(lookup_optimized, "Optimized", num_threads=1, num_iterations=20000)

    # Multi thread comparison (High Contention)
    print("\n--- Multi Threaded (8 threads) ---")
    t3 = run_benchmark(lookup_current, "Current", num_threads=8, num_iterations=40000)
    t4 = run_benchmark(lookup_optimized, "Optimized", num_threads=8, num_iterations=40000)

    if t3 > 0:
        improvement = (t3 - t4) / t3 * 100
        print(f"\nImprovement in multi-threaded: {improvement:.2f}%")
