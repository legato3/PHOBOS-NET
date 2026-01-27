import time
import os
import tracemalloc

FILE_PATH = "temp_threats.txt"
LINES = 200000

def generate_file():
    with open(FILE_PATH, "w") as f:
        for i in range(LINES):
            f.write(f"192.168.{i // 256}.{i % 256}\n")
            if i % 10 == 0:
                f.write(f"# Comment {i}\n")
            if i % 5 == 0:
                f.write("\n")

def load_old():
    with open(FILE_PATH, "r") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return set(lines)

def load_new():
    with open(FILE_PATH, "r") as f:
        return {s for l in f for s in (l.strip(),) if s and not s.startswith("#")}

def benchmark(name, func):
    tracemalloc.start()
    start_time = time.time()
    res = func()
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"{name}:")
    print(f"  Time: {end_time - start_time:.4f}s")
    print(f"  Memory Peak: {peak / 1024 / 1024:.2f} MB")
    print(f"  Result size: {len(res)}")
    return end_time - start_time

if __name__ == "__main__":
    generate_file()
    print(f"Generated {LINES} entries.")

    # Warm up disk cache
    load_old()

    t_old = benchmark("Old Implementation", load_old)
    t_new = benchmark("New Implementation", load_new)

    print(f"Improvement: {(t_old - t_new) / t_old * 100:.2f}% faster")

    os.remove(FILE_PATH)
