## 2024-05-22 - [Optimized DNS Resolution]
**Learning:** Instantiating `dns.resolver.Resolver` inside a frequently called function (`resolve_hostname`) causes unnecessary overhead, especially when resolving many IPs.
**Action:** Move the resolver instantiation to a global scope or reuse a single instance to improve performance.

## 2024-05-22 - [Optimized String Prefix Check]
**Learning:** Using `startswith` with a tuple of prefixes is significantly faster (up to 10x) than looping over a list of prefixes in Python, as it pushes the loop to C level.
**Action:** Convert prefix lists to tuples and use `str.startswith(tuple)` for frequent checks like IP subnet matching.

## 2024-05-22 - [Optimized LRU Cache Pruning]
**Learning:** For LRU caches using dictionaries in Python 3.7+, insertion order is preserved. Pruning by popping the first key (`next(iter(d))`) is O(1) compared to sorting by timestamp which is O(N log N).
**Action:** Rely on dictionary insertion order for LRU eviction. When updating an existing item, delete and re-insert it to move it to the end (MRU).
