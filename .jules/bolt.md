## 2024-05-22 - [Optimized DNS Resolution]
**Learning:** Instantiating `dns.resolver.Resolver` inside a frequently called function (`resolve_hostname`) causes unnecessary overhead, especially when resolving many IPs.
**Action:** Move the resolver instantiation to a global scope or reuse a single instance to improve performance.
