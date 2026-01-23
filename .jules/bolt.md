## 2024-05-20 - Netflow Parsing Optimization & Testing
**Learning:** `nfdump` parsing loops were recalculating `max()` indices on every iteration, and performing expensive string operations (`lower().strip()`) on every line. Moving calculations out of the loop and using a fast-path check (`isdigit()`) for data rows yielded a ~38% speedup.
**Action:** Always check for loop invariants in parsing logic.

**Learning:** Testing `app.services` modules in isolation is difficult because `app/__init__.py` runs `create_app()` on import. This requires extensive `sys.modules` mocking (including fake package structures for `app`, `app.core`, etc.) to bypass side effects.
**Action:** Use the mocking pattern established in `tests/test_netflow_parsing.py` when adding tests for other service modules.
