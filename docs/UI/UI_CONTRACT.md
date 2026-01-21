# UI Contract: Server Status Cards V2

- Redesign only the NetFlow and Filterlog status widgets on the Server page with one shared status-card grammar.
- Enforce hierarchy: header meta -> hero metric -> stat strip; all data always visible.
- Meta tabs must be SOURCE, PORT, UPDATED, STATE with rectangular border-only styling (no filled blocks).
- Updated, Last, and Status appear once each per card.
- No scanlines.
- No rounded pills.
- Use flat glass surfaces, subtle borders, minimal glow; no foggy gradients behind content.
- Keep all existing data bindings; do not change semantics or API calls.
- Scope changes to `frontend/templates/tabs/server.html` and status-card CSS used by these widgets.
