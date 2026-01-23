# Applying Status Card v3 across PHOBOS-NET

## Goal
Make every server-style widget an instance of the canonical Status Card v3 component.

## Steps
1) Identify candidates: title + state + primary number + supporting stats
2) Normalize templates to the DOM contract:
   - header, hero, statstrip (4 stats)
   - include subvalue block always
3) Adopt tokens:
   - import `frontend/src/css/status-card-tokens.css` (or merge into global tokens)
   - replace hardcoded colors in card rules with tokens
4) Remove per-widget overrides:
   - delete layout tweaks that only apply to one card
   - if a different layout is needed, create v4 instead of mutating v3
5) Verify invariants:
   - hero dominates vertically
   - statstrip height bounded
   - no “updated/ago” strings
   - no jumps when missing values

## Quick test list
- NetFlow: low/high traffic, missing last file
- Filterlog: active/idle, errors present
- Firewall: active/idle, no events
- Resize: narrow/wide layouts
- Reduced motion enabled
