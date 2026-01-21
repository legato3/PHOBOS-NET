# PHOBOS-NET Motion Rules
## Status Card v3.1 (micro-motion, calm)

Motion communicates liveness and change, not decoration.

### Allowed motions (Status Card)
1) **Hero value change**
- Transition: opacity (optionally tiny blur)
- Duration: 200–300ms
- Easing: ease-out
- No sliding/bouncing/scaling

2) **State dot pulse (ACTIVE only)**
- Slow pulse (2.0–2.6s)
- Low amplitude (0.95 → 1.10)
- Only when ACTIVE/ONLINE

3) **Hover**
- Border intensity increase
- Optional 1–2px lift
- No animated backgrounds

### Respect reduced motion
- If `prefers-reduced-motion: reduce`:
  - Disable pulses
  - Use minimal transitions
