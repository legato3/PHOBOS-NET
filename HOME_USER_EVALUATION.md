# PHOBOS-NET Home User Evaluation

## Overview
PHOBOS-NET is a powerful network observability tool, but its current language and presentation are heavily oriented toward Security Operations Centers (SOCs) and professional analysts. For a home user with a small network (5-20 devices) and no security training, the dashboard is likely to cause unnecessary anxiety ("alert fatigue") and confusion due to technical jargon.

## 1. Confusing Terminology
The application uses industry-standard cybersecurity terms that are often misinterpreted by laypeople.

| Current Term | Context | User Interpretation | Suggestion |
| :--- | :--- | :--- | :--- |
| **"Anomalies"** | Network Tab, Dashboard | "I've been hacked." | **"Unusual Activity"** or **"Traffic Spikes"**. (Anomalies often just mean a game download or backup). |
| **"Threats"** | Security Tab, World Map | "There is an active attacker in my house." | **"Blocked Risks"** or **"Suspicious Sources"**. (Most "threats" are just background noise hitting the firewall). |
| **"Lateral Movement"** | Alert Filters, Logic | Military/Tactical maneuver. | **"Device-to-Device Traffic"**. |
| **"Data Exfil"** | Alert Filters, Logic | "Someone is stealing my files." | **"Large Upload"** or **"High Outbound Traffic"**. |
| **"Kill Chain" / "MITRE"** | Security Tab, Widgets | Complex SOC methodology. | **"Attack Stage"** or hide by default for home users. |
| **"Beaconing" / "C2"** | Detection Reasons | Spyware/Malware. | **"Repetitive Connections"**. |
| **"Forensics"** | Tab Name | Crime scene investigation. | **"Deep Dive"** or **"Traffic Analysis"**. |
| **"Baseline Warming"** | Protocol Widget | "The system is overheating" or "It's broken". | **"Learning Network Patterns..."** |

## 2. Features That Look Broken (But Aren't)
Features that function correctly technically but communicate their status poorly to a non-technical user.

*   **Feed Health "Detection may be reduced"**:
    *   **Issue**: If a few threat feeds fail to update (common with public feeds), the UI warns that detection is "reduced". This sounds like a system failure or vulnerability.
    *   **Suggestion**: If the majority of feeds are up, show a green "System Online" status with a small "Partially Updated" note, rather than a warning.
*   **Empty States ("No Threat Activity Data")**:
    *   **Issue**: When the system is clean (no threats), it displays "No Threat Activity Data" with a generic icon. It feels like "Data missing" rather than "You are safe".
    *   **Suggestion**: Use a positive state. "All Clear. No threats detected in the last 24 hours."
*   **"Unknown" Identity**:
    *   **Issue**: "Hostname: Unknown", "Location: Unknown".
    *   **Suggestion**: Use "Private / Local" or "Unresolved" which sounds less like a failure of the tool.

## 3. Metrics That Feel Scary (But Are Normal)
Metrics that are presented in a way that emphasizes danger, even when the system is doing its job.

*   **Blocked Events (High Counts)**:
    *   **Issue**: A home firewall might block thousands of packets a day. Seeing "Blocked Events: 5,432" in Red/Orange is terrifying.
    *   **Suggestion**: Frame this as a success. "Protected you from 5,432 attempts." Use Green or Blue for "Blocked" (Success) instead of Red (Danger).
*   **"Threats" Count**:
    *   **Issue**: Similar to blocked events. A "Threat" that was blocked is a non-issue.
    *   **Suggestion**: Distinguish between "Active/Unblocked Threats" (Action Required) and "Blocked Threats" (FYI).
*   **Suspicious Ports**:
    *   **Issue**: Port 8080 or 8443 might be flagged, but are common for local development or smart home devices.
    *   **Suggestion**: Allow easy "Ignore" or "Trust" for devices, or rename to "Non-Standard Ports".

## 4. Missing Reassurance
The dashboard lacks positive feedback loops.

*   **"You are Safe" Indicator**:
    *   There is no clear "Green Light" that says "Everything is okay right now." The "Healthy" status often refers to the *application's* health (CPU/RAM), not the *network's* security status.
    *   **Fix**: Add a prominent "Network Status: Secure" banner when no critical alerts are active.
*   **Contextual Help**:
    *   Terms like "ASN", "NetFlow", and "SNMP" appear without tooltips.
    *   **Fix**: Add simple tooltips (e.g., "ASN: The Internet Service Provider (ISP) owning this IP").

## 5. Recommendation Summary
For a "Home Mode":
1.  **Rename "Anomalies" to "Traffic Insights".**
2.  **Change "Blocked" metrics from Red/Warn to Green/Success colors.**
3.  **Rewrite "Data Exfil" and "Lateral Movement" alerts to plain English ("Large Upload", "Local Transfer").**
4.  **Add a "Good Job" empty state when no threats are found.**
