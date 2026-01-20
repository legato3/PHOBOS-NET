# 🔒 PHOBOS-NET — Agent Development Guide

This document defines the **development workflow, build commands, and coding standards** for PHOBOS-NET, along with the **non-negotiable semantic and architectural rules**.

All AI agents **MUST follow this document strictly**. Violating these rules is considered a **breaking change**.

---

## 1. Development Commands

### Build & Deployment
```bash
# Build Docker image
docker build -f docker/Dockerfile .. -t phobos-net:latest

# Run with docker-compose (from docker/ directory)
docker-compose up -d

# Development server (Python 3.12)
python app/main.py

# Production server (Gunicorn)
gunicorn -c gunicorn_config.py app:app
```

### Testing
```bash
# ⚠️ NO FORMAL TEST SUITE EXISTS
# This is a known gap - tests should be added using pytest

# Manual testing approaches:
# - Check API endpoints: curl http://localhost:8080/health
# - Verify NetFlow ingestion: check /api/netflow/flows
# - Test syslog: send test events to ports 5514/5515
# - Monitor system health: /api/system/health
```

### Code Quality
```bash
# Python linting (if added)
# flake8 app/ --max-line-length=100
# black app/ --line-length=100

# JavaScript linting (if added)  
# eslint frontend/src/js/
```

---

## 2. Tech Stack & Dependencies

### Backend (Python 3.12)
- **Framework**: Flask
- **WSGI Server**: Gunicorn 21.2.0+
- **Key Libraries**: requests, maxminddb, dnspython, flask-compress
- **Database**: SQLite (thread-safe operations)
- **System Tools**: nfdump, python3-pysnmp4

### Frontend
- **Core**: Vanilla JavaScript (ES6+)
- **Reactivity**: Alpine.js
- **Charts**: Chart.js
- **Maps**: Leaflet.js
- **Build**: No bundler - direct file serving

### Deployment
- **Container**: Docker (python:3.12-slim base)
- **Ports**: 8080 (web), 2055 (NetFlow), 5514/5515 (syslog)
- **User**: Non-root (phobos:1000)

---

## 3. Code Style Guidelines

### Python Conventions
```python
# Imports: standard library → third-party → local
import os
import sys
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

import flask
import requests

from app.core.app_state import _shutdown_event
from app.services.shared.timeline import add_timeline_event

# Naming
snake_case_function()        # Functions and variables
PascalCaseClass              # Classes  
UPPER_SNAKE_CASE_CONSTANT    # Constants

# Docstrings: Google/NumPy style
def process_netflow_data(data: Dict[str, Any]) -> Optional[List[str]]:
    """Process NetFlow data and return flow summaries.
    
    Args:
        data: Raw NetFlow data dictionary
        
    Returns:
        List of processed flow summaries, or None if processing fails
    """
    pass

# Error Handling: Comprehensive with graceful degradation
try:
    result = risky_operation()
except SpecificError as e:
    logger.warning(f"Expected error in operation: {e}")
    return fallback_value()
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return None
```

### JavaScript Conventions
```javascript
// Imports: ES6 modules with version cache busting
import { Store } from './store/index.js?v=3.0.13';
import * as Utils from './modules/utils.js?v=3.0.3';

// Naming
camelCaseFunction()         // Functions
PascalCaseClass             // Classes  
UPPER_SNAKE_CASE_CONSTANT  // Constants

// Async/Await for API calls
async function fetchMetrics() {
    try {
        const response = await API.fetchWithLatency('/api/metrics');
        return await response.json();
    } catch (error) {
        console.error('Failed to fetch metrics:', error);
        return null;
    }
}

// JSDoc comments
/**
 * Process NetFlow data and return formatted results
 * @param {Object} data - Raw NetFlow data
 * @returns {Array|null} Processed flow summaries
 */
function processNetFlow(data) {
    // Implementation
}
```

### CSS Architecture
```css
/* Design tokens in tokens.css */
:root {
    --color-primary: #00ffff;
    --color-bg-dark: #0a0a0a;
    --font-mono: 'JetBrains Mono', monospace;
}

/* Component-based organization */
.widget-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: var(--spacing-md);
}

/* Mobile-first responsive */
@media (min-width: 768px) {
    .widget-container {
        grid-template-columns: repeat(2, 1fr);
    }
}
```

---

## 4. Core Semantic Separation (LOCKED)

PHOBOS-NET operates on **four strictly separated semantic layers**. These layers **MUST NEVER be merged, inferred, auto-derived, or implicitly coupled**.

### 4.1 Events (Timeline)
Events are **raw, factual observations** from NetFlow, filterlog, firewall logs, syslog, SNMP, and system events.

**Rules:**
- High-volume and noisy by nature
- Chronological and immutable  
- Informational only
- **MUST NEVER escalate automatically**

**Events answer:** "What happened?"

### 4.2 Signals / Indicators
Signals are **derived observations** like anomalies or deviations (SYN spikes, TCP reset bursts, baseline deviations).

**Rules:**
- Informational only
- Provide context, not urgency
- **MUST NEVER create alerts**
- **MUST NEVER affect system health directly**

**Signals answer:** "This is notable."

### 4.3 Alerts (STRICT)
Alerts are **rare, actionable, stateful objects** requiring human action.

**Every alert MUST include:**
- `first_seen`, `last_seen`, `active` (boolean), `resolved_at` (nullable)

**Rules:**
- Multiple events update **ONE alert**
- **MUST auto-resolve** when conditions clear
- **MUST NEVER be created from:** events, signals, anomalies, raw counters, traffic volume

**Alerts answer:** "Something requires action."

### 4.4 System Health (LOCKED)
**System Health reflects observability integrity — NOT threat level.**

**Health MAY depend on:** NetFlow engine availability, syslog ingestion, SNMP reachability, database connectivity, parser failure rates

**Health MUST NOT depend on:** Alert count, signal count, traffic volume, attack activity, timeline size

**Allowed states ONLY:** `Healthy`, `Degraded`, `Unavailable`

**Health answers:** "Can I trust what I'm seeing?"

---

## 5. Timeline Authority Rule (ABSOLUTE)

The Event Timeline is **non-authoritative**.

**Rules:**
- Timeline events **MUST NEVER:** create alerts, increment alert counters, affect system health, imply urgency
- Timeline exists for: context, explanation, investigation
- Absence of timeline events is **valid and calm**

---

## 6. UI Truthfulness Contract

The UI **MUST:**
- Prefer "—" over guessing
- Distinguish clearly between: unavailable vs zero, noisy vs dangerous
- Avoid alarmist language unless action is required

**Forbidden UI patterns:**
- "Unhealthy" due to traffic volume
- Large red numbers without action
- Alert inflation visuals
- Severity implied by color alone

---

## 7. Change Discipline (ENFORCED)

Before implementing any change, AI agents **MUST ask:**

> "Which layer am I modifying: Events, Signals, Alerts, or Health?"

If unclear → **STOP and ask for clarification**.

After completing a requested phase:
- STOP immediately
- Summarize exactly what changed
- Do NOT continue refactoring or adding features

---

## 8. Security Best Practices

- **Never log secrets** or API keys
- **Non-root container** execution
- **Thread-safe operations** with proper locking
- **Input validation** for all external data
- **Rate limiting** for API endpoints
- **CORS headers** properly configured

---

## 9. File Organization Patterns

```
app/
├── api/routes/          # Flask Blueprint API endpoints
├── services/           # Business logic modules
├── core/              # Application core functionality
└── db/                # Database operations

frontend/src/js/
├── modules/           # Feature-specific modules
├── store/            # State management
└── app.js            # Application entry point
```

---

## 10. Guiding Principle (FINAL)

> **Observability systems must be calm, honest, and boring when things are fine.**  
> Noise is data. Alerts are decisions.

If a change violates this principle, it must not be implemented.

---

## 11. Architecture Version

**PHOBOS-NET Architecture v1.0** - Any change to semantic layers requires explicit human approval.

**Development Guide v1.0** - Commands and coding conventions may be updated by contributors.