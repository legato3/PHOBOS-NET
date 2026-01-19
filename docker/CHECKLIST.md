PHOBOS-NET Release Checklist

This checklist defines the mandatory steps to follow before publishing a new PHOBOS-NET release (GitHub + Docker Hub). It is designed to prevent silent regressions, broken images, and misleading releases.

⸻

1. Code & Logic Freeze
	•	No pending refactors or experimental changes
	•	All recent changes committed (git status clean)
	•	AGENTS.md is up to date and locked
	•	SKILL.md unchanged or intentionally updated

Rule: Never release during active refactoring

⸻

2. Truthfulness & Semantics Validation
	•	Alerts are strictly actionable (no noisy promotion)
	•	Anomalies are not counted as alerts
	•	Health score reflects system operability only
	•	Indicators (traffic signals) do not affect health
	•	null vs 0 is preserved end-to-end (API → UI)

⸻

3. Runtime Validation (Local)

Run locally using Docker:

docker compose up --build

Verify:
	•	Web UI loads without console errors
	•	NetFlow ingestion active
	•	Syslog (filterlog) ingestion active
	•	Firewall decisions API returns data
	•	Timeline stream updates correctly
	•	No widgets stuck in loading state

⸻

4. Docker Image Audit

Dockerfile
	•	Uses non-root user (UID 1000)
	•	Correct base image (python:3.12-slim or intended version)
	•	OCI labels present (title, description, source)
	•	No hardcoded host paths

Volumes
	•	Dynamic data stored only in /app/data
	•	Image starts clean with empty volume

⸻

5. Mandatory Rebuild

If any of the following changed, a rebuild is required:
	•	Dockerfile
	•	Base image (FROM)
	•	Python version
	•	Requirements / dependencies

Rebuild command:

docker build --no-cache -t legato3/phobos-net:X.Y.Z -f docker/Dockerfile .


⸻

6. Pre-Push Verification
	•	Image runs locally
	•	Correct Python version:

docker run --rm legato3/phobos-net:X.Y.Z python --version

	•	Non-root process verified:

docker run --rm legato3/phobos-net:X.Y.Z ps aux


⸻

7. Docker Hub Publication

docker push legato3/phobos-net:X.Y.Z
docker tag legato3/phobos-net:X.Y.Z legato3/phobos-net:latest
docker push legato3/phobos-net:latest

Rules:
	•	❌ Never overwrite an existing version tag
	•	✅ Always increment version

⸻

8. Documentation Sync
	•	GitHub README updated (architecture + usage)
	•	Docker Hub README aligned (shorter, ops-focused)
	•	docs/DOCKER.md up to date
	•	Screenshots reflect current UI

⸻

9. Final Sanity Check

Ask yourself:

“If someone deploys this image fresh, will it be truthful, calm, and usable without guessing?”

If the answer is not a clear yes, do not release.

⸻

10. Post-Release
	•	Tag GitHub release
	•	Monitor first deployment logs
	•	Do not hotfix directly on latest

⸻

Release philosophy:

Slow, explicit, boring releases beat fast broken ones.