# 📦 PHOBOS-NET — Docker Hub Build & Push Guide

This document describes the **exact commands** required to build and push the PHOBOS-NET Docker image to Docker Hub.

It assumes:
- You are on your **development machine**
- Docker Desktop is installed
- You are logged into Docker Hub
- The repository root contains `docker/Dockerfile`

---

## 1. Prerequisites

Verify you are in the **project root**:

```bash
ls docker/Dockerfile app frontend docker-data scripts
```

If this command fails, do **not** continue.

---

## 2. Clean Build (Recommended)

Always do a clean build before publishing:

```bash
docker build --no-cache \
  -t legato3/phobos-net:1.0.0 \
  -f docker/Dockerfile \
  .
```

Explanation:
- `--no-cache` ensures a fully reproducible build
- `-f docker/Dockerfile` explicitly selects the Dockerfile
- `.` sets the build context to the project root

---

## 3. Tag the Image

Create the additional tags expected on Docker Hub:

```bash
docker tag legato3/phobos-net:1.0.0 legato3/phobos-net:1.0
docker tag legato3/phobos-net:1.0.0 legato3/phobos-net:latest
```

Verify tags:

```bash
docker images | grep phobos-net
```

Expected output:
```
legato3/phobos-net   1.0.0
legato3/phobos-net   1.0
legato3/phobos-net   latest
```

---

## 4. Push to Docker Hub

Login if needed:

```bash
docker login
```

Push all tags:

```bash
docker push legato3/phobos-net:1.0.0
docker push legato3/phobos-net:1.0
docker push legato3/phobos-net:latest
```

After this completes, the image is **publicly available**.

---

## 5. Post-Push Verification (Strongly Recommended)

Simulate a real user pull:

```bash
docker image rm legato3/phobos-net:1.0.0
docker pull legato3/phobos-net:1.0.0
```

Then start PHOBOS-NET using `docker-compose.yml` or `docker run` and verify:
- Container starts cleanly
- Healthcheck reports healthy
- UI loads
- No permission errors (non-root user)

---

## 6. Important Notes

- **Do not build on the production server**
- Always build and push from your development machine
- The server should only `docker pull` and run
- Never modify Dockerfile paths without updating this document

---

## 7. Versioning Policy (Current)

For now, PHOBOS-NET uses simple versioning:

- `1.0.0` — exact release
- `1.0` — latest compatible
- `latest` — newest stable

This can evolve later if needed.
