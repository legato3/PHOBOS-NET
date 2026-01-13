# Docker Desktop UDP Port Forwarding Issue

Docker Desktop on macOS has known issues with UDP port forwarding, especially for port 514 (syslog).

## The Problem

Docker Desktop uses a Linux VM (using HyperKit on Intel Macs, or VirtioFS on Apple Silicon). UDP port forwarding through this VM can be unreliable, even when:
- Port mapping is correctly configured in docker-compose.yml
- macOS firewall allows Docker
- The container is listening correctly

## Solutions

### Option 1: Use host.docker.internal (Doesn't help for incoming traffic)

This only works for container → host communication, not host → container.

### Option 2: Use host networking mode (macOS doesn't support)

macOS Docker Desktop doesn't support `network_mode: host`.

### Option 3: Use a different port mapping strategy

Try mapping to a different external port:

```yaml
ports:
  - "1514:514/udp"  # Use 1514 externally, 514 internally
```

Then configure firewall to send to `192.168.0.148:1514`.

### Option 4: Test from within Docker network

If you have another container, test from within the Docker network:

```bash
# From another container on the same network
docker run --rm --network docker_default python:3.11-slim python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = b'<134>1 2026-01-13T18:00:00+00:00 OPNsense filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.45,192.168.0.1,443,54321,0,S,1234567890,,65535,,'
s.sendto(msg, ('netflow-dashboard-test', 514))
print('Sent')
"
```

### Option 5: Use socat to bridge UDP (Advanced)

Create a UDP proxy using socat on the host:

```bash
# Install socat on Mac
brew install socat

# Forward UDP 514 to Docker container
socat UDP4-RECVFROM:514,fork UDP4-SENDTO:127.0.0.1:514
```

### Option 6: Run directly on macOS (Development only)

For testing, you could run the application directly without Docker:

```bash
python3 netflow-dashboard.py
```

This would listen directly on macOS port 514 (requires sudo for port < 1024).

## Verification Steps

1. **Test localhost forwarding:**
   ```bash
   python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('127.0.0.1', 514))"
   ```
   Check if container receives it.

2. **Test from external IP:**
   ```bash
   python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('192.168.0.148', 514))"
   ```
   Check if container receives it.

3. **Monitor with tcpdump:**
   ```bash
   sudo tcpdump -i any -n udp port 514
   ```
   See if packets are reaching the Mac.

4. **Check Docker Desktop settings:**
   - Docker Desktop → Settings → Resources → Network
   - Ensure no proxy is interfering

## Recommended Approach for Production

For production use, deploy to a Linux server (LXC container, VM, or bare metal) where UDP port forwarding works correctly. Docker Desktop on macOS is primarily for development.

## Alternative: Use Docker on Linux

If you need Docker, consider:
- Running Docker on a Linux VM
- Using a remote Linux server
- Using the production LXC container (192.168.0.74)
