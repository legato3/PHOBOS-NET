# Testing Syslog in Docker

The syslog receiver is running and listening on port 514, but it needs data to be sent to it.

## Quick Test

Send a test syslog message from your host machine:

```bash
# Using Python (most reliable)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = b'<134>1 2026-01-13T18:00:00+00:00 OPNsense filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.45,192.168.0.1,443,54321,0,S,1234567890,,65535,,'
s.sendto(msg, ('localhost', 514))
print('Test message sent')
s.close()
"

# Or using netcat (if available)
echo -n '<134>1 2026-01-13T18:00:00+00:00 OPNsense filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.45,192.168.0.1,443,54321,0,S,1234567890,,65535,,' | nc -u -w1 localhost 514

# Or using logger (if available)
logger -n localhost -P 514 "Test syslog message"
```

After sending, check the dashboard - you should see "Received: 1" and "Parsed: 1" (if the message format is correct).

## Configure Firewall to Send Syslog

### Option 1: OPNsense Firewall

1. Log into OPNsense web interface
2. Go to **System → Settings → Logging / Targets**
3. Click **+ Add**
4. Configure:
   - **Enabled**: ✅
   - **Transport**: UDP
   - **Applications**: filter (firewall logs)
   - **Hostname**: `<DOCKER_HOST_IP>` (e.g., `192.168.0.74` or your Mac's IP)
   - **Port**: `514`
   - **Facility**: Local0
   - **Level**: Informational
5. Click **Save** and **Apply**

### Option 2: Find Your Docker Host IP

```bash
# On macOS, find your IP address
ifconfig | grep "inet " | grep -v 127.0.0.1

# Or use this to find the Docker host IP
docker network inspect docker_default | grep Gateway
```

The firewall should send syslog to your Mac's IP address on port 514, and Docker will forward it to the container.

## Verify It's Working

1. Check the dashboard Syslog widget - should show:
   - **Received**: > 0
   - **Parsed**: > 0 (if messages are in correct format)
   - **ACTIVE**: Green badge

2. Check container logs:
   ```bash
   docker logs netflow-dashboard-test | grep -i syslog
   ```

3. Check API directly:
   ```bash
   curl -s http://localhost:8080/api/server/health | python3 -m json.tool | grep -A 6 syslog
   ```

## Troubleshooting

- **Received: 0**: No data is reaching the container. Check firewall configuration and network connectivity.
- **Received > 0 but Parsed: 0**: Messages are arriving but format is incorrect. Check syslog message format.
- **Errors > 0**: Parsing errors occurred. Check container logs for details.
