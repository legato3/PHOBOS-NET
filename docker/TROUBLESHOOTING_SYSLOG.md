# Troubleshooting Syslog Not Receiving Data

If the firewall is configured correctly but logs aren't arriving, check these items:

## 1. Verify Port Mapping

```bash
# Check if port 514 is properly mapped
docker ps | grep netflow-dashboard

# Should show: 0.0.0.0:514->514/udp
```

## 2. Check Your Mac's IP Address

```bash
# Find your Mac's IP address on the local network
ifconfig | grep "inet " | grep -v 127.0.0.1

# Common addresses:
# - 192.168.x.x (local network)
# - Use this IP in your OPNsense firewall configuration
```

## 3. Verify Firewall Configuration

In OPNsense, the syslog target should be:
- **Hostname**: Your Mac's IP (e.g., `192.168.0.148`)
- **Port**: `514`
- **Transport**: `UDP`
- **Applications**: `filter` (for firewall logs)

## 4. Test from Firewall

From your OPNsense firewall (via SSH or console):

```bash
# Test sending syslog to your Mac
logger -n 192.168.0.148 -P 514 "Test message from firewall"

# Or using netcat
echo "Test syslog message" | nc -u -w1 192.168.0.148 514
```

## 5. Test from Mac to Container

Test if the port mapping works from your Mac:

```bash
# Send test message to localhost (should reach container)
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = b'<134>1 2026-01-13T18:00:00+00:00 OPNsense filterlog 12345 - - 5,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,185.220.101.45,192.168.0.1,443,54321,0,S,1234567890,,65535,,'
s.sendto(msg, ('localhost', 514))
print('Sent test message')
s.close()
"

# Check if it was received
sleep 2
curl -s http://localhost:8080/api/server/health | python3 -m json.tool | grep -A 6 syslog
```

## 6. Check macOS Firewall

macOS might be blocking UDP port 514:

```bash
# Check firewall status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# If enabled, you may need to allow Docker or add an exception
# System Preferences → Security & Privacy → Firewall
```

## 7. Check Docker Network

```bash
# Check Docker network configuration
docker network inspect docker_default

# Verify container is on the network
docker inspect netflow-dashboard-test | grep -A 10 NetworkSettings
```

## 8. Monitor Incoming Traffic

If you have tcpdump or Wireshark available:

```bash
# Monitor UDP port 514 on your Mac
sudo tcpdump -i any -n udp port 514

# You should see packets if the firewall is sending data
```

## 9. Check Container Logs

```bash
# Check for any errors
docker logs netflow-dashboard-test | grep -i "syslog\|error\|bind"

# Look for "Syslog receiver started on 0.0.0.0:514"
```

## 10. Common Issues

### Issue: macOS Firewall Blocking UDP
**Solution**: Add Docker to firewall exceptions or temporarily disable macOS firewall for testing

### Issue: Docker Desktop Network Mode
**Solution**: Ensure Docker Desktop is using the correct network mode. Try restarting Docker Desktop.

### Issue: Port Already in Use
**Solution**: Check if something else is using port 514:
```bash
sudo lsof -i :514
```

### Issue: Firewall Sending to Wrong IP
**Solution**: Verify the firewall is configured with your Mac's current IP address (not localhost or 127.0.0.1)

### Issue: Network Routing
**Solution**: Ensure your firewall can reach your Mac's IP address. Test with ping:
```bash
# From firewall, ping your Mac
ping 192.168.0.148
```

## Still Not Working?

1. Restart the Docker container:
   ```bash
   docker-compose -f docker/docker-compose.yml restart
   ```

2. Check if the syslog receiver thread is actually running:
   ```bash
   docker exec netflow-dashboard-test python3 -c "import netflow_dashboard; print('Thread started:', netflow_dashboard._syslog_thread_started)"
   ```

3. Verify the container can receive UDP on port 514:
   ```bash
   docker exec netflow-dashboard-test python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 514)); print('Port 514 bind successful')"
   ```
