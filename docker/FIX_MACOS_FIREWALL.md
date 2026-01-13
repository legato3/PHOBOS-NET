# Fix macOS Firewall for Syslog

macOS Firewall is enabled and may be blocking UDP port 514. Here's how to fix it:

## Option 1: Allow Docker Through Firewall (Recommended)

1. Open **System Settings** (or System Preferences on older macOS)
2. Go to **Network** → **Firewall** (or **Security & Privacy** → **Firewall**)
3. Click **Options** or **Firewall Options**
4. Look for **Docker** in the list and ensure it's set to **Allow incoming connections**
5. If Docker is not in the list, click **+** and add Docker Desktop

## Option 2: Temporarily Disable Firewall (For Testing)

1. Open **System Settings** → **Network** → **Firewall**
2. Turn off the firewall temporarily to test if that's the issue
3. **Important**: Re-enable after testing!

## Option 3: Add Specific Port Exception (Advanced)

You can also allow port 514 specifically via command line (requires admin):

```bash
# Allow UDP port 514 (requires admin password)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/Docker.app
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /System/Library/CoreServices/Docker.app
```

## Verify Fix

After allowing Docker through the firewall, test again:

```bash
# From your firewall, send a test message
# Or from another machine on your network:
python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('192.168.0.148', 514))"

# Check if received
curl -s http://localhost:8080/api/server/health | python3 -m json.tool | grep -A 6 syslog
```

## Check Firewall Status

```bash
# Check if firewall is enabled
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Check application list
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```
