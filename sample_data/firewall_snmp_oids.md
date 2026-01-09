# OPNsense Firewall SNMP OIDs Reference

This document contains all useful SNMP OIDs available from the OPNsense firewall at 192.168.0.1.

**Firewall Details:**
- System: OPNsense 25.7
- OS: FreeBSD 14.3-RELEASE-p7
- SNMP Community: Phoboshomesnmp_3
- Total OIDs Available: 7583

## System Information

| OID | Name | Type | Description | Example Value |
|-----|------|------|-------------|---------------|
| `.1.3.6.1.2.1.1.1.0` | sysDescr | STRING | System description | FreeBSD CHRIS-OPN.phobos-cc.be 14.3-RELEASE-p7 |
| `.1.3.6.1.2.1.1.2.0` | sysObjectID | OID | System object ID | .1.3.6.1.4.1.8072.3.2.8 |
| `.1.3.6.1.2.1.1.3.0` | sysUpTime | TimeTicks | System uptime | (6478487) 17:59:44.87 |
| `.1.3.6.1.2.1.1.4.0` | sysContact | STRING | System contact | legato3@gmail.com |
| `.1.3.6.1.2.1.1.5.0` | sysName | STRING | System hostname | CHRIS-OPN.phobos-cc.be |
| `.1.3.6.1.2.1.1.6.0` | sysLocation | STRING | System location | Phobos |
| `.1.3.6.1.2.1.1.7.0` | sysServices | INTEGER | Services available | 76 |

## CPU & Load Average (UCD-SNMP-MIB)

| OID | Name | Type | Description | Example Value |
|-----|------|------|-------------|---------------|
| `.1.3.6.1.4.1.2021.10.1.3.1` | laLoad.1 | STRING | 1-minute load average | 0.51 |
| `.1.3.6.1.4.1.2021.10.1.3.2` | laLoad.2 | STRING | 5-minute load average | 0.60 |
| `.1.3.6.1.4.1.2021.10.1.3.3` | laLoad.3 | STRING | 15-minute load average | 0.65 |
| `.1.3.6.1.4.1.2021.11.9.0` | ssCpuUser | INTEGER | CPU user time | - |
| `.1.3.6.1.4.1.2021.11.10.0` | ssCpuSystem | INTEGER | CPU system time | - |
| `.1.3.6.1.4.1.2021.11.11.0` | ssCpuIdle | INTEGER | CPU idle time | - |

## Memory (UCD-SNMP-MIB)

| OID | Name | Type | Description | Example Value |
|-----|------|------|-------------|---------------|
| `.1.3.6.1.4.1.2021.4.3.0` | memTotalSwap | INTEGER | Total swap in KB | - |
| `.1.3.6.1.4.1.2021.4.4.0` | memAvailSwap | INTEGER | Available swap in KB | - |
| `.1.3.6.1.4.1.2021.4.5.0` | memTotalReal | INTEGER | Total RAM in KB | 12182676 |
| `.1.3.6.1.4.1.2021.4.6.0` | memAvailReal | INTEGER | Available RAM in KB | 735092 |
| `.1.3.6.1.4.1.2021.4.11.0` | memBuffer | INTEGER | Buffer memory in KB | 0 |
| `.1.3.6.1.4.1.2021.4.13.0` | memCached | INTEGER | Cached memory in KB | 6475320 |

## Network Interfaces

### Interface Table (IF-MIB)

| OID Base | Name | Type | Description |
|----------|------|------|-------------|
| `.1.3.6.1.2.1.2.2.1.1` | ifIndex | INTEGER | Interface index |
| `.1.3.6.1.2.1.2.2.1.2` | ifDescr | STRING | Interface description (igc0, igc1, lo0, enc0, pflog0, pfsync0) |
| `.1.3.6.1.2.1.2.2.1.3` | ifType | INTEGER | Interface type |
| `.1.3.6.1.2.1.2.2.1.4` | ifMtu | INTEGER | Interface MTU |
| `.1.3.6.1.2.1.2.2.1.5` | ifSpeed | Gauge32 | Interface speed in bits/sec |
| `.1.3.6.1.2.1.2.2.1.6` | ifPhysAddress | STRING | MAC address |
| `.1.3.6.1.2.1.2.2.1.7` | ifAdminStatus | INTEGER | Admin status (1=up, 2=down) |
| `.1.3.6.1.2.1.2.2.1.8` | ifOperStatus | INTEGER | Operational status (1=up, 2=down) |

### Interface Statistics

| OID Base | Name | Type | Description |
|----------|------|------|-------------|
| `.1.3.6.1.2.1.2.2.1.10` | ifInOctets | Counter32 | Bytes received |
| `.1.3.6.1.2.1.2.2.1.11` | ifInUcastPkts | Counter32 | Unicast packets received |
| `.1.3.6.1.2.1.2.2.1.12` | ifInNUcastPkts | Counter32 | Non-unicast packets received |
| `.1.3.6.1.2.1.2.2.1.13` | ifInDiscards | Counter32 | Inbound packets discarded |
| `.1.3.6.1.2.1.2.2.1.14` | ifInErrors | Counter32 | Inbound packets with errors |
| `.1.3.6.1.2.1.2.2.1.16` | ifOutOctets | Counter32 | Bytes transmitted |
| `.1.3.6.1.2.1.2.2.1.17` | ifOutUcastPkts | Counter32 | Unicast packets transmitted |
| `.1.3.6.1.2.1.2.2.1.18` | ifOutNUcastPkts | Counter32 | Non-unicast packets transmitted |
| `.1.3.6.1.2.1.2.2.1.19` | ifOutDiscards | Counter32 | Outbound packets discarded |
| `.1.3.6.1.2.1.2.2.1.20` | ifOutErrors | Counter32 | Outbound packets with errors |

### High-Capacity Counters (64-bit)

| OID Base | Name | Type | Description |
|----------|------|------|-------------|
| `.1.3.6.1.2.1.31.1.1.1.6` | ifHCInOctets | Counter64 | Bytes received (64-bit) |
| `.1.3.6.1.2.1.31.1.1.1.10` | ifHCOutOctets | Counter64 | Bytes transmitted (64-bit) |

## IP Statistics (IP-MIB)

| OID | Name | Type | Description |
|-----|------|------|-------------|
| `.1.3.6.1.2.1.4.3.0` | ipInReceives | Counter32 | Total IP packets received |
| `.1.3.6.1.2.1.4.4.0` | ipInHdrErrors | Counter32 | IP packets with header errors |
| `.1.3.6.1.2.1.4.5.0` | ipInAddrErrors | Counter32 | IP packets with address errors |
| `.1.3.6.1.2.1.4.6.0` | ipForwDatagrams | Counter32 | IP packets forwarded |
| `.1.3.6.1.2.1.4.8.0` | ipInDiscards | Counter32 | IP packets discarded |
| `.1.3.6.1.2.1.4.9.0` | ipInDelivers | Counter32 | IP packets delivered |
| `.1.3.6.1.2.1.4.10.0` | ipOutRequests | Counter32 | IP packets requested to transmit |

## TCP Statistics (TCP-MIB)

| OID | Name | Type | Description |
|-----|------|------|-------------|
| `.1.3.6.1.2.1.6.5.0` | tcpActiveOpens | Counter32 | TCP active opens |
| `.1.3.6.1.2.1.6.6.0` | tcpPassiveOpens | Counter32 | TCP passive opens |
| `.1.3.6.1.2.1.6.7.0` | tcpAttemptFails | Counter32 | TCP connection attempt failures |
| `.1.3.6.1.2.1.6.8.0` | tcpEstabResets | Counter32 | TCP established resets |
| `.1.3.6.1.2.1.6.9.0` | tcpCurrEstab | Gauge32 | Current TCP connections |
| `.1.3.6.1.2.1.6.10.0` | tcpInSegs | Counter32 | TCP segments received |
| `.1.3.6.1.2.1.6.11.0` | tcpOutSegs | Counter32 | TCP segments sent |
| `.1.3.6.1.2.1.6.12.0` | tcpRetransSegs | Counter32 | TCP segments retransmitted |

## UDP Statistics (UDP-MIB)

| OID | Name | Type | Description |
|-----|------|------|-------------|
| `.1.3.6.1.2.1.7.1.0` | udpInDatagrams | Counter32 | UDP datagrams received |
| `.1.3.6.1.2.1.7.2.0` | udpNoPorts | Counter32 | UDP datagrams to unknown port |
| `.1.3.6.1.2.1.7.3.0` | udpInErrors | Counter32 | UDP datagrams with errors |
| `.1.3.6.1.2.1.7.4.0` | udpOutDatagrams | Counter32 | UDP datagrams sent |

## ICMP Statistics (IP-MIB)

| OID | Name | Type | Description |
|-----|------|------|-------------|
| `.1.3.6.1.2.1.5.1.0` | icmpInMsgs | Counter32 | ICMP messages received |
| `.1.3.6.1.2.1.5.2.0` | icmpInErrors | Counter32 | ICMP messages with errors |
| `.1.3.6.1.2.1.5.8.0` | icmpInEchos | Counter32 | ICMP echo requests received |
| `.1.3.6.1.2.1.5.9.0` | icmpInEchoReps | Counter32 | ICMP echo replies received |
| `.1.3.6.1.2.1.5.14.0` | icmpOutMsgs | Counter32 | ICMP messages sent |
| `.1.3.6.1.2.1.5.21.0` | icmpOutEchos | Counter32 | ICMP echo requests sent |
| `.1.3.6.1.2.1.5.22.0` | icmpOutEchoReps | Counter32 | ICMP echo replies sent |

## Storage/Disk (HOST-RESOURCES-MIB)

| OID Base | Name | Type | Description |
|----------|------|------|-------------|
| `.1.3.6.1.2.1.25.2.3.1.2` | hrStorageDescr | STRING | Storage description |
| `.1.3.6.1.2.1.25.2.3.1.3` | hrStorageAllocationUnits | INTEGER | Allocation unit size |
| `.1.3.6.1.2.1.25.2.3.1.4` | hrStorageSize | INTEGER | Storage size in units |
| `.1.3.6.1.2.1.25.2.3.1.5` | hrStorageUsed | INTEGER | Storage used in units |

## Processes (HOST-RESOURCES-MIB)

| OID | Name | Type | Description |
|-----|------|------|-------------|
| `.1.3.6.1.2.1.25.1.6.0` | hrSystemProcesses | Gauge32 | Number of running processes |

## Example Queries

### Get System Info
```bash
snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.1.1.0
snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.1.5.0
```

### Get Load Averages
```bash
snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.4.1.2021.10.1.3
```

### Get Memory Stats
```bash
snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.4.1.2021.4
```

### Get Interface Names
```bash
snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.2.2.1.2
```

### Get Interface Traffic (bytes in/out)
```bash
snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.2.2.1.10  # In
snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.2.2.1.16  # Out
```

### Get TCP Connection Count
```bash
snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.6.9.0
```

### Get Process Count
```bash
snmpget -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.25.1.6.0
```

## Potential Dashboard Enhancements

### Current Connections Widget
- **OID**: `.1.3.6.1.2.1.6.9.0` (tcpCurrEstab)
- **Display**: Number of active TCP connections

### Network Traffic Widget
- **OIDs**: `.1.3.6.1.2.1.2.2.1.10.X` (ifInOctets) and `.1.3.6.1.2.1.2.2.1.16.X` (ifOutOctets)
- **Display**: Real-time bandwidth per interface (WAN/LAN)
- **Calculation**: Delta between polls to get bytes/sec

### Packet Statistics Widget
- **OIDs**: IP/TCP/UDP/ICMP counters
- **Display**: Protocol distribution and error rates

### Process Count Widget
- **OID**: `.1.3.6.1.2.1.25.1.6.0` (hrSystemProcesses)
- **Display**: Number of running processes

### Interface Status Widget
- **OIDs**: `.1.3.6.1.2.1.2.2.1.8.X` (ifOperStatus)
- **Display**: Up/Down status for each interface with colored indicators

### TCP Connection Stats Widget
- **OIDs**: `.1.3.6.1.2.1.6.5.0` (active opens), `.1.3.6.1.2.1.6.7.0` (failed attempts)
- **Display**: Connection success/failure rates

## Notes

- Interface-specific OIDs use index numbers (e.g., `.X` where X is the interface index)
- To find interface indexes: `snmpwalk -v2c -c Phoboshomesnmp_3 192.168.0.1 .1.3.6.1.2.1.2.2.1.2`
- Counter32 values wrap at 2^32, use Counter64 (HC) variants for high-speed interfaces
- Some OIDs may return "No Such Object" if the feature is not enabled/available
- Full SNMP walk contains 7583 OIDs - this document covers the most useful ones

## Full SNMP Walk

A complete SNMP walk output is available in `firewall_snmp_full_walk.txt` (7583 lines) for reference.
