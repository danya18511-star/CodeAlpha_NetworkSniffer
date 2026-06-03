Network Packet Analyzer

A Python tool that captures and analyzes live network traffic directly from your network interface. It decodes each packet layer by layer — Ethernet, IP, TCP/UDP/ICMP — and prints a human-readable summary to the terminal.


Requirements:

- Python 3.10 or higher (no third-party libraries needed)
- Windows: must run as Administrator
- Linux / macOS: must run with `sudo`

---

How to Run:

Windows (PyCharm)
1. Close PyCharm
2. Right-click the PyCharm icon → Run as administrator
3. Open `Network_Sniffer.py` and click Run


How to Read the Output:

Startup Banner
When the program starts, it prints a summary of the current settings:


============================================================
  NETWORK PACKET ANALYZER
============================================================
  Interface : all
  Filter    : ALL
  Count     : 50
  Verbose   : no
------------------------------------------------------------
  Press Ctrl+C to stop


Packet Lines

Each captured packet prints on one or two lines:

[    1] 14:23:01.442  TCP    192.168.1.5  ->  93.184.216.34  TTL:64  84B
  Ports: 52341:80  HTTP  [SYN]


| Field | Example | Meaning |
|---|---|---|
| Packet number | `[    1]` | How many packets have been captured so far |
| Timestamp | `14:23:01.442` | Time the packet was captured (hours:minutes:seconds.milliseconds) |
| Protocol | `TCP` | The transport protocol (TCP, UDP, ICMP, or PROTO-X for unknown) |
| Source IP | `192.168.1.5` | The IP address the packet was sent from |
| `->` | | Indicates direction of travel |
| Destination IP | `93.184.216.34` | The IP address the packet is going to |
| TTL | `TTL:64` | Time To Live — how many network hops the packet can travel before being dropped. Typically 64 (Linux), 128 (Windows), or 255 (routers) |
| Size | `84B` | Total size of the IP packet in bytes |


TCP / UDP Second Line

For TCP and UDP packets, a second line shows port and service information:

  Ports: 52341:80  HTTP  [SYN ACK]


| Field | Example | Meaning |
|---|---|---|
| Source port | `52341` | Port on the sending machine (high numbers are usually random/ephemeral) |
| Destination port | `80` | Port on the receiving machine |
| Service name | `HTTP` | The well-known service on that port, if recognized |
| TCP flags | `[SYN]` | Active TCP control flags (see below) |

TCP Flags explained

| Flag | Meaning |
|---|---|
| `SYN` | Starting a new connection (first step of the handshake) |
| `SYN ACK` | Server accepting the connection (second step) |
| `ACK` | Acknowledging received data |
| `PSH` | Pushing data immediately without buffering |
| `FIN` | Closing the connection gracefully |
| `RST` | Resetting / forcefully terminating the connection |

A typical connection looks like: `SYN` → `SYN ACK` → `ACK` → data with `PSH ACK` → `FIN ACK`

ICMP Line

[    3] 14:23:05.112  ICMP   172.16.0.1  ->  1.1.1.1  TTL:128  64B
  ICMP: Echo Request  Code:0


| Field | Example | Meaning |
| Type name | `Echo Request` | What kind of ICMP message it is |
| Code | `Code:0` | Sub-type of the ICMP message |

Common ICMP types:

| Type | Meaning |
| Echo Request | A ping being sent |
| Echo Reply | A ping response |
| Destination Unreachable | The target couldn't be reached |
| Time Exceeded | TTL hit zero — used by traceroute |

DNS Line (shown when --verbose or UDP port 53)

  Ports: 54321:53  DNS
  DNS: Query  TXID:0x1a2b  Qs:1

| Field | Meaning |
| `Query` / `Response` | Whether this packet is asking or answering |
| `TXID` | Transaction ID — matches a query to its response |
| `Qs` | Number of questions in the DNS message |


Verbose Payload (--verbose flag)

When `verbose` is enabled, the raw payload content is shown beneath each packet:

  | GET / HTTP/1.1..Host: example.com..User-Agent: curl/7.88...


- Printable text is shown as-is
- Non-printable bytes are replaced with `.`
- Only the first 64 bytes are shown

Capture Summary

When you press `Ctrl+C` or the packet count is reached, a summary is printed:

============================================================
  CAPTURE SUMMARY
============================================================
  Total Packets          47
  Total Bytes            38.2 KB
  Duration               12.4s
  Capture Rate           3.8 pkt/s

  Protocol Breakdown:
    TCP      ####################     31 ( 65.9%)
    UDP      ########                 12 ( 25.5%)
    ICMP     ###                       4 (  8.5%)

  Top Source IPs:
    192.168.1.5                         18 packets
    10.0.0.1                            11 packets
============================================================

| Field | Meaning |
| Total Packets | How many packets were captured |
| Total Bytes | Combined size of all captured packets |
| Duration | How long the capture ran |
| Capture Rate | Average packets per second |
| Protocol Breakdown | Count and percentage per protocol, with a bar chart |
| Top Source IPs | The 5 most active source IP addresses |

JSON Output (--output flag)

When `--output captures.json` is used, each packet is saved as a JSON object:

json
{
  "num": 1,
  "timestamp": "2026-06-03T14:23:01.442",
  "protocol": "TCP",
  "src_ip": "192.168.1.5",
  "dst_ip": "93.184.216.34",
  "ttl": 64,
  "length": 84,
  "src_port": 52341,
  "dst_port": 80,
  "flags": ["SYN"],
  "service": "HTTP",
  "payload_preview": "GET / HTTP/1.1..Host: example.com"
}

This file can be opened in any text editor or loaded into Python for further analysis.

Common Issues

| Problem | Fix |
| `[ERROR] Administrator privileges required` | Right-click PyCharm or cmd → Run as administrator |
| `[ERROR] Socket error: ...` | Make sure no other packet capture tool (e.g. Wireshark) is using the interface |
| No packets appearing | Try disabling your firewall temporarily, or browse a website to generate traffic |
| `PROTO-X` shown instead of protocol name | The protocol number X is not in the built-in map (e.g. GRE tunnels, OSPF) |
