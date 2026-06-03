#!/usr/bin/env python3
"""
Network Traffic Packet Analyzer
================================
Captures and analyzes network packets using socket and optionally scapy.
Displays source/destination IPs, protocols, ports, and payloads.

Usage:
    sudo python3 packet_analyzer.py [OPTIONS]

Options:
    --interface   Network interface to capture on (default: auto-detect)
    --count       Number of packets to capture (default: 50, 0 = unlimited)
    --filter      Protocol filter: tcp, udp, icmp, all (default: all)
    --output      Save packets to a JSON file
    --verbose     Show detailed payload content
    --help        Show this help message

Examples:
    sudo python3 packet_analyzer.py
    sudo python3 packet_analyzer.py --count 100 --filter tcp
    sudo python3 packet_analyzer.py --output captures.json --verbose
"""

import socket
import struct
import binascii
import time
import json
import argparse
import sys
import os
import signal
import textwrap
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────
#  Protocol Mappings
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 143: "IMAP", 161: "SNMP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


# ─────────────────────────────────────────────
#  Packet Statistics Tracker
# ─────────────────────────────────────────────
class PacketStats:
    def __init__(self):
        self.total = 0
        self.by_protocol = defaultdict(int)
        self.by_src_ip = defaultdict(int)
        self.by_dst_ip = defaultdict(int)
        self.total_bytes = 0
        self.start_time = time.time()

    def update(self, packet_info):
        self.total += 1
        self.total_bytes += packet_info.get("length", 0)
        proto = packet_info.get("protocol", "OTHER")
        self.by_protocol[proto] += 1
        if src := packet_info.get("src_ip"):
            self.by_src_ip[src] += 1
        if dst := packet_info.get("dst_ip"):
            self.by_dst_ip[dst] += 1

    def elapsed(self):
        return time.time() - self.start_time

    def summary(self):
        elapsed = self.elapsed()
        rate = self.total / elapsed if elapsed > 0 else 0
        lines = [
            "",
            "=" * 60,
            "  CAPTURE SUMMARY",
            "=" * 60,
            f"  {'Total Packets':<22} {self.total}",
            f"  {'Total Bytes':<22} {self._fmt_bytes(self.total_bytes)}",
            f"  {'Duration':<22} {elapsed:.1f}s",
            f"  {'Capture Rate':<22} {rate:.1f} pkt/s",
            "",
            "  Protocol Breakdown:",
        ]
        for proto, count in sorted(self.by_protocol.items(), key=lambda x: -x[1]):
            bar = "#" * min(20, int(20 * count / max(self.total, 1)))
            pct = 100 * count / max(self.total, 1)
            lines.append(f"    {proto:<8} {bar:<20} {count:>5} ({pct:5.1f}%)")

        lines.append("")
        lines.append("  Top Source IPs:")
        for ip, count in sorted(self.by_src_ip.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {ip:<35} {count} packets")

        lines.append("=" * 60)
        return "\n".join(lines)

    @staticmethod
    def _fmt_bytes(n):
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"


# ─────────────────────────────────────────────
#  Ethernet Frame Parser
# ─────────────────────────────────────────────
def parse_ethernet_frame(data):
    """Parse an Ethernet II frame."""
    if len(data) < 14:
        return None
    dst_mac = binascii.hexlify(data[0:6]).decode()
    src_mac = binascii.hexlify(data[6:12]).decode()
    eth_type = struct.unpack("!H", data[12:14])[0]

    fmt_mac = lambda m: ":".join(m[i:i+2] for i in range(0, 12, 2))

    return {
        "dst_mac":  fmt_mac(dst_mac),
        "src_mac":  fmt_mac(src_mac),
        "eth_type": eth_type,
        "payload":  data[14:],
    }


# ─────────────────────────────────────────────
#  IP Header Parser
# ─────────────────────────────────────────────
def parse_ip_header(data):
    """Parse an IPv4 header."""
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    ver = (data[0] >> 4)
    tos = data[1]
    total_len = struct.unpack("!H", data[2:4])[0]
    ttl = data[8]
    proto = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    return {
        "version":   ver,
        "ihl":       ihl,
        "tos":       tos,
        "length":    total_len,
        "ttl":       ttl,
        "protocol":  PROTOCOL_MAP.get(proto, f"PROTO-{proto}"),
        "proto_num": proto,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "payload":   data[ihl:],
    }


# ─────────────────────────────────────────────
#  TCP Header Parser
# ─────────────────────────────────────────────
def parse_tcp_header(data):
    """Parse a TCP segment header."""
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", data[0:4])
    seq_num  = struct.unpack("!I", data[4:8])[0]
    ack_num  = struct.unpack("!I", data[8:12])[0]
    offset   = (data[12] >> 4) * 4
    flags    = data[13]

    flag_map = {
        "FIN": bool(flags & 0x01),
        "SYN": bool(flags & 0x02),
        "RST": bool(flags & 0x04),
        "PSH": bool(flags & 0x08),
        "ACK": bool(flags & 0x10),
        "URG": bool(flags & 0x20),
    }
    active_flags = [k for k, v in flag_map.items() if v]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq":      seq_num,
        "ack":      ack_num,
        "flags":    active_flags,
        "service":  PORT_SERVICES.get(dst_port) or PORT_SERVICES.get(src_port),
        "payload":  data[offset:],
    }


# ─────────────────────────────────────────────
#  UDP Header Parser
# ─────────────────────────────────────────────
def parse_udp_header(data):
    """Parse a UDP datagram header."""
    if len(data) < 8:
        return None
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[0:8])
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length":   length,
        "checksum": hex(checksum),
        "service":  PORT_SERVICES.get(dst_port) or PORT_SERVICES.get(src_port),
        "payload":  data[8:],
    }


# ─────────────────────────────────────────────
#  ICMP Header Parser
# ─────────────────────────────────────────────
def parse_icmp_header(data):
    """Parse an ICMP packet."""
    if len(data) < 4:
        return None
    icmp_type, code = data[0], data[1]
    checksum = struct.unpack("!H", data[2:4])[0]

    type_names = {
        0: "Echo Reply", 3: "Destination Unreachable",
        5: "Redirect",   8: "Echo Request",
        11: "Time Exceeded", 12: "Parameter Problem",
    }
    return {
        "type":      icmp_type,
        "type_name": type_names.get(icmp_type, f"Type-{icmp_type}"),
        "code":      code,
        "checksum":  hex(checksum),
        "payload":   data[4:],
    }


# ─────────────────────────────────────────────
#  DNS Quick Parser (port 53)
# ─────────────────────────────────────────────
def parse_dns_quick(data):
    """Minimal DNS parsing: extract transaction ID and flags."""
    if len(data) < 12:
        return None
    txid   = struct.unpack("!H", data[0:2])[0]
    flags  = struct.unpack("!H", data[2:4])[0]
    qr     = (flags >> 15) & 1
    qcount = struct.unpack("!H", data[4:6])[0]
    return {
        "txid":      hex(txid),
        "type":      "Response" if qr else "Query",
        "questions": qcount,
    }


# ─────────────────────────────────────────────
#  Safe Payload Decoder
# ─────────────────────────────────────────────
def decode_payload(raw, max_bytes=64):
    """Return a safe printable snippet of a payload."""
    if not raw:
        return ""
    chunk = raw[:max_bytes]
    try:
        text = chunk.decode("utf-8", errors="replace")
        text = "".join(c if c.isprintable() or c in "\t\n" else "." for c in text)
        return text.strip()
    except Exception:
        return binascii.hexlify(chunk).decode()


# ─────────────────────────────────────────────
#  Packet Display Renderer
# ─────────────────────────────────────────────
def display_packet(pkt_num, ip_info, transport, verbose=False):
    """Render a single packet's info to the terminal."""
    proto = ip_info["protocol"]
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"\n[{pkt_num:>5}] {ts}  {proto:<5}  "
          f"{ip_info['src_ip']}  ->  {ip_info['dst_ip']}  "
          f"TTL:{ip_info['ttl']}  {ip_info['length']}B")

    if transport:
        if proto in ("TCP", "UDP"):
            sp  = transport["src_port"]
            dp  = transport["dst_port"]
            svc = f"  {transport['service']}" if transport.get("service") else ""
            port_line = f"  Ports: {sp}:{dp}{svc}"
            if proto == "TCP" and transport.get("flags"):
                port_line += f"  [{' '.join(transport['flags'])}]"
            print(port_line)

            if transport.get("service") == "DNS" and transport.get("payload"):
                dns = parse_dns_quick(transport["payload"])
                if dns:
                    print(f"  DNS: {dns['type']}  TXID:{dns['txid']}  Qs:{dns['questions']}")

        elif proto == "ICMP":
            print(f"  ICMP: {transport['type_name']}  Code:{transport['code']}")

    if verbose and transport and transport.get("payload"):
        snippet = decode_payload(transport["payload"])
        if snippet:
            wrapped = textwrap.fill(snippet, width=72,
                                    initial_indent="  | ",
                                    subsequent_indent="  | ")
            print(wrapped)


# ─────────────────────────────────────────────
#  Raw Socket Packet Capture
# ─────────────────────────────────────────────
def capture_packets(interface=None, count=50, proto_filter="all",
                    output_file=None, verbose=False):
    """
    Capture raw network packets using a raw socket.
    Requires root / administrator privileges.
    """
    stats    = PacketStats()
    packets  = []
    captured = 0

    # Open raw socket
    try:
        if sys.platform == "win32":
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0003))
            if interface:
                sock.bind((interface, 0))
    except PermissionError:
        print("\n  [ERROR] Permission denied.")
        print("  Run with: sudo python3 packet_analyzer.py\n")
        sys.exit(1)
    except OSError as e:
        print(f"\n  [ERROR] Socket error: {e}\n")
        sys.exit(1)

    # Print banner
    print("=" * 60)
    print("  NETWORK PACKET ANALYZER")
    print("=" * 60)
    print(f"  Interface : {interface or 'all'}")
    print(f"  Filter    : {proto_filter.upper()}")
    print(f"  Count     : {count if count > 0 else 'unlimited'}")
    print(f"  Verbose   : {'yes' if verbose else 'no'}")
    print("-" * 60)
    print("  Press Ctrl+C to stop\n")

    # Signal handler for graceful exit
    def on_exit(sig, frame):
        print(stats.summary())
        if output_file and packets:
            _save_output(packets, output_file)
        try:
            if sys.platform == "win32":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_exit)

    # Capture loop
    while count == 0 or captured < count:
        try:
            raw_data, addr = sock.recvfrom(65535)
        except Exception:
            break

        if sys.platform != "win32":
            eth = parse_ethernet_frame(raw_data)
            if not eth or eth["eth_type"] != 0x0800:
                continue
            ip_data = eth["payload"]
        else:
            ip_data = raw_data

        ip = parse_ip_header(ip_data)
        if not ip:
            continue

        proto = ip["protocol"]

        pf = proto_filter.upper()
        if pf != "ALL" and proto != pf:
            continue

        transport = None
        if proto == "TCP":
            transport = parse_tcp_header(ip["payload"])
        elif proto == "UDP":
            transport = parse_udp_header(ip["payload"])
        elif proto == "ICMP":
            transport = parse_icmp_header(ip["payload"])

        captured += 1
        stats.update({
            "protocol": proto,
            "src_ip":   ip["src_ip"],
            "dst_ip":   ip["dst_ip"],
            "length":   ip["length"],
        })

        display_packet(captured, ip, transport, verbose)

        if output_file:
            record = {
                "num":       captured,
                "timestamp": datetime.now().isoformat(),
                "protocol":  proto,
                "src_ip":    ip["src_ip"],
                "dst_ip":    ip["dst_ip"],
                "ttl":       ip["ttl"],
                "length":    ip["length"],
            }
            if transport:
                for k in ("src_port", "dst_port", "flags", "service",
                          "type_name", "code"):
                    if k in transport:
                        record[k] = transport[k]
                if transport.get("payload"):
                    record["payload_preview"] = decode_payload(transport["payload"])
            packets.append(record)

    # Done
    print(stats.summary())
    if output_file and packets:
        _save_output(packets, output_file)
    try:
        if sys.platform == "win32":
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except Exception:
        pass
    sock.close()


def _save_output(packets, path):
    with open(path, "w") as f:
        json.dump(packets, f, indent=2)
    print(f"\n  Saved {len(packets)} packets -> {path}\n")


# ─────────────────────────────────────────────
#  CLI Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Packet Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--interface", "-i", default=None,
                        help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("--count", "-c", type=int, default=50,
                        help="Packets to capture (0 = unlimited)")
    parser.add_argument("--filter", "-f", default="all",
                        choices=["all","tcp","TCP","udp","UDP","icmp","ICMP"],
                        help="Protocol filter")
    parser.add_argument("--output", "-o", default=None,
                        help="JSON output file path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show payload content")
    args = parser.parse_args()

    if sys.platform == "win32":
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            is_admin = False
        if not is_admin:
            print("\n  [ERROR] Administrator privileges required.")
            print("  Right-click PyCharm / terminal -> Run as administrator\n")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("\n  [ERROR] Root privileges required.")
            print("  Run: sudo python3 packet_analyzer.py\n")
            sys.exit(1)

    capture_packets(
        interface=args.interface,
        count=args.count,
        proto_filter=args.filter,
        output_file=args.output,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
