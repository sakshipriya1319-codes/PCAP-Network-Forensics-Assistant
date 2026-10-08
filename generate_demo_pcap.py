#!/usr/bin/env python3
"""
tools/generate_demo_pcap.py

Generates a harmless synthetic PCAP file for testing the
PCAP Network Forensics Assistant dashboard.

Traffic included:
  - DNS queries and responses (A, AAAA, MX records)
  - TCP connections (HTTP, HTTPS, SSH)
  - UDP traffic
  - ICMP echo request/reply
  - ARP
  - Repeated connections (beaconing pattern)
  - Large burst from one host (port scan indicator)

Usage:
    python tools/generate_demo_pcap.py [output_path]

Default output: uploads/demo_traffic.pcap
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import time

# Ensure we can import Scapy from the project root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        wrpcap, Raw,
    )
except ImportError as exc:
    print(f"Scapy not available: {exc}\nInstall it with: pip install scapy")
    sys.exit(1)

# ─── Helpers ──────────────────────────────────────────────────────────────────

INTERNAL_HOSTS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "192.168.1.50",
]
EXTERNAL_DNS   = "8.8.8.8"
EXTERNAL_WEB   = "93.184.216.34"   # example.com (harmless)
EXTERNAL_WEB2  = "151.101.1.140"   # fastly

DOMAINS = [
    "example.com", "google.com", "github.com",
    "stackoverflow.com", "python.org", "wikipedia.org",
    "openstreetmap.org",
]

NXDOMAINS = ["nonexistent-abc123.local", "badhost.internal"]


def rand_sport() -> int:
    return random.randint(49152, 65535)


def ts_gen(base: float = None):
    """Yields monotonically increasing timestamps."""
    t = base or time.time() - 120
    while True:
        t += random.uniform(0.001, 0.5)
        yield t


def make_eth(src_mac: str, dst_mac: str) -> Ether:
    return Ether(src=src_mac, dst=dst_mac)


def mac(host_ip: str) -> str:
    # Deterministic fake MAC from IP last octet
    last = int(host_ip.split(".")[-1])
    return f"de:ad:be:ef:00:{last:02x}"


# ─── Packet builders ──────────────────────────────────────────────────────────

def build_dns_query(src_ip, dns_server, domain, qtype="A", ts=0.0):
    pkt = (
        IP(src=src_ip, dst=dns_server) /
        UDP(sport=rand_sport(), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )
    pkt.time = ts
    return pkt


def build_dns_response(src_ip, dns_server, domain, answer_ip, ts=0.0, rcode=0):
    if rcode == 0 and answer_ip:
        pkt = (
            IP(src=dns_server, dst=src_ip) /
            UDP(sport=53, dport=rand_sport()) /
            DNS(qr=1, rd=1, ra=1, rcode=rcode,
                qd=DNSQR(qname=domain),
                an=DNSRR(rrname=domain, ttl=300, rdata=answer_ip))
        )
    else:
        pkt = (
            IP(src=dns_server, dst=src_ip) /
            UDP(sport=53, dport=rand_sport()) /
            DNS(qr=1, rd=1, ra=1, rcode=rcode,
                qd=DNSQR(qname=domain))
        )
    pkt.time = ts
    return pkt


def build_tcp_handshake(src_ip, dst_ip, dport, base_sport=None, ts=0.0):
    sport = base_sport or rand_sport()
    pkts = []
    # SYN
    p1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = ts
    # SYN-ACK
    p2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001)
    p2.time = ts + 0.01
    # ACK
    p3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001)
    p3.time = ts + 0.02
    pkts += [p1, p2, p3]
    return pkts


def build_tcp_data(src_ip, dst_ip, sport, dport, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", ts=0.0):
    p = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=payload)
    p.time = ts
    return p


def build_icmp_ping(src_ip, dst_ip, ts=0.0):
    req = IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0) / Raw(load=b"ping-payload")
    req.time = ts
    rep = IP(src=dst_ip, dst=src_ip) / ICMP(type=0, code=0) / Raw(load=b"ping-payload")
    rep.time = ts + 0.002
    return [req, rep]


def build_udp_traffic(src_ip, dst_ip, dport, ts=0.0):
    p = IP(src=src_ip, dst=dst_ip) / UDP(sport=rand_sport(), dport=dport) / Raw(load=b"udp-data")
    p.time = ts
    return p


def build_arp(src_ip, target_ip, ts=0.0):
    p = Ether(src=mac(src_ip), dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=src_ip, pdst=target_ip)
    p.time = ts
    return p


# ─── Demo scenario builders ───────────────────────────────────────────────────

def gen_normal_web_traffic(packets, tsg, host):
    """Normal DNS + TCP web traffic."""
    for domain in DOMAINS:
        ts = next(tsg)
        packets.append(build_dns_query(host, EXTERNAL_DNS, domain, ts=ts))
        packets.append(build_dns_response(host, EXTERNAL_DNS, domain, EXTERNAL_WEB, ts=ts+0.05))
        ts2 = next(tsg)
        for p in build_tcp_handshake(host, EXTERNAL_WEB, 80, ts=ts2):
            packets.append(p)
        packets.append(build_tcp_data(host, EXTERNAL_WEB, rand_sport(), 80, ts=ts2+0.05))
        # HTTPS
        ts3 = next(tsg)
        for p in build_tcp_handshake(host, EXTERNAL_WEB, 443, ts=ts3):
            packets.append(p)


def gen_dns_flood(packets, tsg, host):
    """High-frequency DNS queries from one host (anomaly indicator)."""
    for i in range(120):
        domain = f"subdomain{i}.{random.choice(DOMAINS)}"
        ts = next(tsg)
        packets.append(build_dns_query(host, EXTERNAL_DNS, domain, ts=ts))
        packets.append(build_dns_response(host, EXTERNAL_DNS, domain, EXTERNAL_WEB, ts=ts+0.01))


def gen_nxdomain_failures(packets, tsg, host):
    """Repeated NXDOMAIN responses."""
    for domain in NXDOMAINS * 12:
        ts = next(tsg)
        packets.append(build_dns_query(host, EXTERNAL_DNS, domain, ts=ts))
        packets.append(build_dns_response(host, EXTERNAL_DNS, domain, None, ts=ts+0.02, rcode=3))


def gen_port_scan_indicator(packets, tsg, host):
    """One host sending SYN to many ports."""
    target = "10.0.0.1"
    for port in range(20, 50):
        ts = next(tsg)
        p = IP(src=host, dst=target) / TCP(sport=rand_sport(), dport=port, flags="S")
        p.time = ts
        packets.append(p)
        # RST back
        rst = IP(src=target, dst=host) / TCP(sport=port, dport=rand_sport(), flags="R")
        rst.time = ts + 0.005
        packets.append(rst)


def gen_beaconing(packets, tsg, host):
    """Regular-interval connections (beaconing indicator)."""
    base_ts = next(tsg)
    for i in range(12):
        ts = base_ts + i * 30 + random.uniform(-1, 1)  # ~30s interval
        for p in build_tcp_handshake(host, EXTERNAL_WEB2, 443, ts=ts):
            packets.append(p)
        # Small data exchange
        packets.append(build_tcp_data(host, EXTERNAL_WEB2, rand_sport(), 443, b"\x16\x03\x01", ts=ts+0.03))


def gen_icmp(packets, tsg, host):
    for dst in INTERNAL_HOSTS + [EXTERNAL_WEB]:
        ts = next(tsg)
        packets += build_icmp_ping(host, dst, ts=ts)


def gen_arp(packets, tsg, host):
    for target in INTERNAL_HOSTS:
        if target != host:
            packets.append(build_arp(host, target, ts=next(tsg)))


def gen_ssh(packets, tsg, host):
    ts = next(tsg)
    pkts = build_tcp_handshake(host, "10.0.0.50", 22, ts=ts)
    packets += pkts
    packets.append(build_tcp_data(host, "10.0.0.50", rand_sport(), 22,
                                  b"SSH-2.0-OpenSSH_8.2\r\n", ts=ts+0.1))


def gen_suspicious_port(packets, tsg, host):
    """Traffic on suspicious port 4444 (indicator)."""
    ts = next(tsg)
    pkts = build_tcp_handshake(host, EXTERNAL_WEB2, 4444, ts=ts)
    packets += pkts


# ─── Main ─────────────────────────────────────────────────────────────────────

def generate(output_path: str) -> None:
    print(f"Generating demo PCAP → {output_path}")
    packets = []
    tsg = ts_gen()

    for host in INTERNAL_HOSTS:
        gen_normal_web_traffic(packets, tsg, host)
        gen_icmp(packets, tsg, host)
        gen_arp(packets, tsg, host)
        gen_ssh(packets, tsg, host)

    # Anomalies from specific hosts
    gen_dns_flood(packets, tsg, "192.168.1.10")
    gen_nxdomain_failures(packets, tsg, "192.168.1.20")
    gen_port_scan_indicator(packets, tsg, "192.168.1.30")
    gen_beaconing(packets, tsg, "192.168.1.50")
    gen_suspicious_port(packets, tsg, "192.168.1.10")

    # Sort by timestamp
    packets.sort(key=lambda p: float(p.time))

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"✓ Written {len(packets)} packets to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate demo PCAP for PCAP Forensics Assistant")
    parser.add_argument("output", nargs="?",
                        default=os.path.join(REPO_ROOT, "uploads", "demo_traffic.pcap"),
                        help="Output PCAP path")
    args = parser.parse_args()
    generate(args.output)


if __name__ == "__main__":
    main()
