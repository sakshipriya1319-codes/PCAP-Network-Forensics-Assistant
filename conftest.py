"""
tests/conftest.py

Shared pytest fixtures.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Ensure the project root is on the path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(scope="session")
def app():
    """Create the Flask app configured for testing."""
    from app import create_app
    application = create_app()
    application.config.update({
        "TESTING":      True,
        "SECRET_KEY":   "test-secret",
    })
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def sample_packets():
    """Return a minimal list of synthetic packet metadata dicts."""
    return [
        # Normal DNS
        {
            "index": 0, "timestamp": 1700000000.0, "length": 80,
            "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8",
            "src_port": 54321, "dst_port": 53,
            "protocol": "DNS", "tcp_flags": None,
            "ttl": 64, "layers": ["Ethernet", "IPv4", "UDP", "DNS"],
            "dns_query": "example.com", "dns_type": 1, "dns_resp": ["93.184.216.34"],
            "dns_rcode": 0,
            "icmp_type": None, "icmp_code": None,
            "http_method": None, "http_host": None, "http_uri": None,
            "tls_sni": None, "arp_op": None, "src_mac": None, "dst_mac": None,
        },
        # TCP SYN to HTTP
        {
            "index": 1, "timestamp": 1700000001.0, "length": 60,
            "src_ip": "192.168.1.10", "dst_ip": "93.184.216.34",
            "src_port": 49152, "dst_port": 80,
            "protocol": "HTTP", "tcp_flags": "SYN",
            "ttl": 64, "layers": ["Ethernet", "IPv4", "TCP"],
            "dns_query": None, "dns_type": None, "dns_resp": None, "dns_rcode": None,
            "icmp_type": None, "icmp_code": None,
            "http_method": None, "http_host": None, "http_uri": None,
            "tls_sni": None, "arp_op": None, "src_mac": None, "dst_mac": None,
        },
        # ICMP
        {
            "index": 2, "timestamp": 1700000002.0, "length": 42,
            "src_ip": "192.168.1.20", "dst_ip": "192.168.1.10",
            "src_port": None, "dst_port": None,
            "protocol": "ICMP", "tcp_flags": None,
            "ttl": 64, "layers": ["Ethernet", "IPv4", "ICMP"],
            "dns_query": None, "dns_type": None, "dns_resp": None, "dns_rcode": None,
            "icmp_type": 8, "icmp_code": 0,
            "http_method": None, "http_host": None, "http_uri": None,
            "tls_sni": None, "arp_op": None, "src_mac": None, "dst_mac": None,
        },
        # Suspicious port 4444
        {
            "index": 3, "timestamp": 1700000003.0, "length": 60,
            "src_ip": "192.168.1.10", "dst_ip": "1.2.3.4",
            "src_port": 55000, "dst_port": 4444,
            "protocol": "TCP", "tcp_flags": "SYN",
            "ttl": 64, "layers": ["Ethernet", "IPv4", "TCP"],
            "dns_query": None, "dns_type": None, "dns_resp": None, "dns_rcode": None,
            "icmp_type": None, "icmp_code": None,
            "http_method": None, "http_host": None, "http_uri": None,
            "tls_sni": None, "arp_op": None, "src_mac": None, "dst_mac": None,
        },
    ]
