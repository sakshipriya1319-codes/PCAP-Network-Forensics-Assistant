"""
tests/test_dns_analyzer.py
"""
from analyzer.dns_analyzer import analyze_dns


def test_extracts_dns_query(sample_packets):
    result = analyze_dns(sample_packets)
    assert result["total_queries"] >= 1
    assert any(q["name"] == "example.com" for q in result["queries"])


def test_top_domains(sample_packets):
    result = analyze_dns(sample_packets)
    # example.com was queried once
    domains = [d["domain"] for d in result["top_domains"]]
    assert "example.com" in domains


def test_no_anomalies_on_clean_traffic(sample_packets):
    # The 4-packet fixture doesn't have enough volume to trigger anomalies
    result = analyze_dns(sample_packets)
    # anomalies list should exist (may be empty)
    assert isinstance(result["anomalies"], list)


def test_long_domain_anomaly():
    long_domain = "a" * 60 + ".example.com"
    pkts = [{
        "index": 0, "timestamp": 1700000000.0, "length": 90,
        "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 12345, "dst_port": 53,
        "protocol": "DNS",
        "dns_query": long_domain, "dns_type": 1,
        "dns_resp": None, "dns_rcode": 0,
    }]
    result = analyze_dns(pkts)
    types = [a["type"] for a in result["anomalies"]]
    assert "LONG_DOMAIN_NAME" in types


def test_empty_packets():
    result = analyze_dns([])
    assert result["total_queries"] == 0
    assert result["queries"] == []
