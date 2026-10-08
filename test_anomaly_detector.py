"""
tests/test_anomaly_detector.py
"""
from analyzer.anomaly_detector import detect_anomalies, _is_internal


def test_suspicious_port_detection(sample_packets):
    convs = []
    findings = detect_anomalies(sample_packets, convs)
    rules = [f["rule"] for f in findings]
    assert "SUSPICIOUS_PORT" in rules


def test_suspicious_port_is_medium(sample_packets):
    findings = detect_anomalies(sample_packets, [])
    sp = [f for f in findings if f["rule"] == "SUSPICIOUS_PORT"]
    assert all(f["severity"] == "MEDIUM" for f in sp)


def test_port_scan_detection():
    """One src connecting to >PORT_SCAN_THRESHOLD unique ports."""
    pkts = []
    for port in range(1, 25):  # 24 unique ports
        pkts.append({
            "src_ip": "192.168.1.99", "dst_ip": "10.0.0.1",
            "src_port": 50000 + port, "dst_port": port,
            "protocol": "TCP", "tcp_flags": "SYN",
            "length": 60, "timestamp": 1700000000.0 + port,
        })
    findings = detect_anomalies(pkts, [])
    rules = [f["rule"] for f in findings]
    assert "PORT_SCAN_INDICATOR" in rules


def test_host_scan_detection():
    """One src contacting many distinct destination IPs."""
    pkts = []
    for i in range(1, 20):
        pkts.append({
            "src_ip": "192.168.1.88", "dst_ip": f"10.0.{i}.1",
            "src_port": 50000, "dst_port": 80,
            "protocol": "TCP", "tcp_flags": "SYN",
            "length": 60, "timestamp": 1700000000.0 + i,
        })
    findings = detect_anomalies(pkts, [])
    rules = [f["rule"] for f in findings]
    assert "HOST_SCAN_INDICATOR" in rules


def test_large_transfer_detection():
    """Conversation with bytes > threshold → LARGE_DATA_TRANSFER."""
    from config import LARGE_TRANSFER_THRESHOLD
    convs = [{
        "src_ip":   "192.168.1.10",
        "dst_ip":   "203.0.113.5",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": "TCP",
        "packets":  100,
        "bytes":    LARGE_TRANSFER_THRESHOLD + 1,
        "start_time": 1700000000.0,
        "end_time":   1700000060.0,
    }]
    findings = detect_anomalies([], convs)
    rules = [f["rule"] for f in findings]
    assert "LARGE_DATA_TRANSFER" in rules
    high_alerts = [f for f in findings if f["rule"] == "LARGE_DATA_TRANSFER" and f["severity"] == "HIGH"]
    assert len(high_alerts) >= 1


def test_findings_have_required_fields(sample_packets):
    findings = detect_anomalies(sample_packets, [])
    for f in findings:
        assert "severity"    in f
        assert "rule"        in f
        assert "description" in f
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW")


def test_is_internal():
    assert _is_internal("192.168.1.1")
    assert _is_internal("10.0.0.5")
    assert _is_internal("172.16.5.5")
    assert not _is_internal("8.8.8.8")
    assert not _is_internal("203.0.113.5")


def test_beaconing_detection():
    """Regular ~30s interval connections should flag BEACONING_INDICATOR."""
    convs = []
    base = 1700000000.0
    for i in range(10):
        convs.append({
            "src_ip":   "192.168.1.10",
            "dst_ip":   "203.0.113.1",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": "TCP",
            "packets":  5,
            "bytes":    1024,
            "start_time": base + i * 30.0,  # exactly 30s apart
            "end_time":   base + i * 30.0 + 0.5,
        })
    findings = detect_anomalies([], convs)
    rules = [f["rule"] for f in findings]
    assert "BEACONING_INDICATOR" in rules
