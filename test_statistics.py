"""
tests/test_statistics.py
"""
from analyzer.statistics import compute_statistics


def test_top_talkers(sample_packets):
    cap_stats = {
        "first_timestamp": 1700000000.0,
        "last_timestamp":  1700000003.0,
        "total_packets":   4,
        "total_bytes":     242,
    }
    result = compute_statistics(sample_packets, cap_stats)
    assert len(result["top_talkers_src"]) >= 1
    assert result["unique_hosts"] >= 1


def test_traffic_over_time(sample_packets):
    cap_stats = {
        "first_timestamp": 1700000000.0,
        "last_timestamp":  1700000060.0,
        "total_packets":   4,
        "total_bytes":     242,
    }
    result = compute_statistics(sample_packets, cap_stats)
    series = result["traffic_over_time"]
    assert isinstance(series, list)
    assert len(series) > 0
    assert all("time" in s and "packets" in s for s in series)


def test_empty():
    result = compute_statistics([], {})
    assert result["top_talkers_src"] == []
    assert result["unique_hosts"] == 0
