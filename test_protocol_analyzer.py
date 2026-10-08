"""
tests/test_protocol_analyzer.py
"""
from analyzer.protocol_analyzer import analyze_protocols


def test_counts_protocols(sample_packets):
    result = analyze_protocols(sample_packets)
    assert "counts" in result
    assert "table" in result
    assert result["counts"]["DNS"] >= 1
    assert result["counts"]["HTTP"] >= 1
    assert result["counts"]["ICMP"] >= 1


def test_table_has_percentage(sample_packets):
    result = analyze_protocols(sample_packets)
    for row in result["table"]:
        assert 0.0 <= row["pct_packets"] <= 100.0


def test_top_by_pkts_sorted(sample_packets):
    result = analyze_protocols(sample_packets)
    pkts = [r["packets"] for r in result["top_by_pkts"]]
    assert pkts == sorted(pkts, reverse=True)


def test_empty_packets():
    result = analyze_protocols([])
    assert result["counts"] == {}
    assert result["table"] == []
