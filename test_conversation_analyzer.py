"""
tests/test_conversation_analyzer.py
"""
from analyzer.conversation_analyzer import analyze_conversations


def test_builds_conversations(sample_packets):
    result = analyze_conversations(sample_packets)
    assert result["total"] >= 1
    assert len(result["conversations"]) == result["total"]


def test_unique_ips(sample_packets):
    result = analyze_conversations(sample_packets)
    assert result["unique_src"] >= 1
    assert result["unique_dst"] >= 1


def test_conversation_fields(sample_packets):
    result = analyze_conversations(sample_packets)
    for conv in result["conversations"]:
        assert "src_ip"    in conv
        assert "dst_ip"    in conv
        assert "packets"   in conv
        assert "bytes"     in conv
        assert "duration"  in conv
        assert "conn_state" in conv


def test_empty_packets():
    result = analyze_conversations([])
    assert result["total"] == 0
