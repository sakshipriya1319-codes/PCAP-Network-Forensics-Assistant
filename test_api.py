"""
tests/test_api.py

API endpoint tests (no real PCAP needed – tests status/404 handling).
"""
import json


def test_status_endpoint(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.get_json()
    assert d["app"] == "PCAP Network Forensics Assistant"


def test_analyses_list(client):
    r = client.get("/api/analyses")
    assert r.status_code == 200
    assert isinstance(r.get_json(), list)


def test_analysis_not_found(client):
    r = client.get("/api/analyses/999999")
    assert r.status_code == 404


def test_summary_not_found(client):
    r = client.get("/api/summary/999999")
    assert r.status_code == 404


def test_protocols_not_found(client):
    r = client.get("/api/protocols/999999")
    assert r.status_code in (404, 202)


def test_conversations_not_found(client):
    r = client.get("/api/conversations/999999")
    assert r.status_code in (404, 202)


def test_alerts_not_found(client):
    r = client.get("/api/alerts/999999")
    assert r.status_code in (404, 202)


def test_delete_nonexistent(client):
    r = client.delete("/api/analyses/999999")
    # Should succeed silently (no-op delete)
    assert r.status_code == 200
