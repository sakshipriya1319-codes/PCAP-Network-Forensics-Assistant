"""
tests/test_upload.py

Tests for file upload validation.
"""
from __future__ import annotations

import io
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_upload_no_file(client):
    r = client.post("/upload")
    assert r.status_code == 400
    assert b"No file" in r.data


def test_upload_wrong_extension(client, tmp_path):
    data = {"file": (io.BytesIO(b"not a pcap"), "test.txt")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 400
    assert b"Invalid file type" in r.data


def test_upload_empty_file(client):
    data = {"file": (io.BytesIO(b""), "test.pcap")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    assert r.status_code == 400


def test_upload_valid_pcap_returns_202(client, tmp_path):
    """A minimal valid PCAP magic bytes should be accepted (202)."""
    # Minimal PCAP global header (little-endian)
    magic = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    data = {"file": (io.BytesIO(magic), "test.pcap")}
    r = client.post("/upload", data=data, content_type="multipart/form-data")
    # 202 Accepted (analysis kicked off) – even if parsing fails in background
    assert r.status_code == 202
    json_data = r.get_json()
    assert "analysis_id" in json_data


def test_api_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    d = r.get_json()
    assert "scapy" in d
    assert "tshark" in d
