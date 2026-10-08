"""
routes/upload.py

Handles PCAP file upload, validation, and async analysis trigger.
"""
from __future__ import annotations

import os
import threading
import logging

from flask import (
    Blueprint, request, jsonify, render_template, redirect, url_for
)
from werkzeug.utils import secure_filename

from config import UPLOAD_FOLDER, ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE
from models.database import create_analysis, update_analysis_status, save_analysis_result
from analyzer.pcap_parser import parse_pcap
from analyzer.protocol_analyzer import analyze_protocols
from analyzer.conversation_analyzer import analyze_conversations
from analyzer.dns_analyzer import analyze_dns
from analyzer.anomaly_detector import detect_anomalies
from analyzer.statistics import compute_statistics

log = logging.getLogger(__name__)
upload_bp = Blueprint("upload", __name__)


def _allowed_file(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def _run_analysis(analysis_id: int, filepath: str) -> None:
    """Background worker: parse + analyse the PCAP, persist results."""
    try:
        update_analysis_status(analysis_id, "running")

        from config import MAX_PACKETS
        parse_result = parse_pcap(filepath, max_packets=MAX_PACKETS)
        packets      = parse_result["packets"]
        cap_stats    = parse_result["stats"]

        protocols    = analyze_protocols(packets)
        conv_result  = analyze_conversations(packets)
        conversations= conv_result["conversations"]
        dns_result   = analyze_dns(packets)
        alerts       = detect_anomalies(packets, conversations)
        stats        = compute_statistics(packets, cap_stats)

        result = {
            "capture":       cap_stats,
            "protocols":     protocols,
            "conversations": conv_result,
            "dns":           dns_result,
            "alerts":        alerts,
            "statistics":    stats,
            "parse_errors":  parse_result["errors"],
            # Store a sample of packets for the packet browser (max 5000)
            "packets_sample": packets[:5000],
        }

        save_analysis_result(analysis_id, result)
        log.info("Analysis %d complete", analysis_id)

    except Exception as exc:
        log.exception("Analysis %d failed: %s", analysis_id, exc)
        update_analysis_status(analysis_id, "error", str(exc))


@upload_bp.route("/upload", methods=["GET"])
def upload_page():
    return render_template("index.html")


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not _allowed_file(file.filename):
        return jsonify({
            "error": f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        }), 400

    # Check content-length header (not always present)
    content_length = request.content_length
    if content_length and content_length > MAX_UPLOAD_SIZE:
        return jsonify({"error": "File too large"}), 413

    filename  = secure_filename(file.filename)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filepath  = os.path.join(UPLOAD_FOLDER, filename)

    # Ensure uniqueness to avoid collisions
    base, ext = os.path.splitext(filepath)
    counter = 1
    while os.path.exists(filepath):
        filepath = f"{base}_{counter}{ext}"
        counter += 1

    file.save(filepath)

    # Verify file size on disk
    file_size = os.path.getsize(filepath)
    if file_size > MAX_UPLOAD_SIZE:
        os.remove(filepath)
        return jsonify({"error": "File too large after save"}), 413

    if file_size == 0:
        os.remove(filepath)
        return jsonify({"error": "Empty file"}), 400

    analysis_id = create_analysis(
        os.path.basename(filepath), filepath, file_size
    )

    # Run analysis in background thread
    t = threading.Thread(
        target=_run_analysis, args=(analysis_id, filepath), daemon=True
    )
    t.start()

    return jsonify({
        "message":     "File uploaded successfully. Analysis started.",
        "analysis_id": analysis_id,
        "filename":    os.path.basename(filepath),
        "file_size":   file_size,
    }), 202
