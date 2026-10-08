"""
routes/dashboard.py

HTML page routes.
"""
from __future__ import annotations

from flask import Blueprint, render_template, redirect, url_for, abort

from models.database import get_analysis, get_all_analyses

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    return render_template("index.html")


@dashboard_bp.route("/history")
def history():
    analyses = get_all_analyses()
    return render_template("index.html", analyses=analyses)


@dashboard_bp.route("/dashboard/<int:analysis_id>")
def dashboard(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template("dashboard.html", analysis=analysis)


@dashboard_bp.route("/packets/<int:analysis_id>")
def packets(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template("packets.html", analysis=analysis)


@dashboard_bp.route("/conversations/<int:analysis_id>")
def conversations(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template("conversations.html", analysis=analysis)


@dashboard_bp.route("/dns/<int:analysis_id>")
def dns(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template("dns.html", analysis=analysis)


@dashboard_bp.route("/alerts/<int:analysis_id>")
def alerts(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return render_template("alerts.html", analysis=analysis)
