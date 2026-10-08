"""
routes/api.py

REST API endpoints.  All return JSON.
"""
from __future__ import annotations

import csv
import io
import json
import os
import time
from datetime import datetime

from flask import Blueprint, jsonify, request, abort, Response

from models.database import get_analysis, get_all_analyses, delete_analysis
from analyzer.tshark_parser import tshark_available, get_tshark_version
from analyzer.pcap_parser import scapy_available

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_result(analysis_id: int):
    """Return (result_dict, None) on success, or (None, pending_response) when not complete."""
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404, description="Analysis not found")
    if analysis.get("status") != "complete":
        return None, (jsonify({"status": analysis.get("status"), "error": analysis.get("error")}), 202)
    return analysis.get("result", {}), None


def _paginate(items: list) -> dict:
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(1, int(request.args.get("per_page", 100))))
    total    = len(items)
    start    = (page - 1) * per_page
    end      = start + per_page
    return {
        "data":      items[start:end],
        "total":     total,
        "page":      page,
        "per_page":  per_page,
        "pages":     (total + per_page - 1) // per_page,
    }


# ── Status ────────────────────────────────────────────────────────────────────

@api_bp.route("/status")
def status():
    return jsonify({
        "app":            "PCAP Network Forensics Assistant",
        "version":        "1.0.0",
        "scapy":          scapy_available(),
        "tshark":         tshark_available(),
        "tshark_version": get_tshark_version(),
        "time":           time.time(),
    })


@api_bp.route("/analyses")
def analyses():
    return jsonify(get_all_analyses())


@api_bp.route("/analyses/<int:analysis_id>")
def analysis_status(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    return jsonify({
        "id":          analysis["id"],
        "filename":    analysis["filename"],
        "file_size":   analysis["file_size"],
        "upload_time": analysis["upload_time"],
        "status":      analysis["status"],
        "error":       analysis.get("error"),
    })


@api_bp.route("/analyses/<int:analysis_id>", methods=["DELETE"])
def delete_analysis_route(analysis_id: int):
    delete_analysis(analysis_id)
    return jsonify({"message": "Deleted"}), 200


# ── Core data endpoints ────────────────────────────────────────────────────────

@api_bp.route("/summary/<int:analysis_id>")
def summary(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis:
        abort(404)
    if analysis.get("status") != "complete":
        return jsonify({"status": analysis.get("status"), "error": analysis.get("error")}), 202

    result   = analysis.get("result", {})
    cap      = result.get("capture", {})
    dns      = result.get("dns", {})
    alerts   = result.get("alerts", [])
    conv     = result.get("conversations", {})
    stats    = result.get("statistics", {})

    return jsonify({
        "filename":        analysis["filename"],
        "file_size":       analysis["file_size"],
        "total_packets":   cap.get("total_packets", 0),
        "total_bytes":     cap.get("total_bytes", 0),
        "duration":        cap.get("duration", 0),
        "first_timestamp": cap.get("first_timestamp"),
        "last_timestamp":  cap.get("last_timestamp"),
        "unique_src_ips":  stats.get("unique_src_ips", 0),
        "unique_dst_ips":  stats.get("unique_dst_ips", 0),
        "unique_hosts":    stats.get("unique_hosts", 0),
        "conversations":   conv.get("total", 0),
        "dns_queries":     dns.get("total_queries", 0),
        "alerts":          len(alerts),
        "parse_errors":    len(result.get("parse_errors", [])),
    })


@api_bp.route("/protocols/<int:analysis_id>")
def protocols(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    return jsonify(result.get("protocols", {}))


@api_bp.route("/conversations/<int:analysis_id>")
def conversations(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    convs  = result.get("conversations", {}).get("conversations", [])

    # Filtering
    src_ip   = request.args.get("src_ip")
    dst_ip   = request.args.get("dst_ip")
    proto    = request.args.get("protocol")
    src_port = request.args.get("src_port")
    dst_port = request.args.get("dst_port")

    if src_ip:
        convs = [c for c in convs if c.get("src_ip") == src_ip]
    if dst_ip:
        convs = [c for c in convs if c.get("dst_ip") == dst_ip]
    if proto:
        convs = [c for c in convs if (c.get("protocol") or "").upper() == proto.upper()]
    if src_port:
        convs = [c for c in convs if str(c.get("src_port")) == src_port]
    if dst_port:
        convs = [c for c in convs if str(c.get("dst_port")) == dst_port]

    return jsonify(_paginate(convs))


@api_bp.route("/dns/<int:analysis_id>")
def dns(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    dns_data = result.get("dns", {})

    queries = dns_data.get("queries", [])

    # Filtering
    domain  = request.args.get("domain", "").lower()
    src_ip  = request.args.get("src_ip")
    qtype   = request.args.get("type")

    if domain:
        queries = [q for q in queries if domain in (q.get("name") or "").lower()]
    if src_ip:
        queries = [q for q in queries if q.get("src_ip") == src_ip]
    if qtype:
        queries = [q for q in queries if q.get("type") == qtype.upper()]

    return jsonify({
        "queries":       _paginate(queries),
        "top_domains":   dns_data.get("top_domains",  []),
        "query_types":   dns_data.get("query_types",  {}),
        "top_clients":   dns_data.get("top_clients",  []),
        "server_counts": dns_data.get("server_counts",{}),
        "anomalies":     dns_data.get("anomalies",    []),
        "total_queries": dns_data.get("total_queries", 0),
    })


@api_bp.route("/alerts/<int:analysis_id>")
def alerts(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    findings = result.get("alerts", [])

    severity = request.args.get("severity", "").upper()
    rule     = request.args.get("rule", "").upper()
    src_ip   = request.args.get("src_ip")

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if rule:
        findings = [f for f in findings if rule in (f.get("rule") or "").upper()]
    if src_ip:
        findings = [f for f in findings if f.get("src_ip") == src_ip]

    return jsonify({
        "alerts": _paginate(findings),
        "counts": {
            "HIGH":   sum(1 for f in findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "LOW":    sum(1 for f in findings if f.get("severity") == "LOW"),
        },
    })


@api_bp.route("/packets/<int:analysis_id>")
def packets(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    pkts    = result.get("packets_sample", [])

    # Filtering
    src_ip   = request.args.get("src_ip")
    dst_ip   = request.args.get("dst_ip")
    proto    = request.args.get("protocol")
    src_port = request.args.get("src_port")
    dst_port = request.args.get("dst_port")
    search   = request.args.get("q", "").lower()

    if src_ip:
        pkts = [p for p in pkts if p.get("src_ip") == src_ip]
    if dst_ip:
        pkts = [p for p in pkts if p.get("dst_ip") == dst_ip]
    if proto:
        pkts = [p for p in pkts if (p.get("protocol") or "").upper() == proto.upper()]
    if src_port:
        pkts = [p for p in pkts if str(p.get("src_port")) == src_port]
    if dst_port:
        pkts = [p for p in pkts if str(p.get("dst_port")) == dst_port]
    if search:
        pkts = [p for p in pkts if (
            search in (p.get("src_ip") or "").lower() or
            search in (p.get("dst_ip") or "").lower() or
            search in (p.get("protocol") or "").lower() or
            search in (p.get("dns_query") or "").lower()
        )]

    return jsonify(_paginate(pkts))


@api_bp.route("/hosts/<int:analysis_id>")
def hosts(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    stats  = result.get("statistics", {})
    return jsonify({
        "top_src": stats.get("top_talkers_src", []),
        "top_dst": stats.get("top_talkers_dst", []),
        "unique_hosts": stats.get("unique_hosts", 0),
    })


@api_bp.route("/traffic-over-time/<int:analysis_id>")
def traffic_over_time(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    series = result.get("statistics", {}).get("traffic_over_time", [])
    return jsonify({"series": series})


# ── Export / Report ────────────────────────────────────────────────────────────

@api_bp.route("/export/json/<int:analysis_id>")
def export_json(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    analysis = get_analysis(analysis_id)
    payload  = {
        "report_type": "PCAP Network Forensics Assistant",
        "disclaimer":  (
            "All findings are indicators that require analyst verification. "
            "This tool does not make definitive malice verdicts."
        ),
        "file":        analysis.get("filename"),
        "generated":   datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_packets": result.get("capture", {}).get("total_packets"),
            "duration":      result.get("capture", {}).get("duration"),
            "alerts":        len(result.get("alerts", [])),
        },
        "protocols":     result.get("protocols", {}).get("table", []),
        "alerts":        result.get("alerts", []),
        "top_domains":   result.get("dns", {}).get("top_domains", []),
        "dns_anomalies": result.get("dns", {}).get("anomalies", []),
    }
    resp = Response(
        json.dumps(payload, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="forensics_report_{analysis_id}.json"'},
    )
    return resp


@api_bp.route("/export/csv/<int:analysis_id>")
def export_csv(analysis_id: int):
    result, pending = _get_result(analysis_id)
    if pending: return pending
    alerts  = result.get("alerts", [])
    si      = io.StringIO()
    fields  = ["severity", "rule", "src_ip", "dst_ip", "port", "protocol", "description", "note"]
    writer  = csv.DictWriter(si, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(alerts)
    si.seek(0)
    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="alerts_{analysis_id}.csv"'},
    )


@api_bp.route("/export/html/<int:analysis_id>")
def export_html(analysis_id: int):
    analysis = get_analysis(analysis_id)
    if not analysis or analysis.get("status") != "complete":
        abort(404)
    result   = analysis.get("result", {})
    cap      = result.get("capture", {})
    alerts   = result.get("alerts", [])
    protos   = result.get("protocols", {}).get("table", [])[:15]
    dns_top  = result.get("dns", {}).get("top_domains", [])[:10]

    sev_color = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#3b82f6"}

    rows_alerts = "".join(
        f'<tr><td style="color:{sev_color.get(a.get("severity","LOW"))}">'
        f'{a.get("severity")}</td><td>{a.get("rule")}</td>'
        f'<td>{a.get("src_ip")}</td><td>{a.get("dst_ip")}</td>'
        f'<td>{a.get("description", "")[:120]}</td></tr>'
        for a in alerts
    )
    rows_proto = "".join(
        f'<tr><td>{p["protocol"]}</td><td>{p["packets"]}</td>'
        f'<td>{p["pct_packets"]}%</td></tr>'
        for p in protos
    )
    rows_dns = "".join(
        f'<tr><td>{d["domain"]}</td><td>{d["count"]}</td></tr>'
        for d in dns_top
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Forensics Report – {analysis["filename"]}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}}
h1{{color:#38bdf8}}h2{{color:#7dd3fc;margin-top:2rem}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
th,td{{border:1px solid #334155;padding:.5rem .8rem;text-align:left;font-size:.85rem}}
th{{background:#1e293b}}tr:nth-child(even){{background:#1a2744}}
.disclaimer{{background:#1e293b;border-left:4px solid #f59e0b;padding:1rem;margin:1rem 0}}
footer{{margin-top:3rem;color:#64748b;font-size:.75rem;text-align:center;border-top:1px solid #334155;padding-top:1rem}}
</style></head><body>
<h1>PCAP Network Forensics Report</h1>
<div class="disclaimer">⚠ All findings are indicators requiring analyst verification.
This tool does not make definitive malice verdicts.</div>
<h2>Capture Information</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>File</td><td>{analysis["filename"]}</td></tr>
<tr><td>Total Packets</td><td>{cap.get("total_packets",0):,}</td></tr>
<tr><td>Total Bytes</td><td>{cap.get("total_bytes",0):,}</td></tr>
<tr><td>Duration</td><td>{cap.get("duration",0):.2f}s</td></tr>
<tr><td>Alerts Generated</td><td>{len(alerts)}</td></tr>
</table>
<h2>Protocol Distribution</h2>
<table><tr><th>Protocol</th><th>Packets</th><th>%</th></tr>{rows_proto}</table>
<h2>Top DNS Domains</h2>
<table><tr><th>Domain</th><th>Queries</th></tr>{rows_dns}</table>
<h2>Suspicious Activity Findings ({len(alerts)} total)</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Dest IP</th><th>Description</th></tr>
{rows_alerts}</table>
<footer>Generated by PCAP Network Forensics Assistant &nbsp;|&nbsp; {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</footer>
</body></html>"""

    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id}.html"'},
    )
