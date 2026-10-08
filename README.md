# PCAP Network Forensics Assistant

> **"Analyze. Investigate. Understand Network Traffic."**

A production-quality, web-based network forensics application built as an academic cybersecurity project. Upload a `.pcap` or `.pcapng` packet-capture file and get an instant, detailed forensic analysis through a professional SOC-style dashboard — all running locally with no cloud services required.

---

## Table of ContentsCC

1. [Features](#features)
2. [Architecture](#architecture)
3. [Technology Stack](#technology-stack)
4. [Installation](#installation)
5. [Running the Application](#running-the-application)
6. [Generating Demo Traffic](#generating-demo-traffic)
7. [How to Upload a PCAP](#how-to-upload-a-pcap)
8. [Detection Engine](#detection-engine)
9. [REST API Reference](#rest-api-reference)
10. [Testing](#testing)
11. [Configuration](#configuration)
12. [Limitations](#limitations)
13. [Future Improvements](#future-improvements)

---

## Features

| Category | Details |
|---|---|
| **PCAP Upload** | Drag-and-drop, file validation, size limit, secure filename, background analysis |
| **Overview** | Packets, bytes, duration, unique IPs, protocols, conversations, DNS queries, alert count |
| **Protocol Analysis** | Per-protocol packet + byte counts, doughnut chart, top-protocol tables |
| **Conversations** | 5-tuple flows, duration, TCP state, sortable/filterable table |
| **DNS Analysis** | Query log, top domains, query types, top clients, anomaly detection |
| **Alerts** | Rule-based suspicious activity detection (port scan, DNS anomalies, beaconing, large transfers, suspicious ports, and more) |
| **Packet Browser** | Search/filter packets, decoded layer detail panel |
| **Traffic Charts** | Traffic-over-time line chart, protocol doughnut chart |
| **Export** | JSON report, CSV alerts, standalone HTML report |
| **TShark Integration** | Optional — enriches analysis when TShark is installed |
| **Analysis History** | SQLite-backed history of previous analyses |

---

## Architecture

```
pcap-forensics-assistant/
│
├── app.py                     # Flask application factory
├── config.py                  # All configurable thresholds and settings
├── requirements.txt
├── README.md
│
├── analyzer/
│   ├── pcap_parser.py         # Scapy-based PCAP ingestion
│   ├── protocol_analyzer.py   # Protocol counting / statistics
│   ├── conversation_analyzer.py  # 5-tuple flow aggregation
│   ├── dns_analyzer.py        # DNS extraction and anomaly detection
│   ├── anomaly_detector.py    # Rule-based suspicious activity engine
│   ├── statistics.py          # Top talkers, traffic-over-time
│   └── tshark_parser.py       # Optional TShark integration
│
├── models/
│   └── database.py            # SQLite history store
│
├── routes/
│   ├── upload.py              # File upload + background analysis
│   ├── dashboard.py           # HTML page routes
│   └── api.py                 # REST API (JSON)
│
├── templates/
│   ├── base.html              # Sidebar layout
│   ├── index.html             # Upload page
│   ├── dashboard.html         # Analysis overview
│   ├── packets.html           # Packet browser
│   ├── conversations.html     # Conversations table
│   ├── dns.html               # DNS analysis
│   └── alerts.html            # Suspicious activity alerts
│
├── static/
│   ├── css/style.css          # Dark SOC theme
│   └── js/
│       ├── dashboard.js       # Dashboard data loading / charts
│       └── packets.js         # Packet browser
│
├── tools/
│   └── generate_demo_pcap.py  # Synthetic demo PCAP generator
│
├── tests/                     # pytest test suite
├── uploads/                   # Uploaded PCAP files (git-ignored)
└── reports/                   # Generated reports (git-ignored)
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python 3.11+, Flask 3 |
| Packet Analysis | Scapy 2.5 |
| Optional Supplement | TShark / Wireshark CLI |
| Data Processing | Python stdlib + Pandas (optional) |
| Database | SQLite (via Python stdlib) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4 (CDN) |
| CSS Framework | Custom dark theme (no Bootstrap dependency) |

---

## Installation

### Prerequisites

- Python 3.11 or newer
- pip
- (Optional) Wireshark/TShark for supplemental analysis

### 1. Clone / download the project

```bash
git clone <repo-url> pcap-forensics-assistant
cd pcap-forensics-assistant
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

**Windows:**
```
venv\Scripts\activate
```

**Linux / macOS:**
```bash
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

> **Note (Windows / Scapy):** Scapy on Windows may require Npcap.
> Download it from https://npcap.com/ and install before running.

### TShark (optional)

TShark is the command-line companion to Wireshark.
The application works without it — Scapy is the primary analysis engine.

**Windows:** Install Wireshark from https://www.wireshark.org/ (includes TShark).
Add the Wireshark install directory to your PATH.

**Ubuntu/Debian:**
```bash
sudo apt install tshark
```

**macOS:**
```bash
brew install wireshark
```

Verify:
```bash
tshark --version
```

---

## Running the Application

```bash
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

The application starts, creates the SQLite database, and is ready to accept PCAP uploads.

### Environment variables (optional)

| Variable | Default | Description |
|---|---|---|
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `5000` | Port |
| `SECRET_KEY` | (dev key) | Flask secret key |

---

## Generating Demo Traffic

A synthetic PCAP generator is included for testing the dashboard without a real capture file.

```bash
python tools/generate_demo_pcap.py
# Writes to: uploads/demo_traffic.pcap
```

Or specify a custom path:

```bash
python tools/generate_demo_pcap.py /path/to/output.pcap
```

The generated PCAP contains:
- DNS queries and responses (including anomalous patterns)
- TCP web traffic (HTTP/HTTPS)
- SSH connections
- ICMP ping
- ARP
- Port scan indicators
- Beaconing-like repeated connections
- Suspicious port (4444) traffic

---

## How to Upload a PCAP

1. Navigate to **http://127.0.0.1:5000**
2. Drag and drop a `.pcap` or `.pcapng` file onto the upload zone, or click **Browse File**
3. The file is uploaded and analysis begins automatically in the background
4. The page polls for completion and redirects to the **Analysis Dashboard** when ready
5. Large files show a progress indicator — analysis of 100k+ packet captures may take 1–3 minutes

---

## Detection Engine

> **Important:** All detections are **indicators** requiring analyst verification.
> The engine does not make definitive malice verdicts.

### Detection Rules

| Rule | Trigger | Default Severity |
|---|---|---|
| `PORT_SCAN_INDICATOR` | One source contacts ≥ 15 unique destination ports | MEDIUM |
| `HOST_SCAN_INDICATOR` | One source contacts ≥ 10 unique destination IPs | MEDIUM |
| `SUSPICIOUS_PORT` | Traffic on well-known suspicious ports (4444, 1337, 31337, 6667, …) | MEDIUM |
| `FAILED_TCP_CONNECTIONS` | ≥ 20 TCP RST packets from a single source | MEDIUM |
| `EXCESSIVE_CONNECTIONS` | Source involved in ≥ 200 packet flows | LOW |
| `ICMP_FLOOD_INDICATOR` | Single source sends ≥ 200 ICMP packets | MEDIUM |
| `LARGE_DATA_TRANSFER` | Flow transfers ≥ 10 MB; HIGH if internal → external | HIGH / LOW |
| `BEACONING_INDICATOR` | ≥ 5 repeated connections with ≤ 20% timing jitter | MEDIUM |
| `EXTERNAL_COMMUNICATION` | Internal host communicates with external IP | LOW |
| `UNUSUAL_PROTO_PORT` | Protocol detected on non-standard port | LOW |
| `HIGH_DNS_VOLUME` | Host issues ≥ 100 DNS queries | MEDIUM |
| `LONG_DOMAIN_NAME` | Domain name ≥ 50 characters | LOW |
| `LONG_DNS_LABEL` | Individual DNS label ≥ 40 characters | MEDIUM |
| `HIGH_SUBDOMAIN_ENTROPY` | ≥ 30 unique subdomains under one apex | MEDIUM |
| `REPEATED_DNS_FAILURES` | ≥ 20 NXDOMAIN responses for a host | LOW |
| `HIGH_DNS_RATE` | Average DNS query interval < 0.5s | MEDIUM |

All thresholds are configurable in [`config.py`](config.py).

---

## REST API Reference

All API responses are JSON. Endpoints that return data require a completed analysis (`analysis_id`).

### System

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | Application status, TShark availability |
| GET | `/api/analyses` | List all analyses |
| GET | `/api/analyses/<id>` | Status of one analysis |
| DELETE | `/api/analyses/<id>` | Delete an analysis record |

### Analysis Data

| Method | Endpoint | Description |
|---|---|---|
| POST | `/upload` | Upload PCAP file |
| GET | `/api/summary/<id>` | Capture overview |
| GET | `/api/protocols/<id>` | Protocol statistics |
| GET | `/api/conversations/<id>` | Network conversations (supports filtering) |
| GET | `/api/dns/<id>` | DNS queries and anomalies (supports filtering) |
| GET | `/api/alerts/<id>` | Suspicious activity findings (supports filtering) |
| GET | `/api/packets/<id>` | Packet list (supports filtering + pagination) |
| GET | `/api/hosts/<id>` | Top talkers |
| GET | `/api/traffic-over-time/<id>` | Time-series traffic data |

### Export

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/export/json/<id>` | Full JSON report |
| GET | `/api/export/csv/<id>` | CSV of all alerts |
| GET | `/api/export/html/<id>` | Standalone HTML report |

### Filtering Query Parameters

Conversations: `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`
DNS: `domain`, `src_ip`, `type`
Alerts: `severity` (HIGH/MEDIUM/LOW), `rule`, `src_ip`
Packets: `src_ip`, `dst_ip`, `protocol`, `src_port`, `dst_port`, `q` (global search)
Pagination: `page`, `per_page`

### Example Response — Alert

```json
{
  "severity": "MEDIUM",
  "rule": "PORT_SCAN_INDICATOR",
  "src_ip": "192.168.1.30",
  "dst_ip": "multiple destinations",
  "port": "24 unique ports",
  "protocol": "TCP/UDP",
  "description": "Host 192.168.1.30 contacted 24 unique destination ports. This pattern may indicate port scanning activity.",
  "recommendation": "Review connection attempts from this host. Verify if this is authorised network scanning or enumeration.",
  "confidence": "moderate",
  "note": "Indicator only – requires analyst verification"
}
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_anomaly_detector.py -v

# Run with coverage (requires pytest-cov)
pip install pytest-cov
pytest tests/ --cov=analyzer --cov-report=term-missing
```

Test coverage includes:
- Protocol detection
- Conversation aggregation
- DNS extraction and anomaly detection
- Port scan detection
- Host scan detection
- Beaconing detection
- Large transfer detection
- File upload validation
- API endpoint responses

---

## Configuration

All configurable settings are in [`config.py`](config.py):

```python
MAX_UPLOAD_SIZE     = 500 * 1024 * 1024  # 500 MB
MAX_PACKETS         = 500_000            # demo/memory safety cap

PORT_SCAN_THRESHOLD         = 15   # unique dst ports → scan indicator
HOST_SCAN_THRESHOLD         = 10   # unique dst hosts → scan indicator
FAILED_TCP_THRESHOLD        = 20   # RST packets per src
EXCESSIVE_CONN_THRESHOLD    = 200  # flows per src
DNS_QUERY_THRESHOLD         = 100  # queries per host
LARGE_TRANSFER_THRESHOLD    = 10 * 1024 * 1024  # 10 MB
BEACONING_MIN_CONNECTIONS   = 5
BEACONING_INTERVAL_TOLERANCE = 0.20  # 20% jitter

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 2323, 5555, ...}
```

---

## Limitations

- **No decryption:** TLS/HTTPS payload is not decrypted. Only metadata (IPs, ports, SNI) is analysed.
- **Heuristic detections:** All detections are probabilistic. False positives and false negatives are possible.
- **No live capture:** Only offline PCAP file analysis is supported.
- **Packet limit:** Captures beyond 500,000 packets are truncated for performance. Configurable in `config.py`.
- **No malware identification:** The tool cannot identify specific malware families.
- **Windows / Scapy:** Scapy requires Npcap on Windows for full functionality, although offline PCAP reading typically works without it.
- **Performance:** Very large PCAPs (>100 MB) may take several minutes to process.

---

## Future Improvements

- Live capture mode (Scapy `sniff()`)
- GeoIP lookups for external IPs (offline database)
- More TLS metadata extraction (JA3/JA3S fingerprinting)
- PCAP diff mode (compare two captures)
- IOC matching against offline threat-intel list
- Email / webhook alerting
- Multi-user sessions
- Distributed analysis for very large files
- PCAP slicing and export by conversation

---

## Screenshots
project output.png
project output 2.png

---

## Disclaimer

This tool is for educational and academic purposes. All analysis outputs are indicators requiring
human analyst verification. The tool does not make definitive security verdicts.
Treat all findings as starting points for investigation, not conclusions.

---

*PCAP Network Forensics Assistant – Built with Python, Flask, and Scapy*
