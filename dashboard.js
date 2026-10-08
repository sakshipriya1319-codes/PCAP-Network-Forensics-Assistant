/**
 * dashboard.js – PCAP Forensics Assistant
 * Populates the dashboard with data from the REST API.
 */
(function () {
  "use strict";

  const AID = document.querySelector(".dashboard-wrapper").dataset.id;
  let protoChartInst = null;
  let trafficChartInst = null;

  // ── Colour palette for charts ────────────────────────────────────────────
  const CHART_COLORS = [
    "#38bdf8","#818cf8","#34d399","#fb923c","#f472b6",
    "#facc15","#a78bfa","#60a5fa","#4ade80","#f87171",
    "#e879f9","#2dd4bf",
  ];

  // ── Bootstrap: poll if pending ───────────────────────────────────────────
  const banner = document.getElementById("statusBanner");
  if (banner) {
    // Page just loaded while analysis still running
    const timer = setInterval(async () => {
      const r = await fetch(`/api/analyses/${AID}`);
      const d = await r.json();
      document.getElementById("pollMsg").textContent = d.status + "…";
      if (d.status === "complete") {
        clearInterval(timer);
        location.reload();
      } else if (d.status === "error") {
        clearInterval(timer);
        document.getElementById("pollMsg").textContent = "Error: " + (d.error || "");
      }
    }, 2500);
  } else {
    loadAll();
  }

  // ── Load everything ──────────────────────────────────────────────────────
  async function loadAll() {
    await Promise.all([
      loadSummary(),
      loadProtocols(),
      loadHosts(),
      loadDns(),
      loadAlerts(),
      loadTrafficOverTime(),
    ]);
  }

  // ── Summary cards ────────────────────────────────────────────────────────
  async function loadSummary() {
    try {
      const d = await fetchJson(`/api/summary/${AID}`);
      setText("sc-packets",  fmtNum(d.total_packets));
      setText("sc-bytes",    fmtBytes(d.total_bytes));
      setText("sc-convs",    fmtNum(d.conversations));
      setText("sc-hosts",    fmtNum(d.unique_hosts));
      setText("sc-dns",      fmtNum(d.dns_queries));
      setText("sc-alerts",   fmtNum(d.alerts));

      // Capture table
      const rows = [
        ["File name",        d.filename],
        ["File size",        fmtBytes(d.file_size)],
        ["Total packets",    fmtNum(d.total_packets)],
        ["Total bytes",      fmtBytes(d.total_bytes)],
        ["Duration",         (d.duration || 0).toFixed(3) + "s"],
        ["First packet",     fmtTs(d.first_timestamp)],
        ["Last packet",      fmtTs(d.last_timestamp)],
        ["Unique source IPs",d.unique_src_ips],
        ["Unique dest IPs",  d.unique_dst_ips],
        ["Conversations",    fmtNum(d.conversations)],
        ["DNS queries",      fmtNum(d.dns_queries)],
        ["Parse errors",     d.parse_errors],
      ];
      document.querySelector("#captureTable tbody").innerHTML =
        rows.map(([k, v]) => `<tr><td>${k}</td><td>${v ?? "–"}</td></tr>`).join("");
    } catch (e) { console.error("summary", e); }
  }

  // ── Protocol chart ───────────────────────────────────────────────────────
  async function loadProtocols() {
    try {
      const d = await fetchJson(`/api/protocols/${AID}`);
      const top = (d.top_by_pkts || []).slice(0, 12);
      const labels = top.map(p => p.protocol);
      const data   = top.map(p => p.packets);

      const ctx = document.getElementById("protoChart").getContext("2d");
      if (protoChartInst) protoChartInst.destroy();
      protoChartInst = new Chart(ctx, {
        type: "doughnut",
        data: {
          labels,
          datasets: [{
            data,
            backgroundColor: CHART_COLORS,
            borderColor: "#0b1120",
            borderWidth: 2,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "right",
              labels: { color: "#e2e8f0", font: { size: 11 }, padding: 10 },
            },
          },
        },
      });
    } catch (e) { console.error("protocols", e); }
  }

  // ── Traffic over time ────────────────────────────────────────────────────
  async function loadTrafficOverTime() {
    try {
      const d = await fetchJson(`/api/traffic-over-time/${AID}`);
      const series = d.series || [];
      if (!series.length) return;

      const labels  = series.map(s => fmtTs(s.time, true));
      const pktData  = series.map(s => s.packets);
      const byteData = series.map(s => s.bytes);

      const ctx = document.getElementById("trafficChart").getContext("2d");
      if (trafficChartInst) trafficChartInst.destroy();
      trafficChartInst = new Chart(ctx, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "Packets",
              data: pktData,
              borderColor: "#38bdf8",
              backgroundColor: "rgba(56,189,248,.08)",
              tension: 0.3,
              fill: true,
              yAxisID: "y",
              pointRadius: 0,
            },
            {
              label: "Bytes",
              data: byteData,
              borderColor: "#818cf8",
              backgroundColor: "rgba(129,140,248,.05)",
              tension: 0.3,
              fill: true,
              yAxisID: "y1",
              pointRadius: 0,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: { legend: { labels: { color: "#e2e8f0" } } },
          scales: {
            x:  { ticks: { color: "#64748b", maxTicksLimit: 10 }, grid: { color: "#1e3a5f" } },
            y:  { ticks: { color: "#64748b" }, grid: { color: "#1e3a5f" }, title: { display: true, text: "Packets", color: "#38bdf8" } },
            y1: { position: "right", ticks: { color: "#64748b" }, grid: { display: false }, title: { display: true, text: "Bytes", color: "#818cf8" } },
          },
        },
      });
    } catch (e) { console.error("traffic-over-time", e); }
  }

  // ── Hosts ────────────────────────────────────────────────────────────────
  async function loadHosts() {
    try {
      const d = await fetchJson(`/api/hosts/${AID}`);
      document.getElementById("topSrcBody").innerHTML =
        (d.top_src || []).map(h =>
          `<tr><td>${h.ip}</td><td>${fmtNum(h.packets)}</td><td>${fmtBytes(h.bytes)}</td></tr>`
        ).join("") || "<tr><td colspan=3 class='muted'>No data</td></tr>";

      document.getElementById("topDstBody").innerHTML =
        (d.top_dst || []).map(h =>
          `<tr><td>${h.ip}</td><td>${fmtNum(h.packets)}</td><td>${fmtBytes(h.bytes)}</td></tr>`
        ).join("") || "<tr><td colspan=3 class='muted'>No data</td></tr>";
    } catch (e) { console.error("hosts", e); }
  }

  // ── DNS ──────────────────────────────────────────────────────────────────
  async function loadDns() {
    try {
      const d = await fetchJson(`/api/dns/${AID}?per_page=1`);
      document.getElementById("topDnsBody").innerHTML =
        (d.top_domains || []).slice(0, 10).map(x =>
          `<tr><td>${x.domain}</td><td>${x.count}</td></tr>`
        ).join("") || "<tr><td colspan=2 class='muted'>No DNS data</td></tr>";
    } catch (e) { console.error("dns", e); }
  }

  // ── Alerts ───────────────────────────────────────────────────────────────
  async function loadAlerts() {
    try {
      const d = await fetchJson(`/api/alerts/${AID}?per_page=5`);
      const alerts = d.alerts.data || [];
      const el = document.getElementById("recentAlerts");
      if (!alerts.length) {
        el.innerHTML = "<p class='muted'>No alerts detected.</p>";
        return;
      }
      const sevColor = { HIGH: "sev-high", MEDIUM: "sev-medium", LOW: "sev-low" };
      el.innerHTML = alerts.map(a =>
        `<div class="alert-finding ${sevColor[a.severity] || ''}">
          <div class="finding-header">
            <span class="sev-badge ${sevColor[a.severity] || ''}">${a.severity}</span>
            <span class="finding-rule">${a.rule}</span>
          </div>
          <div class="finding-desc">${(a.description || "").slice(0, 100)}…</div>
         </div>`
      ).join("");
    } catch (e) { console.error("alerts", e); }
  }

  // ── Utilities ────────────────────────────────────────────────────────────
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val ?? "–";
  }

  async function fetchJson(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }

  function fmtNum(n) {
    if (n == null) return "–";
    return Number(n).toLocaleString();
  }

  function fmtBytes(b) {
    if (b == null) return "–";
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
    return (b / 1073741824).toFixed(2) + " GB";
  }

  function fmtTs(ts, short) {
    if (!ts) return "–";
    const d = new Date(ts * 1000);
    if (short) {
      return d.toLocaleTimeString();
    }
    return d.toLocaleString();
  }
})();
