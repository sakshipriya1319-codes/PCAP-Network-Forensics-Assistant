/**
 * packets.js – PCAP Forensics Assistant
 * Drives the packet browser page.
 */
(function () {
  "use strict";

  const AID      = document.querySelector(".page-wrapper").dataset.id;
  let currentPage = 1;
  const PER_PAGE  = 100;
  let lastTotal   = 0;

  // ── Initial load ─────────────────────────────────────────────────────────
  loadPackets();

  // ── Fetch & render ────────────────────────────────────────────────────────
  async function loadPackets() {
    const params = buildParams();
    try {
      const r = await fetch(`/api/packets/${AID}?page=${currentPage}&per_page=${PER_PAGE}&${params}`);
      const d = await r.json();
      lastTotal = d.total || 0;

      document.getElementById("packetCount").textContent =
        `${lastTotal.toLocaleString()} packet(s)`;

      const body = document.getElementById("packetBody");
      body.innerHTML = (d.data || []).map(pkt => rowHtml(pkt)).join("");

      // Click → detail panel
      body.querySelectorAll("tr").forEach((tr, i) => {
        tr.style.cursor = "pointer";
        tr.addEventListener("click", () => showDetail(d.data[i]));
      });

      renderPagination(lastTotal);
    } catch (e) {
      console.error("packets", e);
    }
  }

  // ── Table row ─────────────────────────────────────────────────────────────
  function rowHtml(p) {
    const info = buildInfo(p);
    return `<tr>
      <td>${p.index ?? ""}</td>
      <td>${fmtTs(p.timestamp)}</td>
      <td>${p.src_ip || ""}</td>
      <td>${p.src_port || ""}</td>
      <td>${p.dst_ip || ""}</td>
      <td>${p.dst_port || ""}</td>
      <td><span class="proto-badge">${p.protocol || ""}</span></td>
      <td>${p.length || 0}</td>
      <td class="muted">${info}</td>
    </tr>`;
  }

  function buildInfo(p) {
    if (p.dns_query) return `DNS: ${p.dns_query} (${p.dns_type || "?"})`;
    if (p.http_method) return `${p.http_method} ${p.http_host || ""}${p.http_uri || ""}`;
    if (p.tls_sni) return `SNI: ${p.tls_sni}`;
    if (p.arp_op)  return `ARP ${p.arp_op}`;
    if (p.tcp_flags) return `Flags: ${p.tcp_flags}`;
    if (p.icmp_type != null) return `ICMP type=${p.icmp_type} code=${p.icmp_code}`;
    return "";
  }

  // ── Detail panel ──────────────────────────────────────────────────────────
  function showDetail(p) {
    const panel = document.getElementById("detailPanel");
    panel.classList.remove("hidden");

    const sections = [];

    if (p.src_mac || p.dst_mac) {
      sections.push(layerHtml("Ethernet", [
        ["Source MAC",   p.src_mac],
        ["Dest MAC",     p.dst_mac],
      ]));
    }

    if (p.src_ip) {
      const isV6 = p.src_ip.includes(":");
      sections.push(layerHtml(isV6 ? "IPv6" : "IPv4", [
        ["Source IP",  p.src_ip],
        ["Dest IP",    p.dst_ip],
        ["TTL / Hop",  p.ttl],
        ["Protocol",   p.protocol],
      ]));
    }

    if (p.tcp_flags != null || p.src_port != null) {
      sections.push(layerHtml("TCP / UDP", [
        ["Source Port", p.src_port],
        ["Dest Port",   p.dst_port],
        ["TCP Flags",   p.tcp_flags],
      ]));
    }

    if (p.icmp_type != null) {
      sections.push(layerHtml("ICMP", [
        ["Type", p.icmp_type],
        ["Code", p.icmp_code],
      ]));
    }

    if (p.dns_query) {
      sections.push(layerHtml("DNS", [
        ["Query",        p.dns_query],
        ["Query Type",   p.dns_type],
        ["Response IPs", (p.dns_resp || []).join(", ")],
        ["R-Code",       p.dns_rcode],
      ]));
    }

    if (p.http_method) {
      sections.push(layerHtml("HTTP", [
        ["Method", p.http_method],
        ["Host",   p.http_host],
        ["URI",    p.http_uri],
      ]));
    }

    if (p.tls_sni) {
      sections.push(layerHtml("TLS", [
        ["SNI", p.tls_sni],
      ]));
    }

    if (p.arp_op) {
      sections.push(layerHtml("ARP", [
        ["Operation", p.arp_op],
        ["Sender IP",   p.src_ip],
        ["Target IP",   p.dst_ip],
      ]));
    }

    sections.push(layerHtml("Frame", [
      ["Packet #",   p.index],
      ["Timestamp",  fmtTsFull(p.timestamp)],
      ["Length",     p.length + " bytes"],
      ["Layers",     (p.layers || []).join(" / ")],
    ]));

    document.getElementById("detailContent").innerHTML =
      sections.join("") || "<p class='muted'>No details available.</p>";

    panel.scrollIntoView({ behavior: "smooth" });
  }

  function layerHtml(name, fields) {
    const rows = fields
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) =>
        `<div class="pkt-detail-field">
          <div class="pkt-detail-key">${k}</div>
          <div class="pkt-detail-val">${v}</div>
        </div>`
      ).join("");
    if (!rows) return "";
    return `<details class="pkt-detail-layer" open>
      <summary>${name}</summary>
      ${rows}
    </details>`;
  }

  // ── Filters ───────────────────────────────────────────────────────────────
  function buildParams() {
    const p = new URLSearchParams();
    const v = id => document.getElementById(id).value.trim();
    if (v("fSearch"))  p.set("q",         v("fSearch"));
    if (v("fSrcIp"))   p.set("src_ip",    v("fSrcIp"));
    if (v("fDstIp"))   p.set("dst_ip",    v("fDstIp"));
    if (v("fSrcPort")) p.set("src_port",  v("fSrcPort"));
    if (v("fDstPort")) p.set("dst_port",  v("fDstPort"));
    if (v("fProto"))   p.set("protocol",  v("fProto"));
    return p.toString();
  }

  window.applyFilters = function () { currentPage = 1; loadPackets(); };
  window.resetFilters = function () {
    ["fSearch","fSrcIp","fDstIp","fSrcPort","fDstPort","fProto"]
      .forEach(id => document.getElementById(id).value = "");
    currentPage = 1;
    loadPackets();
  };

  // ── Pagination ────────────────────────────────────────────────────────────
  function renderPagination(total) {
    const pages = Math.ceil(total / PER_PAGE);
    const el = document.getElementById("pagination");
    if (pages <= 1) { el.innerHTML = ""; return; }

    let html = "";
    if (currentPage > 1) html += btn(currentPage - 1, "‹");
    for (let p = Math.max(1, currentPage - 2); p <= Math.min(pages, currentPage + 2); p++) {
      html += btn(p, p, p === currentPage);
    }
    if (currentPage < pages) html += btn(currentPage + 1, "›");
    el.innerHTML = html;
  }

  function btn(page, label, active) {
    return `<button class="${active ? "active" : ""}"
      onclick="goPage(${page})">${label}</button>`;
  }

  window.goPage = function (p) { currentPage = p; loadPackets(); };

  // ── Utilities ─────────────────────────────────────────────────────────────
  function fmtTs(ts) {
    if (!ts) return "–";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString("en-GB", { hour12: false,
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      fractionalSecondDigits: 3
    });
  }

  function fmtTsFull(ts) {
    if (!ts) return "–";
    return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 23);
  }
})();
