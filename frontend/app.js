
const API = "http://localhost:8000";

const SCAN_STEPS = [
  "Resolving DNS records",
  "Probing HTTP headers",
  "Checking TLS certificate",
  "Running Nikto web scan",
  "Scanning ports with nmap",
  "Fingerprinting technologies",
  "Running AI analysis",
  "Enriching with Searchsploit",
  "Looking up Metasploit modules",
  "Compiling report",
];

let chartDonut, chartHosts, chartOwasp;
let stepInterval;

function showTab(name) {
  ["scan","history","dashboard"].forEach(t => {
    document.getElementById("tab-" + t).classList.toggle("hidden", t !== name);
    document.getElementById("pill-" + t).classList.toggle("active", t === name);
  });
  if (name === "history")   loadHistory();
  if (name === "dashboard") loadDashboard();
}

async function startScan() {
  const url = document.getElementById("url").value.trim();
  if (!url) { document.getElementById("url").focus(); return; }
  const btn = document.getElementById("scan-btn");
  btn.disabled = true;
  show("scan-live"); hide("kpi-grid"); hide("findings-area");
  document.getElementById("findings-area").innerHTML = "";
  animateSteps();
  try {
    const res = await fetch(API + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      alert("Scan failed: " + (e.detail || res.statusText));
      return;
    }
    renderResults(await res.json());
  } catch(e) {
    alert("Cannot reach backend. Make sure the server is running.");
  } finally {
    btn.disabled = false;
    document.getElementById("fill").style.width = "100%";
    document.getElementById("step-label").textContent = "Scan complete.";
    clearInterval(stepInterval);
    renderSteps(SCAN_STEPS.length);
  }
}

function animateSteps() {
  const fill  = document.getElementById("fill");
  const label = document.getElementById("step-label");
  fill.style.width = "0%";
  renderSteps(0);
  let i = 0;
  stepInterval = setInterval(() => {
    i++;
    fill.style.width = Math.min(i * 9, 88) + "%";
    label.textContent = SCAN_STEPS[Math.min(i - 1, SCAN_STEPS.length - 1)] + "...";
    renderSteps(i);
    if (i >= SCAN_STEPS.length) clearInterval(stepInterval);
  }, 1100);
}

function renderSteps(currentIdx) {
  const el = document.getElementById("step-list");
  if (!el) return;
  el.innerHTML = SCAN_STEPS.map((s, i) => {
    let cls = "pending";
    let txt = s;
    if (i < currentIdx)       { cls = "done";   txt = s + " \u2713"; }
    else if (i === currentIdx) { cls = "active"; txt = s + "..."; }
    return `<div class="step-item ${cls}"><div class="step-dot"></div><span>${esc(txt)}</span></div>`;
  }).join("");
}

function renderResults(data) {
  const s = data.summary || {};
  document.getElementById("kpi-grid").innerHTML =
    kpi("Critical", s.critical || 0, "crit") +
    kpi("High",     s.high     || 0, "high") +
    kpi("Medium",   s.medium   || 0, "med")  +
    kpi("Low / Info", (s.low||0)+(s.info||0), "low");
  show("kpi-grid");

  const area = document.getElementById("findings-area");
  area.innerHTML = "";

  // Nikto banner
  const nikto = data.nikto || {};
  if (nikto.total_issues > 0) {
    const items = (nikto.findings || []).map(f =>
      `<div class="nikto-item">
        <span class="nikto-method">${esc(f.method)}</span>
        <span>${esc(f.msg)}</span>
        ${f.url ? `<code style="font-size:10px;color:var(--text3);">${esc(f.url)}</code>` : ""}
      </div>`
    ).join("");
    area.innerHTML += `
      <div class="nikto-banner">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        Nikto found <strong style="margin:0 3px;">${nikto.total_issues}</strong> web vulnerabilities
        <button onclick="toggleSection('nikto-list')">Show details</button>
      </div>
      <div class="nikto-list hidden" id="nikto-list">${items}</div>`;
  }

  // cPanel/WHM detection banner
  const cpanel = data.cpanel || {};
  if (cpanel.cpanel_detected || cpanel.whm_detected) {
    const portList = (cpanel.exposed_ports || [])
      .map(p => p.port + " (" + p.label + ")")
      .join(", ");
    area.innerHTML += `
      <div class="cpanel-banner">
        <div class="cpanel-banner-top">
          <span class="cpanel-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
          </span>
          <span class="cpanel-title">cPanel / WHM Detected</span>
          <div class="cpanel-badges">
            ${cpanel.cpanel_detected ? '<span class="cpanel-badge">cPanel</span>' : ""}
            ${cpanel.whm_detected    ? '<span class="cpanel-badge whm">WHM</span>'   : ""}
            ${cpanel.webmail_detected? '<span class="cpanel-badge">Webmail</span>'   : ""}
          </div>
        </div>
        ${cpanel.version ? `<div class="cpanel-meta">Version: <strong>${esc(cpanel.version)}</strong></div>` : ""}
        ${portList ? `<div class="cpanel-meta">Exposed ports: <code>${esc(portList)}</code></div>` : ""}
        ${cpanel.exposed_paths && cpanel.exposed_paths.length ? `
          <div class="cpanel-meta">Accessible at:
            ${cpanel.exposed_paths.slice(0,3).map(p =>
              `<a href="${esc(p)}" target="_blank" class="cpanel-link">${esc(p)}</a>`
            ).join(" ")}
          </div>` : ""}
        ${cpanel.searchsploit && cpanel.searchsploit.length ? `
          <div class="cpanel-exploits">
            <div class="cpanel-exploits-label">
              ${cpanel.searchsploit.length} public exploit${cpanel.searchsploit.length > 1 ? "s" : ""} found on Exploit-DB
            </div>
            ${cpanel.searchsploit.map(e => `
              <div class="exploit-row">
                <span class="edb-badge">EDB</span>
                <span class="exploit-type">${esc(e.type || "")} / ${esc(e.platform || "")}</span>
                <a href="${esc(e.url || "#")}" target="_blank" class="exploit-link">${esc(e.title || "")}</a>
              </div>`).join("")}
          </div>` : ""}
      </div>`;
  }

  // Open ports
  const ports = data.ports || {};
  const openPorts = ports.open_ports || [];
  const riskySet  = new Set((ports.risky_ports || []).map(r => r.port));
  if (openPorts.length > 0) {
    const rows = openPorts.map(p =>
      `<div class="port-row">
        <span class="port-num">${esc(String(p.port))}/${esc(p.protocol)}</span>
        <span class="port-service">${esc(p.service)} ${esc(p.product)} ${esc(p.version)}</span>
        ${riskySet.has(p.port) ? `<span class="port-risky">risky</span>` : ""}
      </div>`
    ).join("");
    area.innerHTML += `
      <div class="ports-card">
        <div class="ports-card-title">Open ports &mdash; ${openPorts.length} found</div>
        ${rows}
      </div>`;
  }

  // Technology exploit references
  const techExploits = data.tech_exploits || {};
  const techMsf      = data.tech_msf      || {};
  const allTechs = new Set([...Object.keys(techExploits), ...Object.keys(techMsf)]);
  if (allTechs.size > 0) {
    area.innerHTML += `<div class="section-divider">Technology exploit references</div>`;
    allTechs.forEach(tech => {
      const ss  = techExploits[tech] || [];
      const msf = techMsf[tech]      || [];
      if (!ss.length && !msf.length) return;
      area.innerHTML += `
        <div class="tech-exploit-card">
          <div class="tech-exploit-title">${esc(tech)}</div>
          ${ss.map(e => exploitRow(e)).join("")}
          ${msf.map(m => msfRow(m)).join("")}
        </div>`;
    });
  }

  // AI Findings
  const order = ["critical","high","medium","low","info"];
  const sorted = [...(data.findings || [])].sort(
    (a,b) => order.indexOf(a.severity) - order.indexOf(b.severity)
  );
  area.innerHTML += `
    <div class="findings-bar">
      <span class="findings-bar-title">AI findings</span>
      <span class="findings-count">${sorted.length} issues</span>
    </div>`;

  sorted.forEach(f => {
    const sev  = (f.severity || "info").toLowerCase();
    const owaspCode = f.owasp ? f.owasp.split(" - ")[0] : "";
    const hasExploits = (f.searchsploit && f.searchsploit.length) || (f.msf_modules && f.msf_modules.length);
    area.innerHTML += `
      <div class="finding sev-${sev}">
        <div class="finding-top">
          <span class="sev-badge ${sev}">${sev}</span>
          ${owaspCode ? `<span class="tag owasp">${esc(owaspCode)}</span>` : ""}
          ${f.cwe  ? `<span class="tag">${esc(f.cwe)}</span>`  : ""}
          ${f.cve  ? `<span class="tag">${esc(f.cve)}</span>`  : ""}
          ${f.category ? `<span class="tag">${esc(f.category)}</span>` : ""}
          <span class="finding-title-txt">${esc(f.title)}</span>
        </div>
        <div class="finding-desc">${esc(f.description)}</div>
        ${f.evidence ? `<div class="evidence">${esc(f.evidence)}</div>` : ""}
        <div class="rec-row">
          <div class="rec-bar"></div>
          <span class="rec-text">${esc(f.recommendation)}</span>
        </div>
        ${hasExploits ? `
          <div class="exploit-section">
            <div class="exploit-section-label">Exploit references</div>
            ${(f.searchsploit||[]).map(e => exploitRow(e)).join("")}
            ${(f.msf_modules ||[]).map(m => msfRow(m)).join("")}
          </div>` : ""}
      </div>`;
  });

  if (data.id) {
    area.innerHTML += `
      <button class="pdf-btn" onclick="exportPDF(${data.id})">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        Download PDF report
      </button>`;
  }
  show("findings-area");
}

function exploitRow(e) {
  return `<div class="exploit-row">
    <span class="edb-badge">EDB</span>
    <span class="exploit-type">${esc(e.type||"")} / ${esc(e.platform||"")}</span>
    <a href="${esc(e.url||"#")}" target="_blank" class="exploit-link">${esc(e.title||"")}</a>
    <span class="exploit-date">${esc(e.date||"")}</span>
  </div>`;
}

function msfRow(m) {
  const rankCol = {excellent:"#f87171",great:"#fb923c",good:"#4ade80",normal:"#60a5fa"}[
    (m.rank||"normal").toLowerCase()
  ] || "#94a3b8";
  return `<div class="exploit-row">
    <span class="msf-badge">MSF</span>
    <span class="exploit-type" style="color:${rankCol};font-weight:500;">${esc(m.rank||"")}</span>
    <span class="exploit-link" style="font-family:var(--mono);font-size:11px;color:var(--text2);">${esc(m.fullname||"")}</span>
    <span class="exploit-date">${esc((m.description||"").slice(0,50))}</span>
  </div>`;
}

function toggleSection(id) {
  const el  = document.getElementById(id);
  const btn = el.previousElementSibling.querySelector("button");
  const hidden = el.classList.contains("hidden");
  el.classList.toggle("hidden", !hidden);
  if (btn) btn.textContent = hidden ? "Hide details" : "Show details";
}

async function loadHistory() {
  const el = document.getElementById("history-list");
  el.innerHTML = `<p class="muted-msg">Loading...</p>`;
  try {
    const rows = await fetch(API + "/history").then(r => r.json());
    if (!rows.length) { el.innerHTML = `<p class="muted-msg">No scans yet.</p>`; return; }
    el.innerHTML = rows.map(r => {
      const s = r.summary || {};
      const badges = [
        s.critical ? `<span class="sev-badge critical">${s.critical} crit</span>` : "",
        s.high     ? `<span class="sev-badge high">${s.high} high</span>`         : "",
        s.medium   ? `<span class="sev-badge medium">${s.medium} med</span>`      : "",
      ].join("");
      return `
        <div class="history-row">
          <div class="history-info">
            <span class="history-host">${esc(r.hostname)}</span>
            <span class="history-url">${esc(r.url)}</span>
            <span class="history-date">${new Date(r.scanned_at).toLocaleString()}</span>
          </div>
          <div class="history-badges">${badges}</div>
          <div class="history-actions">
            <button onclick="viewScan(${r.id})">View</button>
            <button class="del-btn" onclick="deleteScan(${r.id})">Delete</button>
          </div>
        </div>`;
    }).join("");
  } catch(e) {
    el.innerHTML = `<p style="color:#f87171;font-size:12px;">Failed to load history.</p>`;
  }
}

async function viewScan(id) {
  const data = await fetch(API + "/history/" + id).then(r => r.json());
  showTab("scan");
  document.getElementById("url").value = data.url;
  renderResults(data);
}

async function deleteScan(id) {
  if (!confirm("Delete this scan?")) return;
  await fetch(API + "/history/" + id, { method: "DELETE" });
  loadHistory();
}

async function exportPDF(id) {
  window.open(API + "/report/" + id, "_blank");
}

async function loadDashboard() {
  try {
    const scans = await fetch(API + "/history").then(r => r.json());
    if (!scans.length) {
      document.getElementById("dash-kpis").innerHTML =
        `<p class="muted-msg" style="grid-column:1/-1;">No scans yet. Run a scan first.</p>`;
      return;
    }
    const totals = {critical:0,high:0,medium:0,low:0,info:0};
    const hostCounts = {};
    const owaspCounts = {};
    const OWASP_MAP = {
      "A01:2025":"Broken Access Control","A02:2025":"Security Misconfiguration",
      "A03:2025":"Supply Chain Failures","A04:2025":"Cryptographic Failures",
      "A05:2025":"Injection","A06:2025":"Insecure Design",
      "A07:2025":"Authentication Failures","A08:2025":"Data Integrity Failures",
      "A09:2025":"Logging Failures","A10:2025":"Exceptional Conditions",
    };
    Object.keys(OWASP_MAP).forEach(k => owaspCounts[k] = 0);

    for (const s of scans) {
      Object.entries(s.summary||{}).forEach(([k,v]) => totals[k]=(totals[k]||0)+v);
      hostCounts[s.hostname] = (hostCounts[s.hostname]||0)+1;
    }

    // Fetch findings for OWASP chart
    for (const s of scans.slice(0,10)) {
      try {
        const full = await fetch(API + "/history/" + s.id).then(r => r.json());
        (full.findings||[]).forEach(f => {
          if (f.owasp) {
            const code = f.owasp.split(" - ")[0].trim();
            if (owaspCounts[code] !== undefined) owaspCounts[code]++;
          }
        });
      } catch(e) {}
    }

    document.getElementById("dash-kpis").innerHTML =
      kpi("Total scans",  scans.length,       "low")  +
      kpi("Critical",     totals.critical||0,  "crit") +
      kpi("High",         totals.high||0,      "high") +
      kpi("Medium",       totals.medium||0,    "med");

    Chart.defaults.color = "#4a5568";
    Chart.defaults.borderColor = "#1e2d42";

    if (chartDonut) chartDonut.destroy();
    chartDonut = new Chart(document.getElementById("chart-donut"), {
      type: "doughnut",
      data: {
        labels: ["Critical","High","Medium","Low","Info"],
        datasets: [{
          data: [totals.critical||0,totals.high||0,totals.medium||0,totals.low||0,totals.info||0],
          backgroundColor: ["#f87171","#fb923c","#60a5fa","#4ade80","#4a5568"],
          borderWidth: 2, borderColor: "#0d1117",
        }],
      },
      options: {
        cutout:"68%",
        plugins:{legend:{position:"bottom",labels:{font:{size:11},color:"#94a3b8",padding:12}}},
      },
    });

    const topHosts = Object.entries(hostCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
    if (chartHosts) chartHosts.destroy();
    chartHosts = new Chart(document.getElementById("chart-hosts"), {
      type:"bar",
      data:{
        labels: topHosts.map(h=>h[0]),
        datasets:[{label:"Scans",data:topHosts.map(h=>h[1]),backgroundColor:"#1e3a5f",borderColor:"#4a9eff",borderWidth:1,borderRadius:4}],
      },
      options:{
        indexAxis:"y",
        plugins:{legend:{display:false}},
        scales:{
          x:{grid:{color:"#1e2d42"},ticks:{color:"#4a5568",font:{size:11}}},
          y:{grid:{display:false},ticks:{color:"#94a3b8",font:{size:11}}},
        },
      },
    });

    if (chartOwasp) chartOwasp.destroy();
    const owaspKeys = Object.keys(OWASP_MAP);
    chartOwasp = new Chart(document.getElementById("chart-owasp"), {
      type:"bar",
      data:{
        labels: owaspKeys,
        datasets:[{
          label:"Findings",
          data: owaspKeys.map(k=>owaspCounts[k]||0),
          backgroundColor:["#f87171","#fb923c","#c084fc","#60a5fa","#34d399","#4ade80","#fbbf24","#38bdf8","#94a3b8","#1e293b"],
          borderRadius:4,borderWidth:0,
        }],
      },
      options:{
        plugins:{
          legend:{display:false},
          tooltip:{callbacks:{
            title:items=>OWASP_MAP[items[0].label]||items[0].label,
            label:item=>item.raw+" findings",
          }},
        },
        scales:{
          x:{grid:{display:false},ticks:{color:"#4a5568",font:{size:10}}},
          y:{grid:{color:"#1e2d42"},beginAtZero:true,ticks:{color:"#4a5568",font:{size:11}}},
        },
      },
    });

  } catch(e) {
    document.getElementById("dash-kpis").innerHTML =
      `<p style="color:#f87171;font-size:12px;grid-column:1/-1;">Failed: ${e}</p>`;
  }
}

function kpi(label, val, cls) {
  return `<div class="kpi ${cls}"><div class="kpi-label">${label}</div><div class="kpi-val">${val}</div></div>`;
}
function esc(s) {
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function show(id){ document.getElementById(id).classList.remove("hidden"); }
function hide(id){ document.getElementById(id).classList.add("hidden"); }
