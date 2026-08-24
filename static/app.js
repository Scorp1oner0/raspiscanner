const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function formatAgo(ts) {
  if (!ts) return "-";
  const secs = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (secs < 5) return "adesso";
  if (secs < 60) return `${secs}s fa`;
  return `${Math.round(secs / 60)}min fa`;
}

function renderAddressList(elId, addresses) {
  const box = $(elId);
  if (!addresses || addresses.length === 0) {
    box.innerHTML = '<div class="addr-empty">-</div>';
    return;
  }
  box.innerHTML = addresses.map((a) => `
    <div class="addr-row"><span>${escapeHtml(a.ip)}</span><span class="iface-name">${escapeHtml(a.cidr)}</span></div>
  `).join("");
}

async function refreshNetwork() {
  try {
    const res = await fetch("/api/network");
    const data = await res.json();

    $("eth-iface").textContent = data.eth.iface ? `(${data.eth.iface})` : "";
    $("eth-up").textContent = data.eth.reconfiguring
      ? "🔄 riconfigurazione in corso..."
      : (data.eth.up ? "collegato" : "non collegato");
    $("eth-mode").textContent = data.eth.mode || "-";
    renderAddressList("eth-addresses", data.eth.addresses);
    $("eth-last-change").textContent = formatAgo(data.eth.last_change);

    const errLine = $("eth-error-line");
    if (data.eth.error) {
      errLine.classList.remove("hidden");
      $("eth-error").textContent = data.eth.error;
    } else {
      errLine.classList.add("hidden");
    }

    $("wifi-iface").textContent = data.wifi.iface ? `(${data.wifi.iface})` : "";
    $("wifi-ssid").textContent = data.wifi.ssid || "-";
    renderAddressList("wifi-addresses", data.wifi.addresses);

    return data;
  } catch (e) {
    console.error("refreshNetwork", e);
  }
}

function renderPorts(openPorts) {
  if (!openPorts || openPorts.length === 0) return "-";
  return openPorts.map((p) => `${p.port}/${escapeHtml(p.service)}`).join(", ");
}

function renderAllTable(devices) {
  const tbody = $("table-all");
  $("count-all").textContent = devices.length;
  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">Nessun dato: avvia una scansione</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map((d) => `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.mac)}</td>
      <td>${escapeHtml(d.vendor)}</td>
      <td>${escapeHtml(d.hostname)}</td>
      <td>${escapeHtml(d.iface)}</td>
      <td>${escapeHtml(d.network)}</td>
      <td>${renderPorts(d.open_ports)}</td>
      <td>${d.is_camera ? '<span class="camera-badge">📹 ' + escapeHtml(d.device_type) + "</span>" : escapeHtml(d.device_type)}</td>
    </tr>
  `).join("");
}

function renderCameraTable(devices) {
  const tbody = $("table-cameras");
  $("count-cameras").textContent = devices.length;
  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">Nessuna telecamera trovata</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map((d) => `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.mac)}</td>
      <td>${escapeHtml(d.vendor)}</td>
      <td>${renderPorts(d.open_ports)}</td>
      <td>${d.rtsp_url ? '<a class="link" href="' + escapeHtml(d.rtsp_url) + '">' + escapeHtml(d.rtsp_url) + "</a>" : "-"}</td>
      <td>${d.admin_url ? '<a class="link" target="_blank" href="' + escapeHtml(d.admin_url) + '">apri</a>' : "-"}</td>
      <td>${escapeHtml((d.camera_reasons || []).join("; "))}</td>
    </tr>
  `).join("");
}

async function refreshScan() {
  try {
    const res = await fetch("/api/scan/status");
    const state = await res.json();

    const running = state.running;
    $("btn-scan-start").disabled = running;
    $("scan-status").textContent = running
      ? `Scansione in corso... (${state.progress}/${state.total || "?"}) ${state.current_ip || ""}`
      : (state.error ? `Errore: ${state.error}` : "Inattivo");

    const pct = state.total > 0 ? Math.round((state.progress / state.total) * 100) : 0;
    $("progress-fill").style.width = pct + "%";
    $("progress-label").textContent = running ? `${pct}%` : "";

    const devices = state.devices || [];
    renderAllTable(devices);
    renderCameraTable(devices.filter((d) => d.is_camera));
  } catch (e) {
    console.error("refreshScan", e);
  }
}

async function refreshReport() {
  try {
    const res = await fetch("/api/report");
    const data = await res.json();
    $("report-text").textContent = data.text || "Nessun dato.";
  } catch (e) {
    $("report-text").textContent = "Errore nel recupero del report.";
  }
}

function setupTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $("panel-all").classList.toggle("hidden", tab !== "all");
      $("panel-cameras").classList.toggle("hidden", tab !== "cameras");
      $("panel-report").classList.toggle("hidden", tab !== "report");
      if (tab === "report") refreshReport();
    });
  });
}

async function startScan() {
  const res = await fetch("/api/scan/start", { method: "POST" });
  const data = await res.json();
  if (!data.ok) {
    $("scan-status").textContent = data.message;
  }
  refreshScan();
}

async function stopScan() {
  await fetch("/api/scan/stop", { method: "POST" });
  refreshScan();
}

async function rescanNetwork() {
  const force = $("chk-force-rescan").checked;
  $("net-msg").textContent = "Riconfigurazione in corso (puo' richiedere fino a un minuto)...";
  $("btn-rescan-net").disabled = true;
  await fetch("/api/network/rescan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force }),
  });

  // Poll finche' il backend segnala reconfiguring:true invece di indovinare
  // un tempo fisso: la riconfigurazione puo' durare da pochi secondi (DHCP
  // subito disponibile) a ~30s (tutte le classi preimpostate provate).
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1500));
    const data = await refreshNetwork();
    if (data && !data.eth.reconfiguring) break;
  }
  $("net-msg").textContent = "";
  $("btn-rescan-net").disabled = false;
}

async function toggleWifiList() {
  const box = $("wifi-networks");
  if (!box.classList.contains("hidden")) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "Ricerca reti...";
  try {
    const res = await fetch("/api/wifi/networks");
    const nets = await res.json();
    if (nets.length === 0) {
      box.innerHTML = "Nessuna rete trovata (o nmcli non disponibile).";
      return;
    }
    box.innerHTML = nets.map((n) => `
      <div class="wifi-net-row">
        <span>${escapeHtml(n.ssid)} ${n.security ? "🔒" : ""}</span>
        <span>${escapeHtml(n.signal)}%</span>
      </div>
    `).join("");
  } catch (e) {
    box.innerHTML = "Errore nel recupero delle reti.";
  }
}

async function openHotspotModal() {
  $("hotspot-modal").classList.remove("hidden");
  $("hotspot-msg").textContent = "";
  await refreshHotspotStatus();
}

function closeHotspotModal() {
  $("hotspot-modal").classList.add("hidden");
}

async function refreshHotspotStatus() {
  const box = $("hotspot-status-box");
  box.textContent = "Verifica stato...";
  try {
    const res = await fetch("/api/hotspot/status");
    const data = await res.json();
    if (data.active) {
      box.innerHTML = `🟢 Attivo — SSID <strong>${escapeHtml(data.ssid)}</strong>, raggiungibile su <strong>${escapeHtml(data.ip)}:7332</strong>`;
    } else {
      box.textContent = "⚪ Non attivo";
    }
    if (!$("hotspot-ssid").value) {
      $("hotspot-ssid").value = data.ssid || data.default_ssid || "";
    }
  } catch (e) {
    box.textContent = "Errore nel recupero dello stato.";
  }
}

async function generateHotspotPassword() {
  try {
    const res = await fetch("/api/hotspot/generate-password");
    const data = await res.json();
    $("hotspot-password").value = data.password;
  } catch (e) {
    console.error("generateHotspotPassword", e);
  }
}

async function startHotspot() {
  const ssid = $("hotspot-ssid").value.trim();
  const password = $("hotspot-password").value;
  $("hotspot-msg").textContent = "Attivazione in corso...";
  try {
    const res = await fetch("/api/hotspot/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid, password }),
    });
    const data = await res.json();
    $("hotspot-msg").textContent = data.message || "";
    await refreshHotspotStatus();
    await refreshNetwork();
  } catch (e) {
    $("hotspot-msg").textContent = "Errore di rete.";
  }
}

async function stopHotspot() {
  $("hotspot-msg").textContent = "Disattivazione in corso...";
  try {
    const res = await fetch("/api/hotspot/stop", { method: "POST" });
    const data = await res.json();
    $("hotspot-msg").textContent = data.message || "";
    await refreshHotspotStatus();
    await refreshNetwork();
  } catch (e) {
    $("hotspot-msg").textContent = "Errore di rete.";
  }
}

function init() {
  setupTabs();
  $("btn-scan-start").addEventListener("click", startScan);
  $("btn-scan-stop").addEventListener("click", stopScan);
  $("btn-rescan-net").addEventListener("click", rescanNetwork);
  $("btn-wifi-list").addEventListener("click", toggleWifiList);
  $("btn-refresh-report").addEventListener("click", refreshReport);
  $("btn-open-hotspot").addEventListener("click", openHotspotModal);
  $("btn-close-hotspot").addEventListener("click", closeHotspotModal);
  $("btn-hotspot-generate").addEventListener("click", generateHotspotPassword);
  $("btn-hotspot-start").addEventListener("click", startHotspot);
  $("btn-hotspot-stop").addEventListener("click", stopHotspot);
  $("hotspot-modal").addEventListener("click", (ev) => {
    if (ev.target.id === "hotspot-modal") closeHotspotModal();
  });

  refreshNetwork();
  refreshScan();
  setInterval(refreshNetwork, 5000);
  setInterval(refreshScan, 1500);
}

document.addEventListener("DOMContentLoaded", init);
