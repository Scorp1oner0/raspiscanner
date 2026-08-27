const $ = (id) => document.getElementById(id);

// Popolato una volta in init() da /api/settings/me: la UI dei ruoli (sezione
// gestione utenti visibile solo agli admin, dropdown cambio password) si basa
// su questo, ma e' solo un aiuto visivo — l'enforcement vero e' lato server
// (@require_role in raspi-scanner.py), qui serve solo a non mostrare
// controlli che il backend rifiuterebbe comunque con 403.
let CURRENT_USER = { username: null, role: null };

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function formatAgo(ts) {
  if (!ts) return "-";
  const secs = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  return `${Math.round(secs / 60)}min ago`;
}

function renderAddressList(elId, addresses) {
  const box = $(elId);
  renderAddressListInto(box, addresses);
}

function renderAddressListInto(box, addresses) {
  if (!addresses || addresses.length === 0) {
    box.innerHTML = '<div class="addr-empty">-</div>';
    return;
  }
  box.innerHTML = addresses.map((a) => `
    <div class="addr-row"><span>${escapeHtml(a.ip)}</span><span class="iface-name">${escapeHtml(a.cidr)}</span></div>
  `).join("");
}

// Wi-Fi interfaces known from the last refresh: used to pre-fill the
// hotspot select without a separate network call.
let lastWifiIfaces = [];

function renderWifiBoxes(wifiByIface) {
  const container = $("wifi-boxes");
  const ifaces = Object.keys(wifiByIface || {}).sort();
  lastWifiIfaces = ifaces;

  if (ifaces.length === 0) {
    container.innerHTML = '<div class="net-box net-box-empty">📶 No Wi-Fi adapter detected</div>';
    return;
  }

  // Only recreate the boxes if the interface set changed, so the
  // open/closed state of the "visible networks" panel survives each poll.
  const existingIfaces = Array.from(container.querySelectorAll(".net-box[data-iface]")).map((b) => b.dataset.iface);
  const sameSet = existingIfaces.length === ifaces.length && existingIfaces.every((v, i) => v === ifaces[i]);
  if (!sameSet) {
    container.innerHTML = ifaces.map((iface) => `
      <div class="net-box" id="net-wifi-${escapeHtml(iface)}" data-iface="${escapeHtml(iface)}">
        <div class="net-title">📶 Wi-Fi <span class="iface-name">(${escapeHtml(iface)})</span></div>
        <div class="net-line">SSID: <span class="wifi-ssid">-</span></div>
        <div class="net-line">Addresses:</div>
        <div class="addr-list wifi-addresses"><div class="addr-empty">-</div></div>
        <button class="btn small btn-wifi-list" data-iface="${escapeHtml(iface)}">Visible networks</button>
        <button class="btn small btn-open-hotspot" data-iface="${escapeHtml(iface)}">📡 Hotspot</button>
        <div class="wifi-list hidden wifi-networks-panel"></div>
      </div>
    `).join("");
  }

  for (const iface of ifaces) {
    const info = wifiByIface[iface];
    const box = document.getElementById(`net-wifi-${iface}`);
    if (!box) continue;
    box.querySelector(".wifi-ssid").textContent = info.ssid || "-";
    renderAddressListInto(box.querySelector(".wifi-addresses"), info.addresses);
  }
}

function renderEthCandidates(candidates) {
  const box = $("eth-choose-network");
  const list = $("eth-candidates");
  if (!candidates || candidates.length === 0) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  list.innerHTML = candidates.map((c) => `
    <button class="btn small btn-choose-network" data-cidr="${escapeHtml(c.cidr)}">
      ${escapeHtml(c.cidr)} <span class="iface-name">(${c.hosts_found} host${c.hosts_found === 1 ? "" : "s"})</span>
    </button>
  `).join("");
}

async function chooseNetwork(cidr) {
  $("net-msg").textContent = `Selecting ${cidr}...`;
  try {
    const res = await fetch("/api/network/choose", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidr }),
    });
    const data = await res.json();
    $("net-msg").textContent = data.message || "";
  } catch (e) {
    $("net-msg").textContent = "Network error.";
  }
  await refreshNetwork();
}

function renderVpnBoxes(vpnByIface) {
  const container = $("vpn-boxes");
  const ifaces = Object.keys(vpnByIface || {}).sort();

  if (ifaces.length === 0) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = ifaces.map((iface) => {
    const info = vpnByIface[iface];
    const noarpNote = info.noarp
      ? '<div class="net-line">Discovery: <span>ICMP (no ARP on this link)</span></div>'
      : "";
    return `
      <div class="net-box">
        <div class="net-title">🔒 VPN <span class="iface-name">(${escapeHtml(iface)})</span></div>
        <div class="net-line">Status: <span>${info.up ? "connected" : "disconnected"}</span></div>
        <div class="net-line">Addresses:</div>
        <div class="addr-list">${info.addresses && info.addresses.length
          ? info.addresses.map((a) => `<div class="addr-row"><span>${escapeHtml(a.ip)}</span><span class="iface-name">${escapeHtml(a.cidr)}</span></div>`).join("")
          : '<div class="addr-empty">-</div>'}</div>
        ${noarpNote}
      </div>
    `;
  }).join("");
}

async function refreshNetwork() {
  try {
    const res = await fetch("/api/network");
    const data = await res.json();

    $("eth-iface").textContent = data.eth.iface ? `(${data.eth.iface})` : "";
    $("eth-up").textContent = data.eth.reconfiguring
      ? "🔄 reconfiguring..."
      : (data.eth.up ? "connected" : "disconnected");
    $("eth-mode").textContent = data.eth.mode || "-";
    $("eth-probing-line").classList.toggle("hidden", !data.eth.probing);
    if (data.eth.probing) {
      $("eth-probing-index").textContent = data.eth.probe_index ?? "-";
      $("eth-probing-total").textContent = data.eth.probe_total ?? "-";
      $("eth-probing-cidr").textContent = data.eth.probe_cidr || "-";
      $("eth-probing-timeout").textContent = data.eth.probe_timeout ?? "-";
    }
    renderAddressList("eth-addresses", data.eth.addresses);
    $("eth-last-change").textContent = formatAgo(data.eth.last_change);
    renderEthCandidates(data.eth.candidates);

    const errLine = $("eth-error-line");
    if (data.eth.error) {
      errLine.classList.remove("hidden");
      $("eth-error").textContent = data.eth.error;
    } else {
      errLine.classList.add("hidden");
    }

    renderWifiBoxes(data.wifi);
    renderVpnBoxes(data.vpn);

    return data;
  } catch (e) {
    console.error("refreshNetwork", e);
  }
}

function renderNetworkCell(d) {
  const base = escapeHtml(d.network) || "-";
  // vlan_id (P4): quasi sempre assente (la maggior parte delle porte sono
  // "access", lo switch toglie il tag 802.1Q prima di consegnare il
  // frame) — mostrato solo quando c'e' davvero, non una colonna sempre
  // visibile e vuota per il 99% degli scan.
  if (d.vlan_id === null || d.vlan_id === undefined) return base;
  return `${base} <span class="vlan-badge" title="802.1Q VLAN tag seen on this device's traffic">VLAN ${d.vlan_id}</span>`;
}

function renderPorts(device) {
  const openPorts = device.open_ports;
  if (openPorts && openPorts.length > 0) {
    return openPorts.map((p) => `${p.port}/${escapeHtml(p.service)}`).join(", ");
  }
  if (device.onvif_xaddr) {
    // No ports scanned because the IP isn't reachable over unicast on
    // this network: the only evidence is the multicast reply.
    return '<span class="badge badge-warn">ONVIF multicast</span>';
  }
  return "-";
}

function renderModelCell(d) {
  if (!d.model) return "-";
  // model_source e' sempre valorizzato quando model lo e' (scan_engine
  // popola entrambi insieme): il nome non e' mai indovinato/pattern-matchato
  // da altri campi, e' esattamente cio' che il dispositivo ha dichiarato di
  // se stesso — il tooltip lo rende esplicito invece di lasciarlo ambiguo.
  const sourceLabel = d.model_source === "onvif" ? "self-reported via ONVIF"
    : d.model_source === "mdns" ? "self-reported via mDNS/Bonjour"
    : null;
  const title = sourceLabel ? ` title="${escapeHtml(sourceLabel)}"` : "";
  return `<span${title}>${escapeHtml(d.model)}</span>`;
}

function renderVendorCell(d) {
  // vendor_source (P4 richer vendor fingerprinting): "oui" (default MAC
  // lookup) / "banner" (fallback quando l'OUI non sa nulla, indovinato dal
  // banner HTTP del dispositivo) / "onvif" (auto-dichiarato, il piu'
  // affidabile) — reso esplicito invece di mostrare lo stesso nome vendor
  // a prescindere da quanto sia affidabile la fonte.
  const sourceLabel = d.vendor_source === "onvif" ? "self-reported via ONVIF"
    : d.vendor_source === "banner" ? "guessed from the device's own HTTP banner (MAC vendor unknown)"
    : d.vendor_source === "oui" ? "from MAC vendor lookup (OUI database)"
    : null;
  const title = sourceLabel ? ` title="${escapeHtml(sourceLabel)}"` : "";
  return `<span${title}>${escapeHtml(d.vendor)}</span>`;
}

function deviceTypeCell(d) {
  if (d.network_mismatch) {
    return '<span class="badge badge-warn">⚠️ ' + escapeHtml(d.device_type) + ' — out of network</span>';
  }
  if (d.is_camera) {
    return '<span class="badge badge-ok">📹 ' + escapeHtml(d.device_type) + '</span>';
  }
  return escapeHtml(d.device_type);
}

function renderAllTable(devices) {
  const tbody = $("table-all");
  $("count-all").textContent = devices.length;
  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty">No data yet — start a scan</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map((d) => `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.mac) || "-"}</td>
      <td>${renderVendorCell(d)}</td>
      <td>${renderModelCell(d)}</td>
      <td>${escapeHtml(d.hostname)}</td>
      <td>${escapeHtml(d.iface)}</td>
      <td>${renderNetworkCell(d)}</td>
      <td>${renderPorts(d)}</td>
      <td>${deviceTypeCell(d)}</td>
    </tr>
  `).join("");
}

function renderCameraRowOk(d) {
  return `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.mac)}</td>
      <td>${renderVendorCell(d)}</td>
      <td>${renderModelCell(d)}</td>
      <td>${renderPorts(d)}</td>
      <td>${d.rtsp_url ? '<a class="link" title="Guessed from an open RTSP port, not a verified working stream" href="' + escapeHtml(d.rtsp_url) + '">' + escapeHtml(d.rtsp_url) + "</a>" : "-"}</td>
      <td>${d.admin_url ? '<a class="link" title="Guessed from an open web port, not confirmed to be the device\'s admin panel" target="_blank" href="' + escapeHtml(d.admin_url) + '">open</a>' : "-"}</td>
      <td>${escapeHtml((d.reasons || []).join("; "))}</td>
    </tr>
  `;
}

function renderCameraRowMismatch(d) {
  return `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${renderVendorCell(d)}</td>
      <td>${renderModelCell(d)}</td>
      <td>${escapeHtml(d.iface) || "-"}</td>
      <td>${d.onvif_xaddr ? '<a class="link" href="' + escapeHtml(d.onvif_xaddr) + '">' + escapeHtml(d.onvif_xaddr) + "</a>" : "-"}</td>
    </tr>
  `;
}

function renderCameraTables(devices) {
  const ok = devices.filter((d) => !d.network_mismatch);
  const mismatch = devices.filter((d) => d.network_mismatch);

  $("count-cameras").textContent = devices.length;
  $("count-cameras-ok").textContent = ok.length;
  $("count-cameras-mismatch").textContent = mismatch.length;

  const tbodyOk = $("table-cameras-ok");
  tbodyOk.innerHTML = ok.length === 0
    ? '<tr><td colspan="7" class="empty">No cameras found</td></tr>'
    : ok.map(renderCameraRowOk).join("");

  const showMismatch = mismatch.length > 0;
  $("mismatch-group-title").classList.toggle("hidden", !showMismatch);
  $("mismatch-group-note").classList.toggle("hidden", !showMismatch);
  $("table-mismatch-wrap").classList.toggle("hidden", !showMismatch);
  if (showMismatch) {
    $("table-cameras-mismatch").innerHTML = mismatch.map(renderCameraRowMismatch).join("");
  }
}

function updateStatTile(id, value) {
  $(id).textContent = value;
  $(id).closest(".stat-tile").classList.toggle("stat-tile-zero", value === 0);
}

function refreshStats(devices) {
  const cameras = devices.filter((d) => d.is_camera);
  const mismatch = devices.filter((d) => d.network_mismatch);
  const infra = devices.filter((d) => d.is_network_infra);

  updateStatTile("stat-devices", devices.length);
  updateStatTile("stat-cameras", cameras.length);
  updateStatTile("stat-mismatch", mismatch.length);
  updateStatTile("stat-infra", infra.length);
}

async function refreshSecurityStats() {
  try {
    const res = await fetch("/api/security/summary");
    const counts = await res.json();
    updateStatTile("stat-critical", counts.critical || 0);
    updateStatTile("stat-high", counts.high || 0);
    updateStatTile("stat-medium", counts.medium || 0);
  } catch (e) {
    console.error("refreshSecurityStats", e);
  }
}

async function refreshScan() {
  try {
    const res = await fetch("/api/scan/status");
    const state = await res.json();

    const running = state.running;
    $("btn-scan-start").disabled = running;
    $("scan-status").textContent = running
      ? `Scanning... (${state.progress}/${state.total || "?"}) ${state.current_ip || ""}`
      : (state.error ? `Error: ${state.error}` : "Idle");

    const pct = state.total > 0 ? Math.round((state.progress / state.total) * 100) : 0;
    $("progress-fill").style.width = pct + "%";
    $("progress-label").textContent = running ? `${pct}%` : "";

    const devices = state.devices || [];
    renderAllTable(devices);
    renderCameraTables(devices.filter((d) => d.is_camera));
    refreshStats(devices);
  } catch (e) {
    console.error("refreshScan", e);
  }
}

function renderReportText(text) {
  // Evidenzia solo righe con un prefisso ESATTO e noto (il testo e'
  // sempre escaped PRIMA di questo controllo, quindi anche se un campo
  // controllato dal dispositivo scansionato coincidesse per caso con uno
  // di questi prefissi non ci sarebbe nessun rischio, solo una riga
  // colorata per errore — puramente cosmetico, non un problema di
  // sicurezza).
  const escaped = escapeHtml(text);
  const html = escaped.split("\n").map((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("Critical:")) return `<span class="sev-line sev-critical">${line}</span>`;
    if (trimmed.startsWith("High:")) return `<span class="sev-line sev-high">${line}</span>`;
    if (trimmed.startsWith("Medium:")) return `<span class="sev-line sev-medium">${line}</span>`;
    if (trimmed.startsWith("Low:")) return `<span class="sev-line sev-low">${line}</span>`;
    if (trimmed.startsWith("⚠")) return `<span class="sev-line sev-warn">${line}</span>`;
    return line;
  }).join("\n");
  $("report-text").innerHTML = html;
}

async function refreshReport() {
  try {
    const res = await fetch("/api/report");
    const data = await res.json();
    renderReportText(data.text || "No data.");
  } catch (e) {
    $("report-text").textContent = "Failed to fetch the report.";
  }
}

function formatTimestamp(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

async function refreshHistory() {
  try {
    const res = await fetch("/api/history/scans?limit=20");
    const data = await res.json();
    const scans = data.scans || [];

    $("table-history-scans").innerHTML = scans.length
      ? scans.map((s) => `
          <tr>
            <td>${s.id}</td>
            <td>${formatTimestamp(s.started_at)}</td>
            <td>${formatTimestamp(s.finished_at)}</td>
            <td>${s.device_count}</td>
          </tr>
        `).join("")
      : '<tr><td colspan="4" class="empty">No saved scans yet — run one first.</td></tr>';

    const options = scans.map((s) => `<option value="${s.id}">#${s.id} — ${formatTimestamp(s.started_at)}</option>`).join("");
    $("compare-old-scan").innerHTML = options;
    $("compare-new-scan").innerHTML = options;
    if (scans.length > 1) {
      $("compare-old-scan").value = scans[1].id;
      $("compare-new-scan").value = scans[0].id;
    }
  } catch (e) {
    console.error("refreshHistory (scans)", e);
  }

  try {
    const res = await fetch("/api/history/assets?limit=500");
    const data = await res.json();
    const assets = data.assets || [];
    $("table-history-assets").innerHTML = assets.length
      ? assets.map((a) => `
          <tr>
            <td>${escapeHtml(a.mac)}</td>
            <td>${escapeHtml(a.last_vendor) || "-"}</td>
            <td>${escapeHtml(a.last_device_type) || "-"}</td>
            <td>${formatTimestamp(a.first_seen)}</td>
            <td>${formatTimestamp(a.last_seen)}</td>
            <td>${a.times_seen}</td>
          </tr>
        `).join("")
      : '<tr><td colspan="6" class="empty">No known assets yet.</td></tr>';
  } catch (e) {
    console.error("refreshHistory (assets)", e);
  }
}

async function compareScans() {
  const oldId = $("compare-old-scan").value;
  const newId = $("compare-new-scan").value;
  const box = $("compare-result");
  if (!oldId || !newId) {
    box.style.display = "block";
    box.textContent = "Pick two scans to compare.";
    return;
  }
  box.style.display = "block";
  box.textContent = "Comparing...";
  try {
    const res = await fetch(`/api/history/compare?old=${oldId}&new=${newId}`);
    const diff = await res.json();
    const lines = [];
    lines.push(`Comparing scan #${oldId} -> #${newId}`);
    lines.push("");
    lines.push(`${diff.added.length} device(s) added:`);
    diff.added.forEach((d) => lines.push(`  + ${d.ip} (${d.mac}) ${d.vendor || ""}`));
    lines.push("");
    lines.push(`${diff.removed.length} device(s) removed:`);
    diff.removed.forEach((d) => lines.push(`  - ${d.ip} (${d.mac}) ${d.vendor || ""}`));
    lines.push("");
    lines.push(`${diff.changed.length} device(s) changed:`);
    diff.changed.forEach((c) => lines.push(`  ~ ${c.new.ip} (${c.mac}): ${c.fields.join(", ")}`));
    box.textContent = lines.join("\n");
  } catch (e) {
    box.textContent = "Failed to compare scans.";
  }
}

async function refreshWebhookConfig() {
  try {
    const res = await fetch("/api/settings/webhook");
    if (!res.ok) return;  // non-admin: 403, il campo resta nascosto insieme al resto della sezione
    const data = await res.json();
    $("webhook-url").value = data.url || "";
    $("webhook-enabled").checked = !!data.enabled;
  } catch (e) {
    console.error("refreshWebhookConfig", e);
  }
}

async function saveWebhookConfig() {
  const msg = $("webhook-msg");
  msg.textContent = "Saving...";
  try {
    const res = await fetch("/api/settings/webhook", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: $("webhook-url").value.trim(), enabled: $("webhook-enabled").checked }),
    });
    const data = await res.json();
    msg.textContent = data.message || "";
  } catch (e) {
    msg.textContent = "Network error.";
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
      $("panel-history").classList.toggle("hidden", tab !== "history");
      $("panel-settings").classList.toggle("hidden", tab !== "settings");
      if (tab === "report") refreshReport();
      if (tab === "history") refreshHistory();
      if (tab === "settings") refreshUsers();
    });
  });
}

async function refreshUsers() {
  $("settings-my-account").textContent = CURRENT_USER.username
    ? `Signed in as ${CURRENT_USER.username} (role: ${CURRENT_USER.role}).`
    : "";

  const isAdmin = CURRENT_USER.role === "admin";
  $("settings-admin-section").classList.toggle("hidden", !isAdmin);

  const select = $("change-pass-username");
  if (!isAdmin) {
    // Un utente non-admin puo' cambiare solo la propria password (vedi
    // check self-or-admin lato server): niente dropdown, solo il proprio
    // username, per non far credere che si possa scegliere altro.
    select.innerHTML = `<option value="${escapeHtml(CURRENT_USER.username)}">${escapeHtml(CURRENT_USER.username)}</option>`;
    select.disabled = true;
    return;
  }
  select.disabled = false;
  refreshWebhookConfig();

  const list = $("settings-user-list");
  try {
    const res = await fetch("/api/settings/users");
    const data = await res.json();
    const users = data.users || [];

    list.innerHTML = users.map((u) => `
      <div class="user-row">
        <span>👤 ${escapeHtml(u.username)} <span class="role-badge">${escapeHtml(u.role)}</span></span>
        <button class="btn small btn-remove-user" data-username="${escapeHtml(u.username)}" ${users.length <= 1 ? "disabled" : ""}>🗑 Remove</button>
      </div>
    `).join("");

    const current = select.value;
    const usernames = users.map((u) => u.username);
    select.innerHTML = usernames.map((u) => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join("");
    if (usernames.includes(current)) select.value = current;
  } catch (e) {
    list.innerHTML = "Failed to fetch users.";
  }
}

async function addUser() {
  const username = $("new-user-username").value.trim();
  const password = $("new-user-password").value;
  const role = $("new-user-role").value;
  const msg = $("add-user-msg");
  msg.textContent = "Adding...";
  try {
    const res = await fetch("/api/settings/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    const data = await res.json();
    msg.textContent = data.message || "";
    if (data.ok) {
      $("new-user-username").value = "";
      $("new-user-password").value = "";
      refreshUsers();
    }
  } catch (e) {
    msg.textContent = "Network error.";
  }
}

async function changePassword() {
  const username = $("change-pass-username").value;
  const password = $("change-pass-password").value;
  const msg = $("change-pass-msg");
  if (!username) {
    msg.textContent = "No user selected.";
    return;
  }
  msg.textContent = "Updating...";
  try {
    const res = await fetch("/api/settings/users/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    msg.textContent = data.message || "";
    if (data.ok) $("change-pass-password").value = "";
  } catch (e) {
    msg.textContent = "Network error.";
  }
}

async function removeUser(username) {
  try {
    const res = await fetch(`/api/settings/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    const data = await res.json();
    if (!data.ok) {
      $("add-user-msg").textContent = data.message || "";
    }
    refreshUsers();
  } catch (e) {
    $("add-user-msg").textContent = "Network error.";
  }
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
  $("net-msg").textContent = "Reconfiguring (can take up to a minute)...";
  $("btn-rescan-net").disabled = true;
  await fetch("/api/network/rescan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force }),
  });

  // Poll until the backend reports reconfiguring:false instead of guessing
  // a fixed time: reconfiguration can take from a few seconds (DHCP
  // immediately available) to ~30s (all preset classes tried).
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1500));
    const data = await refreshNetwork();
    if (data && !data.eth.reconfiguring) break;
  }
  $("net-msg").textContent = "";
  $("btn-rescan-net").disabled = false;
}

async function toggleWifiListFor(iface, panel) {
  if (!panel.classList.contains("hidden")) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  panel.innerHTML = "Scanning for networks...";
  try {
    const res = await fetch(`/api/wifi/networks?iface=${encodeURIComponent(iface)}`);
    const nets = await res.json();
    if (nets.length === 0) {
      panel.innerHTML = "No networks found (or nmcli not available).";
      return;
    }
    panel.innerHTML = nets.map((n) => `
      <div class="wifi-net-row">
        <span>${escapeHtml(n.ssid)} ${n.security ? "🔒" : ""}</span>
        <span>${escapeHtml(n.signal)}%</span>
        <button class="btn small btn-connect-wifi" data-ssid="${escapeHtml(n.ssid)}" data-secured="${n.security ? "1" : "0"}">Connect</button>
      </div>
    `).join("");
  } catch (e) {
    panel.innerHTML = "Failed to fetch networks.";
  }
}

function populateHotspotIfaceSelect(preferredIface) {
  const select = $("hotspot-iface");
  const ifaces = lastWifiIfaces.length > 0 ? lastWifiIfaces : (preferredIface ? [preferredIface] : []);
  select.innerHTML = ifaces.map((i) => `<option value="${escapeHtml(i)}">${escapeHtml(i)}</option>`).join("");
  if (preferredIface && ifaces.includes(preferredIface)) {
    select.value = preferredIface;
  }
}

async function openHotspotModal(iface) {
  $("hotspot-modal").classList.remove("hidden");
  $("hotspot-msg").textContent = "";
  $("hotspot-ssid").value = "";
  populateHotspotIfaceSelect(iface);
  await refreshHotspotStatus();
}

function closeHotspotModal() {
  $("hotspot-modal").classList.add("hidden");
}

function openWifiConnectModal(iface, ssid, secured) {
  $("wifi-connect-modal").dataset.iface = iface;
  $("wifi-connect-iface").textContent = iface;
  $("wifi-connect-ssid").value = ssid;
  $("wifi-connect-password").value = "";
  $("wifi-connect-password").placeholder = secured ? "password" : "not required (open network)";
  $("wifi-connect-msg").textContent = "";
  $("wifi-connect-modal").classList.remove("hidden");
}

function closeWifiConnectModal() {
  $("wifi-connect-modal").classList.add("hidden");
}

async function submitWifiConnect() {
  const iface = $("wifi-connect-modal").dataset.iface;
  const ssid = $("wifi-connect-ssid").value;
  const password = $("wifi-connect-password").value;
  const msg = $("wifi-connect-msg");
  msg.textContent = "Connecting (can take a few seconds)...";
  try {
    const res = await fetch("/api/wifi/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid, password, iface }),
    });
    const data = await res.json();
    msg.textContent = data.message || (data.ok ? "Connected." : "Failed to connect.");
    if (data.ok) {
      await refreshNetwork();
      setTimeout(closeWifiConnectModal, 1200);
    }
  } catch (e) {
    msg.textContent = "Network error.";
  }
}

async function refreshHotspotStatus() {
  const box = $("hotspot-status-box");
  const iface = $("hotspot-iface").value;
  box.textContent = "Checking status...";
  try {
    const res = await fetch(`/api/hotspot/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`);
    const data = await res.json();
    if (data.active) {
      const port = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
      box.innerHTML = `🟢 Active on <strong>${escapeHtml(data.iface)}</strong> — SSID <strong>${escapeHtml(data.ssid)}</strong>, reachable at <strong>${escapeHtml(data.ip)}:${port}</strong>`;
    } else {
      box.textContent = "⚪ Not active";
    }
    if (!$("hotspot-ssid").value) {
      $("hotspot-ssid").value = data.ssid || data.default_ssid || "";
    }
  } catch (e) {
    box.textContent = "Failed to fetch status.";
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
  const iface = $("hotspot-iface").value;
  $("hotspot-msg").textContent = "Activating...";
  try {
    const res = await fetch("/api/hotspot/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ssid, password, iface }),
    });
    const data = await res.json();
    $("hotspot-msg").textContent = data.message || "";
    await refreshHotspotStatus();
    await refreshNetwork();
  } catch (e) {
    $("hotspot-msg").textContent = "Network error.";
  }
}

async function stopHotspot() {
  $("hotspot-msg").textContent = "Deactivating...";
  try {
    const res = await fetch("/api/hotspot/stop", { method: "POST" });
    const data = await res.json();
    $("hotspot-msg").textContent = data.message || "";
    await refreshHotspotStatus();
    await refreshNetwork();
  } catch (e) {
    $("hotspot-msg").textContent = "Network error.";
  }
}

async function checkForcedPasswordChange() {
  try {
    const res = await fetch("/api/settings/me");
    if (!res.ok) return false;
    const data = await res.json();
    CURRENT_USER = { username: data.username, role: data.role };
    if (data.must_change_password) {
      $("forced-password-username").textContent = data.username;
      $("forced-password-overlay").dataset.username = data.username;
      $("forced-password-overlay").classList.remove("hidden");
      return true;
    }
  } catch (e) {
    console.error("checkForcedPasswordChange", e);
  }
  return false;
}

async function submitForcedPasswordChange() {
  const username = $("forced-password-overlay").dataset.username;
  const password = $("forced-password-input").value;
  const msg = $("forced-password-msg");
  msg.textContent = "Updating...";
  try {
    const res = await fetch("/api/settings/users/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.ok) {
      msg.textContent = "Password updated — reloading...";
      // Ricarica invece di proseguire in place: piu' semplice e sicuro
      // che reinizializzare a meta' uno stato che finora era bloccato di
      // proposito, e la pagina e' comunque leggera.
      setTimeout(() => window.location.reload(), 800);
    } else {
      msg.textContent = data.message || "Failed to update password.";
    }
  } catch (e) {
    msg.textContent = "Network error.";
  }
}

async function init() {
  // P0: se questo utente ha ancora la password casuale di bootstrap,
  // blocca tutto il resto della dashboard (niente scan, niente polling)
  // finche' non la cambia — vedi _PASSWORD_CHANGE_ALWAYS_ALLOWED lato
  // server, che rifiuta con 403 qualunque altro endpoint nel frattempo.
  const mustChangePassword = await checkForcedPasswordChange();
  if (mustChangePassword) {
    $("btn-forced-password-submit").addEventListener("click", submitForcedPasswordChange);
    return;
  }

  setupTabs();
  $("btn-scan-start").addEventListener("click", startScan);
  $("btn-scan-stop").addEventListener("click", stopScan);
  $("btn-rescan-net").addEventListener("click", rescanNetwork);
  $("eth-candidates").addEventListener("click", (ev) => {
    const btn = ev.target.closest(".btn-choose-network");
    if (btn) chooseNetwork(btn.dataset.cidr);
  });
  $("btn-refresh-report").addEventListener("click", refreshReport);
  $("btn-close-hotspot").addEventListener("click", closeHotspotModal);
  $("btn-hotspot-generate").addEventListener("click", generateHotspotPassword);
  $("btn-hotspot-start").addEventListener("click", startHotspot);
  $("btn-hotspot-stop").addEventListener("click", stopHotspot);
  $("btn-add-user").addEventListener("click", addUser);
  $("btn-change-password").addEventListener("click", changePassword);
  $("btn-save-webhook").addEventListener("click", saveWebhookConfig);
  $("btn-compare-scans").addEventListener("click", compareScans);
  $("settings-user-list").addEventListener("click", (ev) => {
    const btn = ev.target.closest(".btn-remove-user");
    if (btn) removeUser(btn.dataset.username);
  });
  $("hotspot-iface").addEventListener("change", () => {
    $("hotspot-ssid").value = "";
    refreshHotspotStatus();
  });
  $("hotspot-modal").addEventListener("click", (ev) => {
    if (ev.target.id === "hotspot-modal") closeHotspotModal();
  });
  $("btn-close-wifi-connect").addEventListener("click", closeWifiConnectModal);
  $("btn-wifi-connect-submit").addEventListener("click", submitWifiConnect);
  $("wifi-connect-modal").addEventListener("click", (ev) => {
    if (ev.target.id === "wifi-connect-modal") closeWifiConnectModal();
  });

  // The Wi-Fi boxes (one per adapter) are generated dynamically by
  // renderWifiBoxes: their "Visible networks"/"Hotspot"/"Connect" buttons
  // are wired up here by delegation instead of by id, since they can be
  // recreated or vary in number (0, 1, several adapters).
  $("wifi-boxes").addEventListener("click", (ev) => {
    const listBtn = ev.target.closest(".btn-wifi-list");
    if (listBtn) {
      const panel = listBtn.closest(".net-box").querySelector(".wifi-networks-panel");
      toggleWifiListFor(listBtn.dataset.iface, panel);
      return;
    }
    const hotspotBtn = ev.target.closest(".btn-open-hotspot");
    if (hotspotBtn) {
      openHotspotModal(hotspotBtn.dataset.iface);
      return;
    }
    const connectBtn = ev.target.closest(".btn-connect-wifi");
    if (connectBtn) {
      const iface = connectBtn.closest(".net-box").dataset.iface;
      openWifiConnectModal(iface, connectBtn.dataset.ssid, connectBtn.dataset.secured === "1");
    }
  });

  refreshNetwork();
  refreshScan();
  refreshSecurityStats();
  setInterval(refreshNetwork, 5000);
  setInterval(refreshScan, 1500);
  setInterval(refreshSecurityStats, 5000);
}

document.addEventListener("DOMContentLoaded", init);
