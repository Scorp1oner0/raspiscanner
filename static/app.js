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

async function refreshNetwork() {
  try {
    const res = await fetch("/api/network");
    const data = await res.json();

    $("eth-iface").textContent = data.eth.iface ? `(${data.eth.iface})` : "";
    $("eth-up").textContent = data.eth.reconfiguring
      ? "🔄 reconfiguring..."
      : (data.eth.up ? "connected" : "disconnected");
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

    renderWifiBoxes(data.wifi);

    return data;
  } catch (e) {
    console.error("refreshNetwork", e);
  }
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
    tbody.innerHTML = '<tr><td colspan="8" class="empty">No data yet — start a scan</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map((d) => `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.mac) || "-"}</td>
      <td>${escapeHtml(d.vendor)}</td>
      <td>${escapeHtml(d.hostname)}</td>
      <td>${escapeHtml(d.iface)}</td>
      <td>${escapeHtml(d.network) || "-"}</td>
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
      <td>${escapeHtml(d.vendor)}</td>
      <td>${renderPorts(d)}</td>
      <td>${d.rtsp_url ? '<a class="link" href="' + escapeHtml(d.rtsp_url) + '">' + escapeHtml(d.rtsp_url) + "</a>" : "-"}</td>
      <td>${d.admin_url ? '<a class="link" target="_blank" href="' + escapeHtml(d.admin_url) + '">open</a>' : "-"}</td>
      <td>${escapeHtml((d.reasons || []).join("; "))}</td>
    </tr>
  `;
}

function renderCameraRowMismatch(d) {
  return `
    <tr>
      <td>${escapeHtml(d.ip)}</td>
      <td>${escapeHtml(d.vendor)}</td>
      <td>${escapeHtml(d.model) || "-"}</td>
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

async function refreshReport() {
  try {
    const res = await fetch("/api/report");
    const data = await res.json();
    $("report-text").textContent = data.text || "No data.";
  } catch (e) {
    $("report-text").textContent = "Failed to fetch the report.";
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
      $("panel-settings").classList.toggle("hidden", tab !== "settings");
      if (tab === "report") refreshReport();
      if (tab === "settings") refreshUsers();
    });
  });
}

async function refreshUsers() {
  const list = $("settings-user-list");
  const select = $("change-pass-username");
  try {
    const res = await fetch("/api/settings/users");
    const data = await res.json();
    const users = data.users || [];

    list.innerHTML = users.map((u) => `
      <div class="user-row">
        <span>👤 ${escapeHtml(u)}</span>
        <button class="btn small btn-remove-user" data-username="${escapeHtml(u)}" ${users.length <= 1 ? "disabled" : ""}>🗑 Remove</button>
      </div>
    `).join("");

    const current = select.value;
    select.innerHTML = users.map((u) => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join("");
    if (users.includes(current)) select.value = current;
  } catch (e) {
    list.innerHTML = "Failed to fetch users.";
  }
}

async function addUser() {
  const username = $("new-user-username").value.trim();
  const password = $("new-user-password").value;
  const msg = $("add-user-msg");
  msg.textContent = "Adding...";
  try {
    const res = await fetch("/api/settings/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
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

async function refreshHotspotStatus() {
  const box = $("hotspot-status-box");
  const iface = $("hotspot-iface").value;
  box.textContent = "Checking status...";
  try {
    const res = await fetch(`/api/hotspot/status${iface ? `?iface=${encodeURIComponent(iface)}` : ""}`);
    const data = await res.json();
    if (data.active) {
      box.innerHTML = `🟢 Active on <strong>${escapeHtml(data.iface)}</strong> — SSID <strong>${escapeHtml(data.ssid)}</strong>, reachable at <strong>${escapeHtml(data.ip)}:7332</strong>`;
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

function init() {
  setupTabs();
  $("btn-scan-start").addEventListener("click", startScan);
  $("btn-scan-stop").addEventListener("click", stopScan);
  $("btn-rescan-net").addEventListener("click", rescanNetwork);
  $("btn-refresh-report").addEventListener("click", refreshReport);
  $("btn-close-hotspot").addEventListener("click", closeHotspotModal);
  $("btn-hotspot-generate").addEventListener("click", generateHotspotPassword);
  $("btn-hotspot-start").addEventListener("click", startHotspot);
  $("btn-hotspot-stop").addEventListener("click", stopHotspot);
  $("btn-add-user").addEventListener("click", addUser);
  $("btn-change-password").addEventListener("click", changePassword);
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

  // The Wi-Fi boxes (one per adapter) are generated dynamically by
  // renderWifiBoxes: their "Visible networks"/"Hotspot" buttons are wired
  // up here by delegation instead of by id, since they can be recreated or
  // vary in number (0, 1, several adapters).
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
