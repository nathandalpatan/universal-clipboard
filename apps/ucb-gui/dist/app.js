// Universal Clipboard GUI — frontend logic (vanilla JS, no bundler).
// Talks to the Rust command layer via the global Tauri API (withGlobalTauri).
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// --- helpers ---------------------------------------------------------------

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

// UX-3: reveal a spinner element only if the awaited work exceeds 350ms.
async function withSpinner(spinnerEl, work) {
  let shown = false;
  const timer = setTimeout(() => {
    shown = true;
    if (spinnerEl) spinnerEl.classList.add("show");
  }, 350);
  try {
    return await work();
  } finally {
    clearTimeout(timer);
    if (shown && spinnerEl) spinnerEl.classList.remove("show");
  }
}

function escapeText(s) {
  return String(s == null ? "" : s);
}

function fmtTime(ms) {
  try {
    return new Date(Number(ms)).toLocaleString();
  } catch {
    return String(ms);
  }
}

// --- tab navigation --------------------------------------------------------

function showView(name) {
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("is-active", t.dataset.view === name)
  );
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("is-active", v.id === `view-${name}`)
  );
  if (name === "history") loadHistory(true);
  if (name === "devices") refreshDevices();
}

document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => showView(t.dataset.view))
);

// --- Devices (UX-2) --------------------------------------------------------

let lastPeers = [];

async function refreshDevices() {
  const body = $("#devices-body");
  let status;
  try {
    status = await withSpinner($("#devices-spin"), () => invoke("ipc_status"));
  } catch (e) {
    // No daemon socket / unreachable → clear empty state.
    setDaemonDot(false);
    body.innerHTML = "";
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "Daemon not running"));
    const p = el("p", "muted");
    p.innerHTML = 'Start the engine first: run <code>ucb run</code> in a terminal.';
    box.appendChild(p);
    body.appendChild(box);
    lastPeers = [];
    updateDeviceFilter();
    return;
  }

  setDaemonDot(true);
  const peers = (status && status.peers) || [];
  lastPeers = peers;
  updateDeviceFilter();
  body.innerHTML = "";

  if (peers.length === 0) {
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "No devices paired"));
    box.appendChild(el("p", "muted", "Pair another device to start syncing your clipboard."));
    const cta = el("button", "btn primary", "Pair a device");
    cta.addEventListener("click", () => showView("pair"));
    box.appendChild(cta);
    body.appendChild(box);
    return;
  }

  for (const p of peers) {
    const row = el("div", "rowitem");
    const badge = el("span", `badge ${p.connected ? "on" : "off"}`, p.connected ? "connected" : "offline");
    row.appendChild(badge);
    const grow = el("div", "grow");
    grow.appendChild(el("div", "name", p.name || "(unnamed)"));
    grow.appendChild(el("div", "sub", p.id_short));
    row.appendChild(grow);
    const revoke = el("button", "btn small danger", "Revoke");
    revoke.addEventListener("click", () => revokePeer(p.id_short, p.name));
    row.appendChild(revoke);
    body.appendChild(row);
  }
}

async function revokePeer(prefix, name) {
  if (!confirm(`Revoke ${name || prefix}? This blocks re-pairing until you run \`ucb revoke --forget\`.`)) {
    return;
  }
  try {
    const res = await invoke("ipc_revoke", { prefix });
    if (!res.ok) alert(res.detail || "Revoke failed.");
  } catch (e) {
    alert(String(e));
  }
  refreshDevices();
}

function setDaemonDot(on) {
  const dot = $("#daemon-dot");
  dot.classList.toggle("on", on);
  dot.classList.toggle("off", !on);
}

// --- Pair (PAIR-2) ---------------------------------------------------------

$("#pair-start").addEventListener("click", startPairing);
$("#pair-cancel").addEventListener("click", cancelPairing);
$("#pair-copy").addEventListener("click", () => {
  const uri = $("#pair-uri").textContent;
  if (navigator.clipboard) navigator.clipboard.writeText(uri).catch(() => {});
});
$("#pair-accept").addEventListener("click", () => confirmPairing(true));
$("#pair-reject").addEventListener("click", () => confirmPairing(false));

function resetPairUI() {
  $("#pair-idle").hidden = false;
  $("#pair-live").hidden = true;
  $("#pair-code-card").hidden = true;
  $("#pair-result").hidden = true;
  $("#pair-qr").textContent = "";
  $("#pair-uri").textContent = "";
  $("#pair-code").textContent = "";
}

async function startPairing() {
  $("#pair-result").hidden = true;
  let first;
  try {
    first = await invoke("pair_start");
  } catch (e) {
    showPairResult(false, String(e));
    return;
  }
  if (first && first.type === "error") {
    showPairResult(false, first.message || "Could not start pairing.");
    return;
  }
  $("#pair-idle").hidden = true;
  $("#pair-live").hidden = false;
  $("#pair-code-card").hidden = true;
  $("#pair-uri").textContent = first.uri || "";
  $("#pair-qr").textContent = first.qr_text || "";
}

async function cancelPairing() {
  try { await invoke("pair_cancel"); } catch {}
  resetPairUI();
}

async function confirmPairing(accept) {
  try {
    await invoke("pair_confirm", { accept });
  } catch (e) {
    showPairResult(false, String(e));
  }
  $("#pair-code-card").hidden = true;
}

function showPairResult(ok, msg) {
  const b = $("#pair-result");
  b.hidden = false;
  b.classList.toggle("err", !ok);
  b.textContent = ok ? `Paired with ${msg}.` : `Pairing failed: ${msg}`;
  $("#pair-live").hidden = true;
  $("#pair-idle").hidden = false;
}

// Streamed pairing events from the Rust side.
listen("pair://event", (event) => {
  const v = event.payload || {};
  if (v.type === "code") {
    $("#pair-code").textContent = v.code || "";
    const dev = v.device || {};
    $("#pair-peer").textContent = `${dev.name || "device"} (${(dev.id || "").slice(0, 8)})`;
    $("#pair-code-card").hidden = false;
  } else if (v.type === "result") {
    if (v.ok) {
      showPairResult(true, v.name || "device");
      refreshDevices();
    } else {
      showPairResult(false, v.message || "declined");
    }
  } else if (v.type === "closed") {
    // Connection dropped before completion; return to idle unless a result
    // already rendered.
    if ($("#pair-result").hidden) resetPairUI();
  }
});

// --- History (HIST-3) ------------------------------------------------------

let histOldestTs = null;

function updateDeviceFilter() {
  const sel = $("#hist-device");
  const current = sel.value;
  sel.innerHTML = '<option value="">All devices</option>';
  for (const p of lastPeers) {
    const o = el("option", null, `${p.name || "(unnamed)"} — ${p.id_short}`);
    o.value = p.id_short;
    sel.appendChild(o);
  }
  sel.value = current;
}

$("#hist-apply").addEventListener("click", () => loadHistory(true));
$("#hist-search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") loadHistory(true);
});
$("#hist-starred").addEventListener("change", () => loadHistory(true));
$("#hist-device").addEventListener("change", () => loadHistory(true));
$("#hist-more").addEventListener("click", () => loadHistory(false));

const HIST_PAGE = 50;

async function loadHistory(reset) {
  const body = $("#history-body");
  if (reset) {
    histOldestTs = null;
    body.innerHTML = "";
  }
  const args = {
    search: $("#hist-search").value || null,
    device: $("#hist-device").value || null,
    starred: $("#hist-starred").checked ? true : null,
    limit: HIST_PAGE,
    beforeTs: reset ? null : histOldestTs,
  };

  let res;
  try {
    res = await withSpinner($("#history-spin"), () => invoke("ipc_history_list", args));
  } catch (e) {
    body.innerHTML = "";
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "Daemon not running"));
    const p = el("p", "muted");
    p.innerHTML = 'History lives in the daemon. Run <code>ucb run</code> first.';
    box.appendChild(p);
    body.appendChild(box);
    $("#hist-more").hidden = true;
    return;
  }

  const entries = (res && res.entries) || [];
  if (reset && entries.length === 0) {
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "No history yet"));
    box.appendChild(el("p", "muted", "Copied items will appear here once the daemon records them."));
    body.appendChild(box);
    $("#hist-more").hidden = true;
    return;
  }

  for (const e of entries) {
    body.appendChild(renderEntry(e));
    histOldestTs = e.ts_ms;
  }
  // If a full page came back, there may be more.
  $("#hist-more").hidden = entries.length < HIST_PAGE;
}

function renderEntry(e) {
  const row = el("div", "rowitem");

  const star = el("button", `star ${e.starred ? "on" : ""}`, e.starred ? "★" : "☆");
  star.title = e.starred ? "Unstar" : "Star";
  star.addEventListener("click", async () => {
    try {
      await invoke("ipc_history_star", { id: e.id, starred: !e.starred });
      loadHistory(true);
    } catch (err) { alert(String(err)); }
  });
  row.appendChild(star);

  const grow = el("div", "grow");
  const head = el("div");
  head.appendChild(el("span", "kind", e.kind));
  head.appendChild(document.createTextNode("  "));
  head.appendChild(el("span", "sub", `${fmtTime(e.ts_ms)} · ${escapeText(e.origin_name)} (${String(e.origin_id).slice(0, 8)})`));
  grow.appendChild(head);

  let preview;
  if (e.content != null) {
    preview = escapeText(e.content);
  } else if (e.width && e.height) {
    preview = `[image ${e.width}×${e.height}]`;
  } else {
    preview = "[binary]";
  }
  grow.appendChild(el("div", "content", preview));
  row.appendChild(grow);

  const del = el("button", "btn small danger", "Delete");
  del.addEventListener("click", async () => {
    try {
      await invoke("ipc_history_delete", { id: e.id });
      loadHistory(true);
    } catch (err) { alert(String(err)); }
  });
  row.appendChild(del);

  return row;
}

// --- boot ------------------------------------------------------------------

refreshDevices();
setInterval(() => {
  // Poll devices only while its view is active (every 2s per UX-2).
  if ($("#view-devices").classList.contains("is-active")) refreshDevices();
}, 2000);
