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

// --- platform capabilities (HIST-5/6/7) ------------------------------------

// Populated at boot from the `platform_capabilities` command. Sensible defaults
// (no protection) until it resolves, so we never render a fake lock.
let caps = { os: "", capture_protection: false, biometrics: false };

const CAPTURE_KEY = "ucb.captureProtection"; // "on" | "off"

async function initCapabilities() {
  try {
    caps = await invoke("platform_capabilities");
  } catch {
    caps = { os: "", capture_protection: false, biometrics: false };
  }
  applyCaptureFromStorage();
  renderSettings();
}

// --- tab navigation --------------------------------------------------------

let currentView = "devices";

function showView(name) {
  currentView = name;
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("is-active", t.dataset.view === name)
  );
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("is-active", v.id === `view-${name}`)
  );
  if (name === "history") enterHistory();
  if (name === "devices") refreshDevices();
  if (name === "settings") renderSettings();
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

// --- History gate (HIST-5) -------------------------------------------------

const UNLOCK_MS = 5 * 60 * 1000; // success unlocks History for 5 minutes
const RELOCK_BLUR_MS = 60 * 1000; // re-lock after >1 min unfocused
let historyUnlockedUntil = 0;
let blurTimer = null;

function historyUnlocked() {
  // No biometrics on this platform → never gated (never a fake lock).
  if (!caps.biometrics) return true;
  return Date.now() < historyUnlockedUntil;
}

function enterHistory() {
  if (historyUnlocked()) {
    showHistoryUnlocked();
  } else {
    showHistoryLocked("Authenticate to view your clipboard history.");
    attemptBiometric();
  }
}

function showHistoryUnlocked() {
  $("#history-locked").hidden = true;
  $("#history-content").hidden = false;
  loadHistory(true);
}

function showHistoryLocked(msg) {
  $("#history-content").hidden = true;
  const box = $("#history-locked");
  box.hidden = false;
  $("#history-locked-msg").textContent = msg;
}

async function attemptBiometric() {
  let res;
  try {
    res = await invoke("authenticate", { reason: "Unlock clipboard history" });
  } catch (e) {
    showHistoryLocked(`Authentication error: ${e}`);
    return;
  }
  if (!res.supported) {
    // Platform gained/using no biometric support — show history ungated.
    caps.biometrics = false;
    showHistoryUnlocked();
    return;
  }
  if (res.success) {
    historyUnlockedUntil = Date.now() + UNLOCK_MS;
    showHistoryUnlocked();
  } else {
    showHistoryLocked(res.error ? `Locked — ${res.error}` : "Authentication cancelled.");
  }
}

$("#history-unlock").addEventListener("click", attemptBiometric);

// Re-lock when the window stays unfocused for over a minute.
window.addEventListener("blur", () => {
  if (blurTimer) clearTimeout(blurTimer);
  blurTimer = setTimeout(() => {
    historyUnlockedUntil = 0;
    if (currentView === "history") {
      showHistoryLocked("Locked after inactivity. Authenticate to continue.");
    }
  }, RELOCK_BLUR_MS);
});
window.addEventListener("focus", () => {
  if (blurTimer) {
    clearTimeout(blurTimer);
    blurTimer = null;
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

  const pending = [];
  for (const e of entries) {
    const { row, contentEl, text } = renderEntry(e);
    body.appendChild(row);
    histOldestTs = e.ts_ms;
    if (text != null) pending.push({ contentEl, text });
  }

  // HIST-6: batch-classify text entries and blur the sensitive ones. One IPC
  // round-trip per page; the heuristic lives in Rust (`is_sensitive_batch`).
  if (pending.length) {
    try {
      const flags = await invoke("is_sensitive_batch", {
        texts: pending.map((p) => p.text),
      });
      pending.forEach((p, i) => {
        if (flags[i]) markSensitive(p.contentEl);
      });
    } catch {
      /* classification is best-effort; leave entries visible on failure */
    }
  }

  // If a full page came back, there may be more.
  $("#hist-more").hidden = entries.length < HIST_PAGE;
}

// HIST-6: blur a flagged entry and add a "sensitive" badge + reveal controls.
// Reveal via the eye button (10s) or click-and-hold on the content.
function markSensitive(contentEl) {
  contentEl.classList.add("sensitive");
  let hideTimer = null;
  const hide = () => contentEl.classList.add("sensitive");
  const show = () => contentEl.classList.remove("sensitive");

  const bar = el("div", "sens-bar");
  bar.appendChild(el("span", "sens-badge", "sensitive"));
  const eye = el("button", "btn small sens-eye", "👁 Reveal");
  eye.title = "Reveal for 10 seconds";
  eye.addEventListener("click", () => {
    show();
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(hide, 10000);
  });
  bar.appendChild(eye);
  contentEl.insertAdjacentElement("afterend", bar);

  // Click-and-hold to peek while held.
  contentEl.addEventListener("mousedown", show);
  contentEl.addEventListener("mouseup", () => {
    if (!hideTimer) hide();
  });
  contentEl.addEventListener("mouseleave", () => {
    if (!hideTimer) hide();
  });
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
  let text = null;
  if (e.content != null) {
    preview = escapeText(e.content);
    text = preview;
  } else if (e.width && e.height) {
    preview = `[image ${e.width}×${e.height}]`;
  } else {
    preview = "[binary]";
  }
  const contentEl = el("div", "content", preview);
  grow.appendChild(contentEl);
  row.appendChild(grow);

  const del = el("button", "btn small danger", "Delete");
  del.addEventListener("click", async () => {
    try {
      await invoke("ipc_history_delete", { id: e.id });
      loadHistory(true);
    } catch (err) { alert(String(err)); }
  });
  row.appendChild(del);

  // `text` is the plain content for text entries (HIST-6 classification input),
  // or null for images/binary which are never blurred.
  return { row, contentEl, text };
}

// --- Settings (HIST-7 capture toggle + HIST-5 note) ------------------------

// Apply the persisted screenshot-protection preference (default ON) on boot.
async function applyCaptureFromStorage() {
  const stored = localStorage.getItem(CAPTURE_KEY);
  const enabled = stored == null ? true : stored === "on";
  $("#set-capture").checked = enabled;
  if (caps.capture_protection) {
    try {
      await invoke("set_capture_protection", { enabled });
    } catch {
      /* non-fatal; window was created with protection ON by default */
    }
  }
}

$("#set-capture").addEventListener("change", async (ev) => {
  const enabled = ev.target.checked;
  localStorage.setItem(CAPTURE_KEY, enabled ? "on" : "off");
  if (caps.capture_protection) {
    try {
      await invoke("set_capture_protection", { enabled });
    } catch (e) {
      alert(String(e));
    }
  }
});

// Update Settings copy to reflect what this platform can actually enforce.
function renderSettings() {
  const cap = $("#capture-note");
  const bio = $("#biometric-note");
  if (caps.capture_protection) {
    cap.textContent =
      "Excludes this window from screenshots, screen recording, and screen sharing.";
  } else {
    cap.textContent =
      "Screen-capture protection is not enforceable on this platform (Linux) — this toggle has no effect here.";
  }
  if (caps.biometrics) {
    bio.textContent =
      "The History view is protected by Touch ID. It unlocks for 5 minutes, and re-locks if the window stays unfocused for over a minute.";
  } else {
    bio.textContent = "Biometric lock unavailable on this platform — History is shown without a lock.";
  }
}

// --- boot ------------------------------------------------------------------

initCapabilities();
refreshDevices();
setInterval(() => {
  // Poll devices only while its view is active (every 2s per UX-2).
  if ($("#view-devices").classList.contains("is-active")) refreshDevices();
}, 2000);
