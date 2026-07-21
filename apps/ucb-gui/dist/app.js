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

// Relative time for status feedback: "just now", "42s ago", "5m ago"…
function relTime(ms) {
  const d = Date.now() - Number(ms);
  if (!Number.isFinite(d) || d < 0) return "just now";
  if (d < 5000) return "just now";
  if (d < 60000) return `${Math.floor(d / 1000)}s ago`;
  if (d < 3600000) return `${Math.floor(d / 60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d / 3600000)}h ago`;
  return new Date(Number(ms)).toLocaleDateString();
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

// --- toasts (UX-4) ---------------------------------------------------------

// Show a transient toast. `actions` is an array of { label, onClick }.
function toast(msg, kind = "ok", actions = [], timeout = 6000) {
  const box = el("div", `toast ${kind}`);
  box.appendChild(el("span", "toast-msg", msg));
  const dismiss = () => {
    if (box.parentNode) box.parentNode.removeChild(box);
  };
  for (const a of actions) {
    const b = el("button", "btn small", a.label);
    b.addEventListener("click", () => {
      try {
        a.onClick();
      } catch {}
      dismiss();
    });
    box.appendChild(b);
  }
  $("#toasts").appendChild(box);
  if (timeout) setTimeout(dismiss, timeout);
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
  if (name === "settings") {
    renderSettings();
    loadConfigIntoSettings();
  }
}

document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => showView(t.dataset.view))
);

// --- daemon reachability + managed sync control ----------------------------

let daemonUp = false;
let daemonManaged = false;
// True while a Start/Stop is in flight. Holds the button in a "busy" state and
// stops the background poll from clobbering that label before the daemon socket
// actually comes up (or fails to), so a click always has visible feedback.
let syncPending = false;

function setDaemonDot(on) {
  const dot = $("#daemon-dot");
  dot.classList.toggle("on", on);
  dot.classList.toggle("off", !on);
}

// Put the sync button into an immediate busy state (disabled + spinner label).
function setSyncBusy(text) {
  syncPending = true;
  const btn = $("#sync-toggle");
  const label = $("#sync-label");
  btn.hidden = false;
  btn.disabled = true;
  btn.classList.add("busy");
  btn.textContent = text;
  if (label) label.textContent = text === "Starting…" ? "Starting sync…" : "Stopping sync…";
}

// Release the busy state so the next status refresh can set the real label.
function clearSyncBusy() {
  syncPending = false;
  const btn = $("#sync-toggle");
  btn.disabled = false;
  btn.classList.remove("busy");
}

// Refresh the header sync label + Start/Stop button from the current state.
async function refreshSyncControl(status) {
  // A start/stop is mid-flight: keep the busy label until it resolves.
  if (syncPending) {
    daemonUp = !!status;
    setDaemonDot(daemonUp);
    return;
  }
  daemonUp = !!status;
  setDaemonDot(daemonUp);

  const label = $("#sync-label");
  const btn = $("#sync-toggle");

  if (daemonUp) {
    try {
      daemonManaged = await invoke("daemon_is_managed");
    } catch {
      daemonManaged = false;
    }
    const peers = (status.peers || []).length;
    const connected = (status.peers || []).filter((p) => p.connected).length;
    label.textContent = `Sync on · ${connected}/${peers} connected`;
    if (daemonManaged) {
      btn.hidden = false;
      btn.textContent = "Stop sync";
    } else {
      btn.hidden = true; // an external / background daemon — not ours to stop
    }
  } else {
    daemonManaged = false;
    label.textContent = "Sync off";
    btn.hidden = false;
    btn.textContent = "Start sync";
  }
}

$("#sync-toggle").addEventListener("click", async () => {
  if (daemonUp && daemonManaged) {
    // Stop: show immediate feedback, then let the socket drop before refreshing.
    setSyncBusy("Stopping…");
    try {
      await invoke("daemon_stop");
    } catch (e) {
      clearSyncBusy();
      toast(String(e), "err");
      return;
    }
    setTimeout(async () => {
      clearSyncBusy();
      await pollStatus();
      toast("Sync stopped", "ok");
    }, 400);
  } else if (!daemonUp) {
    // Route through onboarding if the device isn't set up yet.
    let inited = false;
    try {
      inited = await invoke("ucb_is_initialized");
    } catch {}
    if (!inited) {
      openOnboard();
      return;
    }
    setSyncBusy("Starting…");
    try {
      await invoke("daemon_start");
    } catch (e) {
      clearSyncBusy();
      toast(`Couldn't start sync: ${e}`, "err", [], 9000);
      return;
    }
    waitForDaemon();
  }
});

// --- live status panel (Devices view) --------------------------------------
// Answers "who am I, who am I connected to, and is sync actually moving data".

let selfLabel = null; // cached "name · port"; reset when the daemon goes down
let lastSyncByOrigin = {}; // origin id_short → newest history ts_ms

async function ensureSelfLabel() {
  if (selfLabel) return selfLabel;
  try {
    const cfg = await invoke("ipc_config_get");
    if (cfg && cfg.name) {
      selfLabel = `${cfg.name} · port ${cfg.listen_port}`;
      return selfLabel;
    }
  } catch {}
  return null;
}

// Pull the newest history entries and derive (a) the headline "last activity"
// line and (b) a per-device newest-sync map used by the paired list.
async function refreshActivity(status) {
  const actEl = $("#stat-activity");
  if (!status) {
    actEl.textContent = "—";
    return;
  }
  let entries = [];
  try {
    const res = await invoke("ipc_history_list", { limit: 30 });
    entries = (res && res.entries) || [];
  } catch {
    actEl.textContent = "—";
    return;
  }
  const peers = status.peers || [];
  const byShort = {};
  for (const p of peers) byShort[p.id_short] = p;

  const map = {};
  for (const e of entries) {
    const short = String(e.origin_id).slice(0, 8);
    if (!(short in map) || Number(e.ts_ms) > map[short]) map[short] = Number(e.ts_ms);
  }
  lastSyncByOrigin = map;

  if (entries.length === 0) {
    actEl.textContent = "nothing synced yet";
    return;
  }
  const newest = entries[0];
  const short = String(newest.origin_id).slice(0, 8);
  const peer = byShort[short];
  const what = newest.kind || "clip";
  actEl.textContent = peer
    ? `${relTime(newest.ts_ms)} · ${what} from ${peer.name || short}`
    : `${relTime(newest.ts_ms)} · ${what} copied here`;
}

async function refreshStatPanel(status) {
  const syncChip = $("#stat-sync");
  const peersEl = $("#stat-peers");
  const selfEl = $("#stat-self");

  if (status) {
    const peers = status.peers || [];
    const connected = peers.filter((p) => p.connected).length;
    syncChip.textContent = "on";
    syncChip.className = "badge on";
    peersEl.textContent =
      peers.length === 0
        ? "no paired devices"
        : `${connected}/${peers.length} device${peers.length === 1 ? "" : "s"} connected`;
    const self = await ensureSelfLabel();
    const proto = status.protocol ? ` · protocol v${status.protocol}` : "";
    selfEl.textContent = self ? self + proto : "…";
  } else {
    selfLabel = null;
    syncChip.textContent = "off";
    syncChip.className = "badge off";
    peersEl.textContent = "start sync to connect";
    selfEl.textContent = "—";
  }
  await refreshActivity(status);
}

// Poll the daemon status; drives the header, dot, stat panel, and onboarding.
async function pollStatus() {
  let status = null;
  try {
    status = await invoke("ipc_status");
  } catch {
    status = null;
  }
  await refreshSyncControl(status);
  await refreshStatPanel(status);
  if (!status) {
    // Don't pop onboarding mid-start — waitForDaemon owns that transition.
    if (!syncPending) maybeShowOnboard();
  } else {
    hideOnboard();
    ensureTransfersStream();
    detectSyncedAway(status);
  }
  return status;
}

// After a start/onboarding, poll until the daemon socket answers (or give up
// after ~10s), then report a clear success or failure either way.
function waitForDaemon() {
  let tries = 0;
  const iv = setInterval(async () => {
    tries++;
    let status = null;
    try {
      status = await invoke("ipc_status");
    } catch {
      status = null;
    }
    if (status || tries > 20) {
      clearInterval(iv);
      clearSyncBusy();
      const s = await pollStatus();
      if (s) {
        refreshDevices();
        toast("Sync is on — you can now pair a device", "ok");
      } else {
        toast(
          "Couldn't start sync — the daemon didn't come up. Try again, or check that another copy isn't already running on this port.",
          "err",
          [],
          9000
        );
      }
    }
  }, 500);
}

// --- onboarding wizard (first-run "front door") ----------------------------

let onboardVisible = false;

function maybeShowOnboard() {
  // Only surface onboarding when the daemon is unreachable.
  if (daemonUp) return;
  openOnboard();
}

async function openOnboard() {
  if (onboardVisible) return;
  onboardVisible = true;
  $("#onboard").hidden = false;
  $("#onboard-msg").hidden = true;

  try {
    $("#onboard-bin").textContent = await invoke("ucb_binary_path");
  } catch {
    $("#onboard-bin").textContent = "ucb (not found on PATH)";
  }

  let inited = false;
  try {
    inited = await invoke("ucb_is_initialized");
  } catch {}
  $("#onboard-setup").hidden = inited;
  $("#onboard-start").hidden = !inited;
  $("#onboard-title").textContent = inited
    ? "Sync isn't running"
    : "Welcome to Universal Clipboard";
}

function hideOnboard() {
  if (!onboardVisible) return;
  onboardVisible = false;
  $("#onboard").hidden = true;
}

$("#onboard-go").addEventListener("click", async () => {
  const name = $("#onboard-name").value.trim() || null;
  const keepBackground = $("#onboard-keepbg").checked;
  const msg = $("#onboard-msg");
  msg.hidden = true;
  const btn = $("#onboard-go");
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.classList.add("busy");
  btn.textContent = "Setting up…";
  try {
    const res = await invoke("onboard", { name, keepBackground });
    const id = res && res.identity && res.identity.id;
    toast(id ? `This device is ready (${String(id).slice(0, 8)})` : "This device is ready");
    waitForDaemon();
  } catch (e) {
    msg.hidden = false;
    msg.classList.add("err");
    msg.textContent = String(e);
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
    btn.textContent = originalText;
  }
});

$("#onboard-startbtn").addEventListener("click", async () => {
  const msg = $("#onboard-msg");
  msg.hidden = true;
  const btn = $("#onboard-startbtn");
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.classList.add("busy");
  btn.textContent = "Starting…";
  try {
    await invoke("daemon_start");
    toast("Starting sync…");
    waitForDaemon();
  } catch (e) {
    msg.hidden = false;
    msg.classList.add("err");
    msg.textContent = String(e);
  } finally {
    btn.disabled = false;
    btn.classList.remove("busy");
    btn.textContent = originalText;
  }
});

// --- Devices (UX-2) --------------------------------------------------------

let lastPeers = [];
let lastDiscovered = []; // last "nearby" snapshot, so incoming rows can find a
// peer's pairing port when the user clicks Pair.
// NAT-60: incoming attempts the user dismissed, keyed by full device id → the
// `last_seen_ms` at dismissal. A newer attempt from the same device re-surfaces.
const dismissedIncoming = new Map();

async function refreshDevices() {
  const body = $("#devices-body");
  const nearby = $("#nearby-body");
  let status;
  try {
    status = await withSpinner($("#devices-spin"), () => invoke("ipc_status"));
  } catch (e) {
    // No daemon socket / unreachable → onboarding takes over; clear the lists.
    body.innerHTML = "";
    nearby.innerHTML = "";
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "Sync isn't running"));
    box.appendChild(el("p", "muted", "Start sync from the header, or set up this device."));
    const cta = el("button", "btn primary", "Set up / start");
    cta.addEventListener("click", openOnboard);
    box.appendChild(cta);
    body.appendChild(box);
    lastPeers = [];
    updateDeviceFilter();
    return;
  }

  const peers = (status && status.peers) || [];
  lastPeers = peers;
  updateDeviceFilter();

  // Paired devices.
  body.innerHTML = "";
  if (peers.length === 0) {
    const box = el("div", "empty");
    box.appendChild(el("h2", null, "No devices paired yet"));
    box.appendChild(
      el("p", "muted", "On your other computer, install ucb and click Pair — or use “Show pairing code” above.")
    );
    body.appendChild(box);
  } else {
    for (const p of peers) {
      const row = el("div", "rowitem");
      const badge = el(
        "span",
        `badge ${p.connected ? "on" : "off"}`,
        p.connected ? "connected" : "offline"
      );
      row.appendChild(badge);
      const grow = el("div", "grow");
      grow.appendChild(el("div", "name", p.name || "(unnamed)"));
      const ls = lastSyncByOrigin[p.id_short];
      const subText = ls
        ? `${p.id_short} · last sync ${relTime(ls)}`
        : `${p.id_short} · nothing synced from this device yet`;
      grow.appendChild(el("div", "sub", subText));
      row.appendChild(grow);
      const revoke = el("button", "btn small danger", "Revoke");
      revoke.addEventListener("click", () => revokePeer(p.id_short, p.name));
      row.appendChild(revoke);
      body.appendChild(row);
    }
  }

  await refreshNearby();
  await refreshIncoming();
}

// Nearby devices: discovered but not yet paired.
async function refreshNearby() {
  const nearby = $("#nearby-body");
  let discovered = [];
  try {
    const res = await invoke("ipc_discovered");
    discovered = (res && res.peers) || [];
  } catch {
    discovered = [];
  }
  lastDiscovered = discovered;

  const unpaired = discovered.filter((p) => !p.trusted);
  nearby.innerHTML = "";
  if (unpaired.length === 0) {
    const box = el("div", "empty");
    box.appendChild(el("p", "muted", "No unpaired devices seen on your network yet."));
    nearby.appendChild(box);
    return;
  }

  for (const p of unpaired) {
    const row = el("div", "rowitem");
    row.appendChild(el("span", "badge", "nearby"));
    const grow = el("div", "grow");
    grow.appendChild(el("div", "name", p.name || "(unnamed)"));
    const ip = (p.addrs && p.addrs[0]) || "?";
    grow.appendChild(el("div", "sub", `${ip} · ${p.id_short} · discovered, not paired`));
    row.appendChild(grow);
    const btn = el("button", "btn small primary", "Pair");
    btn.addEventListener("click", () => {
      // Dial the peer's *pairing* port (advertised sync port + 1). The peer must
      // be showing its pairing code ("Show pairing code") for this to connect.
      const pairPort = Number(p.port) + 1;
      startConnectPairing(`${ip}:${pairPort}`, p.name || ip);
    });
    row.appendChild(btn);
    nearby.appendChild(row);
  }
}

// Incoming requests (NAT-60): devices that tried to connect but aren't paired.
// This is a read-only, informational surface — showing an entry grants no trust
// (the daemon already rejected the connection). "Pair" routes into the normal
// mutual, code-confirmed pairing flow; "Dismiss" hides it until it retries.
async function refreshIncoming() {
  const wrap = $("#incoming-wrap");
  const body = $("#incoming-body");
  let attempts = [];
  try {
    const res = await invoke("ipc_incoming");
    attempts = (res && res.attempts) || [];
  } catch {
    attempts = [];
  }

  // Drop anything already paired (it belongs in "Paired devices" now) or
  // dismissed — unless a *newer* attempt has arrived since the dismissal.
  const pairedShorts = new Set(lastPeers.map((p) => p.id_short));
  const pending = attempts.filter((a) => {
    if (pairedShorts.has(a.id_short)) return false;
    const dz = dismissedIncoming.get(a.id);
    return dz == null || Number(a.last_seen_ms) > dz;
  });

  wrap.hidden = pending.length === 0;
  body.innerHTML = "";
  for (const a of pending) {
    const row = el("div", "rowitem incoming");
    row.appendChild(el("span", "badge", "not paired"));
    const grow = el("div", "grow");
    const who = a.name || a.id_short;
    grow.appendChild(el("div", "name", who));
    const ip = a.addr || "?";
    const when =
      Number(a.count) > 1
        ? `${a.count}× · last ${relTime(a.last_seen_ms)}`
        : relTime(a.first_seen_ms);
    grow.appendChild(el("div", "sub", `${ip} tried to connect — not paired · ${when}`));
    row.appendChild(grow);

    const pair = el("button", "btn small primary", "Pair");
    pair.addEventListener("click", () => pairFromIncoming(a));
    row.appendChild(pair);

    const dismiss = el("button", "btn small ghost", "Dismiss");
    dismiss.addEventListener("click", () => {
      dismissedIncoming.set(a.id, Number(a.last_seen_ms) || Date.now());
      refreshIncoming();
    });
    row.appendChild(dismiss);
    body.appendChild(row);
  }
}

// Start pairing with a device that just tried to reach us. If discovery knows
// where it listens, dial its pairing port directly (same as "Nearby" Pair);
// otherwise fall back to showing our code so the mutual, code-confirmed pair can
// still complete. Either way this is ≤2 clicks into the existing pairing modal.
function pairFromIncoming(a) {
  const disc = lastDiscovered.find((d) => d.id === a.id || d.id_short === a.id_short);
  if (disc && disc.port) {
    const ip = a.addr || (disc.addrs && disc.addrs[0]);
    startConnectPairing(`${ip}:${Number(disc.port) + 1}`, a.name || ip);
  } else {
    // We don't know its pairing port — show our code and tell the user the peer
    // needs to accept from their side.
    startListenPairing();
    toast(`Ask ${a.name || a.id_short} to accept the code on their device`, "ok");
  }
}

async function revokePeer(prefix, name) {
  if (!confirm(`Revoke ${name || prefix}? This blocks re-pairing until you run \`ucb revoke --forget\`.`)) {
    return;
  }
  try {
    const res = await invoke("ipc_revoke", { prefix });
    if (!res.ok) toast(res.detail || "Revoke failed.", "err");
    else toast(`Revoked ${name || prefix}`);
  } catch (e) {
    toast(String(e), "err");
  }
  refreshDevices();
}

// Devices actions row.
$("#pair-show-code").addEventListener("click", startListenPairing);
$("#addr-pair").addEventListener("click", () => {
  const addr = $("#addr-input").value.trim();
  if (addr) startConnectPairing(addr, addr);
});
$("#addr-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const addr = e.target.value.trim();
    if (addr) startConnectPairing(addr, addr);
  }
});

// --- Pairing modal (PAIR-2) ------------------------------------------------

let pairMode = null; // "listen" | "connect"

function openPairModal() {
  $("#pair-modal").hidden = false;
  $("#pair-listen-info").hidden = true;
  $("#pair-connecting").hidden = true;
  $("#pair-code-card").hidden = true;
  $("#pair-result").hidden = true;
  $("#pair-uri").textContent = "";
  $("#pair-qr").textContent = "";
  $("#pair-code").textContent = "";
}

async function closePairModal() {
  try {
    await invoke("pair_cancel");
  } catch {}
  pairMode = null;
  $("#pair-modal").hidden = true;
}

$("#pair-modal-close").addEventListener("click", closePairModal);
$("#pair-copy").addEventListener("click", () => {
  const uri = $("#pair-uri").textContent;
  if (navigator.clipboard) navigator.clipboard.writeText(uri).catch(() => {});
});
$("#pair-accept").addEventListener("click", () => confirmPairing(true));
$("#pair-reject").addEventListener("click", () => confirmPairing(false));

async function startListenPairing() {
  pairMode = "listen";
  openPairModal();
  $("#pair-modal-title").textContent = "Show pairing code";
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
  $("#pair-listen-info").hidden = false;
  $("#pair-uri").textContent = first.uri || "";
  $("#pair-qr").textContent = first.qr_text || "";
}

async function startConnectPairing(addr, label) {
  pairMode = "connect";
  openPairModal();
  $("#pair-modal-title").textContent = "Pair a device";
  $("#pair-connecting").hidden = false;
  $("#pair-target").textContent = label || addr;
  try {
    await invoke("pair_connect_start", { addr });
  } catch (e) {
    showPairResult(false, String(e));
  }
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
  $("#pair-listen-info").hidden = true;
  $("#pair-connecting").hidden = true;
  $("#pair-code-card").hidden = true;
}

// Streamed pairing events from the Rust side (both listen + connect flows).
listen("pair://event", (event) => {
  const v = event.payload || {};
  if (v.type === "code") {
    $("#pair-code").textContent = v.code || "";
    const dev = v.device || {};
    $("#pair-peer").textContent = `${dev.name || "device"} (${(dev.id || "").slice(0, 8)})`;
    $("#pair-connecting").hidden = true;
    $("#pair-code-card").hidden = false;
  } else if (v.type === "result") {
    if (v.ok) {
      showPairResult(true, v.name || "device");
      toast(`Paired with ${v.name || "device"} — syncing now`, "ok");
      refreshDevices();
      setTimeout(() => {
        if (pairMode) $("#pair-modal").hidden = true;
      }, 1500);
    } else {
      showPairResult(false, v.message || "declined");
    }
  } else if (v.type === "error") {
    showPairResult(false, v.message || "pairing error");
  } else if (v.type === "closed") {
    if ($("#pair-result").hidden && !$("#pair-modal").hidden) {
      showPairResult(false, "connection closed");
    }
  }
});

// --- Transfers + progress (UX-3/UX-4) --------------------------------------

const transfers = new Map(); // transfer_id -> state
let transfersStreamActive = false;

function ensureTransfersStream() {
  if (transfersStreamActive) return;
  transfersStreamActive = true;
  invoke("transfers_start").catch(() => {
    transfersStreamActive = false;
  });
}

function renderTransfers() {
  const panel = $("#transfers");
  panel.innerHTML = "";
  const visible = [...transfers.values()].filter((t) => t.visible);
  panel.hidden = visible.length === 0;
  for (const t of visible) {
    const box = el("div", "xfer");
    const head = el("div", "xfer-head");
    head.appendChild(el("span", "xfer-name", `${t.dir === "recv" ? "↓" : "↑"} ${t.name}`));
    const pct = t.total ? Math.min(100, Math.round((t.done / t.total) * 100)) : 0;
    const meta = t.speed ? `${pct}% · ${fmtBytes(t.speed)}/s` : `${pct}%`;
    head.appendChild(el("span", "xfer-meta", meta));
    box.appendChild(head);
    const bar = el("div", "bar");
    const fill = el("i");
    fill.style.width = `${pct}%`;
    bar.appendChild(fill);
    box.appendChild(bar);
    panel.appendChild(box);
  }
}

// Update rolling-window speed from chunk fraction * known size.
function updateSpeed(t) {
  const now = Date.now();
  if (t.sizeBytes && t.total) {
    const bytes = (t.done / t.total) * t.sizeBytes;
    if (t.lastTime) {
      const dt = (now - t.lastTime) / 1000;
      if (dt > 0.05) {
        const inst = (bytes - t.lastBytes) / dt;
        t.speed = t.speed ? t.speed * 0.6 + inst * 0.4 : inst; // smoothed
        t.lastBytes = bytes;
        t.lastTime = now;
      }
    } else {
      t.lastBytes = bytes;
      t.lastTime = now;
    }
  }
}

// Reveal a transfer's progress bar only if it is still active past 350ms.
function scheduleVisible(id) {
  setTimeout(() => {
    const t = transfers.get(id);
    if (t) {
      t.visible = true;
      renderTransfers();
    }
  }, 350);
}

listen("transfer://event", (event) => {
  const v = event.payload || {};
  const id = v.transfer_id;
  switch (v.type) {
    case "recv_started": {
      transfers.set(id, {
        dir: "recv",
        name: v.name || "file",
        sizeBytes: Number(v.size) || 0,
        total: 0,
        done: 0,
        visible: false,
        speed: 0,
      });
      scheduleVisible(id);
      break;
    }
    case "recv_progress": {
      const t = transfers.get(id) || { dir: "recv", name: "file", visible: false, speed: 0 };
      t.total = Number(v.total) || t.total;
      t.done = Number(v.received) || t.done;
      updateSpeed(t);
      transfers.set(id, t);
      renderTransfers();
      break;
    }
    case "recv_completed": {
      const t = transfers.get(id);
      const name = (t && t.name) || "file";
      transfers.delete(id);
      renderTransfers();
      if (v.ok) {
        const path = v.path || "";
        toast(
          `Received ${name}`,
          "ok",
          path ? [{ label: "Show in folder", onClick: () => invoke("reveal_in_folder", { path }) }] : []
        );
      } else {
        toast(`Failed to receive ${name}: ${v.detail || ""}`, "err");
      }
      break;
    }
    case "send_progress": {
      const existed = transfers.has(id);
      const t = transfers.get(id) || { dir: "send", name: "Sending file…", visible: false, speed: 0 };
      t.total = Number(v.total) || t.total;
      t.done = Number(v.sent) || t.done;
      transfers.set(id, t);
      if (!existed) scheduleVisible(id);
      renderTransfers();
      break;
    }
    case "send_completed": {
      const t = transfers.get(id);
      const name = v.name || (t && t.name) || "file";
      transfers.delete(id);
      renderTransfers();
      if (v.ok) toast(`Sent ${name}`, "ok");
      else toast(`Failed to send ${name}: ${v.detail || ""}`, "err");
      break;
    }
    case "stream_closed": {
      transfers.clear();
      renderTransfers();
      transfersStreamActive = false;
      // Reconnect shortly if the daemon is still up.
      setTimeout(() => {
        if (daemonUp) ensureTransfersStream();
      }, 1500);
      break;
    }
  }
});

// --- "synced while away" detection (UX-4) ----------------------------------

let prevConnected = new Set();

function detectSyncedAway(status) {
  const now = Date.now();
  const nowConnected = new Set(
    (status.peers || []).filter((p) => p.connected).map((p) => p.id_short)
  );
  for (const id of nowConnected) {
    if (!prevConnected.has(id)) {
      // Peer just connected — check for a burst of arriving clips over ~5s.
      const at = now;
      setTimeout(() => checkSyncedAway(id, at), 5000);
    }
  }
  prevConnected = nowConnected;
}

async function checkSyncedAway(idShort, sinceTs) {
  try {
    const res = await invoke("ipc_history_list", { limit: 20 });
    const entries = (res && res.entries) || [];
    const fresh = entries.filter((e) => Number(e.ts_ms) >= sinceTs);
    if (fresh.length > 3) {
      const peer = lastPeers.find((p) => p.id_short === idShort);
      const who = (peer && peer.name) || idShort;
      toast(`Synced ${fresh.length} clips from ${who} while you were away`, "ok");
    }
  } catch {
    /* best-effort */
  }
}

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
    box.appendChild(el("h2", null, "Sync isn't running"));
    box.appendChild(el("p", "muted", "History lives in the daemon. Start sync first."));
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
    } catch (err) { toast(String(err), "err"); }
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
    } catch (err) { toast(String(err), "err"); }
  });
  row.appendChild(del);

  // `text` is the plain content for text entries (HIST-6 classification input),
  // or null for images/binary which are never blurred.
  return { row, contentEl, text };
}

// --- Settings (auto-file-sync + max file + capture + history-lock) ---------

const MIB = 1024 * 1024;

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
      toast(String(e), "err");
    }
  }
});

// Load current daemon config into the Settings controls.
async function loadConfigIntoSettings() {
  let cfg;
  try {
    cfg = await invoke("ipc_config_get");
  } catch {
    return; // daemon down; onboarding handles it
  }
  if (cfg && typeof cfg === "object") {
    $("#set-autofile").checked = !!cfg.auto_file_sync;
    if (cfg.max_auto_file_bytes != null) {
      $("#set-maxfile").value = Math.max(1, Math.round(Number(cfg.max_auto_file_bytes) / MIB));
    }
  }
}

function showRestartBanner() {
  const banner = $("#restart-banner");
  banner.hidden = false;
  const btn = $("#restart-sync");
  // The one-click restart only works for a GUI-managed daemon.
  btn.hidden = !daemonManaged;
  if (!daemonManaged) {
    $("#restart-msg").textContent =
      "A setting changed. Restart the daemon (e.g. `ucb run`) to apply it.";
  } else {
    $("#restart-msg").textContent = "A setting changed. Restart sync to apply it.";
  }
}

$("#set-autofile").addEventListener("change", async (ev) => {
  try {
    await invoke("ipc_config_set", { autoFileSync: ev.target.checked, maxAutoFileBytes: null });
    showRestartBanner();
  } catch (e) {
    toast(String(e), "err");
  }
});

$("#set-maxfile-save").addEventListener("click", async () => {
  const mib = Math.max(1, Math.round(Number($("#set-maxfile").value) || 0));
  try {
    await invoke("ipc_config_set", { autoFileSync: null, maxAutoFileBytes: mib * MIB });
    toast(`Max file size set to ${mib} MiB`);
    showRestartBanner();
  } catch (e) {
    toast(String(e), "err");
  }
});

$("#restart-sync").addEventListener("click", async () => {
  try {
    await invoke("daemon_restart");
    $("#restart-banner").hidden = true;
    toast("Restarting sync…");
    waitForDaemon();
  } catch (e) {
    toast(String(e), "err");
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

// --- software updates (REL-1) ----------------------------------------------

// Offer to install a found update via a toast with an Install button. Shared by
// the silent launch auto-check and the manual "Check for updates" button.
function offerUpdate(info) {
  toast(
    `Version ${info.version} is available.`,
    "ok",
    [
      {
        label: "Install & restart",
        onClick: async () => {
          toast("Downloading update…");
          try {
            // On success the app relaunches, so this never resolves.
            await invoke("install_update");
          } catch (e) {
            toast(`Update failed: ${e}`, "err");
          }
        },
      },
    ],
    0 // no auto-dismiss — the user should decide
  );
}

// Silent auto-check on launch: only surfaces UI if an update actually exists.
async function autoCheckUpdates() {
  try {
    const info = await invoke("check_for_update");
    if (info && info.available) offerUpdate(info);
  } catch {
    /* offline / no manifest yet — stay silent on launch */
  }
}

// Manual check from Settings: always gives feedback, including "up to date".
$("#check-updates").addEventListener("click", async () => {
  const status = $("#update-status");
  const btn = $("#check-updates");
  btn.disabled = true;
  status.textContent = "Checking…";
  try {
    const info = await invoke("check_for_update");
    if (info && info.available) {
      status.textContent = `Update available: ${info.version}`;
      offerUpdate(info);
    } else {
      status.textContent = "You're up to date.";
    }
  } catch (e) {
    status.textContent = `Update check failed: ${e}`;
  } finally {
    btn.disabled = false;
  }
});

// --- boot ------------------------------------------------------------------

initCapabilities();
pollStatus().then(() => refreshDevices());
autoCheckUpdates();

setInterval(() => {
  pollStatus();
  if ($("#view-devices").classList.contains("is-active")) refreshDevices();
}, 3000);
