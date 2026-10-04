// sy watch UI — vanilla JS, no build step. SSE in, DOM out, nothing
// ever leaves the browser (and the browser can only look, never act).
"use strict";

const $ = (id) => document.getElementById(id);

// ---------- state ----------
let events = [];          // all events received, newest last
let hosts = [];           // last /api/hosts
let pending = [];         // last /api/pending
let seenSeq = 0;
let filters = {
  search: "",
  host: "",
  key: "",
  decisions: { allow: true, deny: true, request: true, approval: true, other: true },
};
const MAX_EVENTS = 5000;

// ---------- decision rendering ----------
function decisionClass(ev) {
  switch (ev.decision) {
    case "allow": case "builtin": return "b-allow";
    case "deny": case "malformed": case "lockdown": case "internal":
    case "timeout": return "b-deny";
    case "request": return "b-request";
    case "approve": return "b-approve";
    case "reject": return "b-reject";
    case "result": return "b-result";
    case "privileged": return "b-allow";
    default: return "b-other";
  }
}
function decisionGroup(ev) {
  switch (ev.decision) {
    case "allow": case "builtin": case "privileged": return "allow";
    case "deny": case "malformed": case "lockdown": case "internal":
    case "timeout": return "deny";
    case "request": return "request";
    case "approve": case "reject": case "result": return "approval";
    default: return "other";
  }
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function fmtTime(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return "?";
  return d.toLocaleTimeString(undefined, { hour12: false });
}
function fmtAge(sec) {
  if (sec < 60) return sec + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m" + (sec % 60) + "s";
  return Math.floor(sec / 3600) + "h" + Math.floor((sec % 3600) / 60) + "m";
}

// ---------- filtering ----------
function passesFilters(ev) {
  if (filters.host && ev.host !== filters.host) return false;
  if (filters.key && ev.key !== filters.key) return false;
  if (!filters.decisions[decisionGroup(ev)]) return false;
  if (filters.search) {
    const hay = (ev.argv || []).join(" ") + " " + ev.key + " " + ev.host + " " + ev.decision;
    if (!hay.toLowerCase().includes(filters.search.toLowerCase())) return false;
  }
  return true;
}

// ---------- events table ----------
function renderRow(ev, isNew) {
  const tr = document.createElement("tr");
  if (isNew) tr.className = "new";
  const badge = `<span class="badge ${decisionClass(ev)}">${esc(ev.decision)}</span>` +
    (ev.priv ? `<span class="badge b-priv">priv</span>` : "");
  const exit = ev.exit !== null && ev.exit !== undefined ? String(ev.exit) : "·";
  const ms = ev.dur_ms !== null && ev.dur_ms !== undefined ? String(ev.dur_ms) : "·";
  tr.innerHTML =
    `<td class="ts">${esc(fmtTime(ev.ts))}</td>` +
    `<td class="host">${esc(ev.host)}</td>` +
    `<td class="key">${esc(ev.key)}</td>` +
    `<td class="argv">${esc((ev.argv || []).join(" "))}</td>` +
    `<td>${badge}</td>` +
    `<td class="exit">${esc(exit)}</td>` +
    `<td class="ms">${esc(ms)}</td>`;
  return tr;
}

function rebuildRows() {
  const tbody = $("rows");
  tbody.innerHTML = "";
  const visible = events.filter(passesFilters);
  const frag = document.createDocumentFragment();
  for (const ev of visible) frag.appendChild(renderRow(ev, false));
  tbody.appendChild(frag);
  $("empty").style.display = visible.length ? "none" : "flex";
  updateStats();
}

function appendEvent(ev) {
  if (ev.seq <= seenSeq) return;
  seenSeq = ev.seq;
  events.push(ev);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  if (!passesFilters(ev)) { updateStats(); return; }
  const tbody = $("rows");
  tbody.appendChild(renderRow(ev, true));
  $("empty").style.display = "none";
  if ($("autoscroll").checked) {
    const wrap = $("tablewrap");
    wrap.scrollTop = wrap.scrollHeight;
  }
  updateStats();
}

// ---------- hosts ----------
function renderHosts() {
  const bar = $("hostbar");
  if (!hosts.length) { bar.innerHTML = '<span class="pill idle">no hosts</span>'; return; }
  bar.innerHTML = hosts.map((h) =>
    `<span class="pill ${esc(h.state)}" title="${esc(h.last_error || "")}">${esc(h.name)}</span>`).join("");
  syncOptions("hostfilter", hosts.map((h) => h.name));
}

// ---------- pending approvals ----------
function renderPending() {
  const panel = $("pending");
  const live = pending.filter((p) => !p.expired);
  const expired = pending.filter((p) => p.expired);
  const count = document.getElementById("pendingcount");
  count.textContent = live.length ? `● ${live.length} pending` : "";
  if (!pending.length) { panel.hidden = true; return; }
  panel.hidden = false;

  const row = (p) =>
    `<div class="pending-row${p.expired ? " expired" : ""}">
      <span class="pid">${esc(p.host)} · ${esc(p.id)}</span>
      <span class="pargv">${esc((p.argv || []).join(" "))}</span>
      <span class="pmeta">key=${esc(p.key)} · age ${fmtAge(p.age_sec)}${p.expired ? " · expired (refuse-by-default)" : ""}</span>
      <button class="copybtn" data-cmd="sy approve ${esc(p.host)} ${esc(p.id)}">copy: sy approve ${esc(p.host)} ${esc(p.id.slice(0, 18))}…</button>
    </div>`;
  // live first — those are the actionable ones; expired trail after,
  // faded, as the historical record of what was never answered
  $("pendingrows").innerHTML =
    live.map(row).join("") + expired.map(row).join("");
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".copybtn");
  if (!btn) return;
  navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
    btn.classList.add("copied");
    btn.textContent = "copied ✓";
    setTimeout(() => {
      btn.classList.remove("copied");
      const [_, h, id] = btn.dataset.cmd.split(" ").slice(-3);
      btn.textContent = `copy: sy approve ${h} ${id.slice(0, 18)}…`;
    }, 1200);
  });
});

// clicking the pending count scrolls the panel into view
$("pendingcount").addEventListener("click", () => {
  const p = $("pending");
  if (!p.hidden) p.scrollIntoView({ behavior: "smooth", block: "nearest" });
});

// ---------- filter option syncing ----------
function syncOptions(selectId, values) {
  const sel = $(selectId);
  const cur = sel.value;
  const label = selectId === "hostfilter" ? "all hosts" : "all keys";
  const seen = new Set();
  let html = `<option value="">${label}</option>`;
  for (const v of values.sort()) {
    if (seen.has(v)) continue;
    seen.add(v);
    html += `<option value="${esc(v)}">${esc(v)}</option>`;
  }
  if (cur && !seen.has(cur)) html += `<option value="${esc(cur)}">${esc(cur)}</option>`;
  sel.innerHTML = html;
  sel.value = cur;
}

$("search").addEventListener("input", (e) => { filters.search = e.target.value; rebuildRows(); });
$("hostfilter").addEventListener("change", (e) => { filters.host = e.target.value; rebuildRows(); });
$("keyfilter").addEventListener("change", (e) => { filters.key = e.target.value; rebuildRows(); });
$("decisionchips").addEventListener("change", (e) => {
  filters.decisions[e.target.value] = e.target.checked;
  rebuildRows();
});

function updateStats() {
  const visible = $("rows").children.length;
  $("stats").textContent =
    `${events.length} events buffered · ${visible} shown · ${hosts.length} hosts` +
    (hosts.length ? ` · ${hosts.filter((h) => h.state === "following").length} following` : "");
}

// ---------- theme ----------
const savedTheme = localStorage.getItem("sywatch-theme");
if (savedTheme) document.body.dataset.theme = savedTheme;
$("themeToggle").addEventListener("click", () => {
  const next = document.body.dataset.theme === "dark" ? "light" : "dark";
  document.body.dataset.theme = next;
  localStorage.setItem("sywatch-theme", next);
});

// ---------- polling loops ----------
async function pollHosts() {
  try {
    const r = await fetch("/api/hosts");
    hosts = await r.json();
    renderHosts();
    updateStats();
  } catch {}
}
async function pollPending() {
  try {
    const r = await fetch("/api/pending");
    pending = await r.json();
    renderPending();
  } catch {}
}

// ---------- SSE ----------
function connect() {
  const es = new EventSource("/api/events?limit=500");
  es.onmessage = (m) => {
    try { appendEvent(JSON.parse(m.data)); } catch {}
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}

// ---------- boot ----------
pollHosts();
pollPending();
connect();
setInterval(pollHosts, 5000);
setInterval(pollPending, 5000);
