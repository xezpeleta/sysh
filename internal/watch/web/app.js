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
    `<div class="pending-row">
      <span class="pid">${esc(p.host)} · ${esc(p.id)}</span>
      <span class="pargv">${esc((p.argv || []).join(" "))}</span>
      <span class="pmeta">key=${esc(p.key)} · age ${fmtAge(p.age_sec)}</span>
      <button class="runbtn herebtn" data-host="${esc(p.host)}" data-id="${esc(p.id)}">✓ approve here</button>
      <button class="runbtn" data-host="${esc(p.host)}" data-id="${esc(p.id)}">▸ run in terminal</button>
      <button class="copybtn" data-cmd="sy approve ${esc(p.host)} ${esc(p.id)}">copy</button>
    </div>`;
  // Expired rows leave the panel the moment the poller marks them:
  // the request is refuse-by-default, dead buttons answered nothing,
  // and its story lives in the log. One quiet line says how many
  // went that way, so silence is never the feedback.
  $("pendingrows").innerHTML =
    live.map(row).join("") +
    (expired.length ? `<div class="pexpired">${expired.length} expired request${expired.length > 1 ? "s" : ""} hidden — refuse-by-default; the agent can re-file</div>` : "");
}

document.addEventListener("click", async (e) => {
  const here = e.target.closest(".herebtn");
  if (here && !here.disabled) { openCeremony(here.dataset.host, here.dataset.id); return; }
  const run = e.target.closest(".runbtn");
  if (run && !run.disabled) {
    run.disabled = true;
    run.textContent = "opening…";
    try {
      const r = await fetch("/api/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: run.dataset.host, id: run.dataset.id }),
      });
      if (r.ok) {
        run.textContent = "terminal opened ✓ — finish the ceremony there";
      } else {
        const msg = await r.text();
        run.textContent = `✗ ${msg || "launch failed"}`;
        setTimeout(() => { run.textContent = "▸ run in terminal"; run.disabled = false; }, 4000);
      }
    } catch {
      run.textContent = "✗ cannot reach sy watch";
      setTimeout(() => { run.textContent = "▸ run in terminal"; run.disabled = false; }, 4000);
    }
    return;
  }
  const btn = e.target.closest(".copybtn");
  if (!btn) return;
  navigator.clipboard.writeText(btn.dataset.cmd).then(() => {
    btn.classList.add("copied");
    btn.textContent = "copied ✓";
    setTimeout(() => {
      btn.classList.remove("copied");
      btn.textContent = "copy";
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

// ---------- browser alerts ----------
// Calendar-style: when a new approval request arrives, a native
// browser notification pops — but only because the operator granted
// the permission themselves (the browser asks; the user answers).
// The alert carries argv and key; the ceremony stays on the server —
// the browser remains a renderer that can look, never act.
const bell = $("bellToggle");
let sseGraceUntil = 0;        // replay window after (re)connect: no alerts for history
let firstPendingPoll = true;  // baseline: what is already waiting never alerts
const knownPending = new Set();
let lastAlert = { key: "", at: 0 }; // dedupe between the SSE and poll paths

function alertsOn() {
  return "Notification" in window && Notification.permission === "granted"
    && localStorage.getItem("sywatch-alerts") !== "off";
}

function bellState() {
  if (!("Notification" in window)) {
    bell.textContent = "🔕";
    bell.title = "this browser does not support notifications";
    bell.classList.add("blocked");
    return;
  }
  bell.classList.remove("on", "blocked");
  if (Notification.permission === "denied") {
    bell.textContent = "🔕";
    bell.title = "browser alerts blocked — allow notifications for this site in the browser settings";
    bell.classList.add("blocked");
    return;
  }
  if (alertsOn()) {
    bell.textContent = "🔔";
    bell.title = "browser alerts on (beta) — click to turn off";
    bell.classList.add("on");
    return;
  }
  bell.textContent = "🔕";
  bell.title = Notification.permission === "granted"
    ? "browser alerts off — click to turn on"
    : "click to allow browser alerts on new approval requests (beta)";
}

bell.addEventListener("click", async () => {
  if (!("Notification" in window) || Notification.permission === "denied") return;
  if (Notification.permission !== "granted") {
    await Notification.requestPermission(); // the browser asks; the user answers
    if (Notification.permission === "granted") {
      localStorage.setItem("sywatch-alerts", "on");
      bellState();
      new Notification("sy watch", {
        body: "alerts on — new approval requests will pop here",
        tag: "sywatch-test",
      });
    }
    bellState();
    return;
  }
  // granted: toggle
  const off = localStorage.getItem("sywatch-alerts") === "off";
  localStorage.setItem("sywatch-alerts", off ? "on" : "off");
  bellState();
});

function alertRequest(host, key, argv, tag) {
  // dedupe the two triggers (SSE event and pending poll) for the
  // same request within a short window
  const dedupe = host + " " + (argv || []).join(" ");
  const now = Date.now();
  if (dedupe === lastAlert.key && now - lastAlert.at < 10000) return;
  lastAlert = { key: dedupe, at: now };
  try {
    const n = new Notification("sy watch — approval requested", {
      body: (argv || []).join(" ") + "\n" + host + " · key " + key,
      tag,
      requireInteraction: true, // stays until answered, like a meeting invite
    });
    n.onclick = () => {
      window.focus();
      pollPending();
      const p = $("pending");
      if (!p.hidden) p.scrollIntoView({ behavior: "smooth", block: "nearest" });
      n.close();
    };
  } catch {} // some browsers throw on Notification constructor quirks
}

function maybeAlertFromEvent(ev) {
  if (ev.decision !== "request") return;
  if (Date.now() < sseGraceUntil) return; // replayed history, not news
  if (!alertsOn()) return;
  alertRequest(ev.host, ev.key, ev.argv, "sywatch-req-" + ev.seq);
}

bellState();

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
    const list = await r.json();
    // backstop for a missed SSE event: a request id that was not
    // there on the previous poll alerts too (never on the first
    // poll — what was already waiting when the page opened is the
    // banner's job, not a pop-up)
    if (!firstPendingPoll) {
      for (const p of list) {
        const kid = p.host + "/" + p.id;
        if (!knownPending.has(kid) && !p.expired) {
          alertRequest(p.host, p.key, p.argv, "sywatch-pend-" + kid);
        }
      }
    }
    for (const p of list) knownPending.add(p.host + "/" + p.id);
    firstPendingPoll = false;
    pending = list;
    renderPending();
  } catch {}
}

// ---------- SSE ----------
function connect() {
  const es = new EventSource("/api/events?limit=500");
  es.onopen = () => {
    // the first burst after (re)connecting is replayed history —
    // give it a moment to flush before treating requests as news
    sseGraceUntil = Date.now() + 2500;
  };
  es.onmessage = (m) => {
    try {
      const ev = JSON.parse(m.data);
      appendEvent(ev);
      maybeAlertFromEvent(ev);
    } catch {}
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}

// ---------- boot ----------
pollHosts();
pollPending();
connect();
setInterval(pollHosts, 5000);
setInterval(pollPending, 5000);

// ---------- in-web ceremony ----------
// The browser is the renderer; the watch server is the ceremony:
// it fetches the argv (fresh), shows it here, and signs the exact
// same bytes after the typed argument. The touch happens inside
// ssh-keygen on the server side — a PIN-requiring key says so and
// points at the terminal.
const ceremony = $("ceremony");
let ceremonyCtx = null; // {host, id, token}

function openCeremony(host, id) {
  const state = $("c-state");
  state.textContent = "fetching the request from the host…";
  $("c-argv").textContent = "";
  $("c-meta").textContent = "";
  $("c-typed").value = "";
  $("c-typed").disabled = false;
  $("c-typed").hidden = true;   // revealed only if the challenge is on
  $("c-note").hidden = true;
  $("c-confirm").disabled = true;
  ceremony.hidden = false;

  fetch("/api/ceremony", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host, id }),
  })
    .then(async (r) => {
      if (!r.ok) throw new Error((await r.text()) || "cannot start ceremony");
      return r.json();
    })
    .then((info) => {
      ceremonyCtx = { host, id, token: info.token, challenge: !!info.challenge };
      $("c-argv").textContent = (info.argv || []).join(" ");
      $("c-meta").textContent = `${info.host} · ${info.id} · key ${info.key} · age ${fmtAge(info.age)}`;
      if (info.challenge) {
        $("c-note").hidden = false;
        $("c-note").textContent = "Type the last argument to show you read it:";
        $("c-typed").hidden = false;
        state.textContent = `type “${info.type}” to confirm you read the argv`;
        $("c-typed").focus();
      } else {
        // --no-challenge: the touch is the confirmation
        state.textContent = "";
      }
      $("c-confirm").disabled = false;
    })
    .catch((e) => {
      state.textContent = `✗ ${e.message}`;
      $("c-typed").disabled = true;
    });
}

function confirmCeremony() {
  if (!ceremonyCtx) return;
  const typed = ceremonyCtx.challenge ? $("c-typed").value.trim() : "";
  if (ceremonyCtx.challenge && !typed) return;
  $("c-typed").disabled = true;
  $("c-confirm").disabled = true;
  const state = $("c-state");
  state.textContent = "waiting for your token touch…";

  fetch("/api/ceremony/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      host: ceremonyCtx.host,
      id: ceremonyCtx.id,
      token: ceremonyCtx.token,
      typed,
    }),
  })
    .then(async (r) => {
      const text = await r.text();
      if (!r.ok) throw new Error(text || "ceremony failed");
      return JSON.parse(text);
    })
    .then((res) => {
      state.textContent = `✓ ${res.result.trim().split("\n").pop()}`;
      setTimeout(() => { ceremony.hidden = true; pollPending(); }, 2500);
    })
    .catch((e) => {
      state.textContent = `✗ ${e.message}`;
      $("c-typed").value = "";
      $("c-typed").disabled = false;
    });
}

document.addEventListener("click", (e) => {
  if (e.target.closest("#c-confirm")) { confirmCeremony(); return; }
  if (e.target.closest("#c-cancel") || e.target.id === "ceremony") {
    ceremony.hidden = true;
    ceremonyCtx = null;
  }
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !ceremony.hidden) { ceremony.hidden = true; ceremonyCtx = null; }
  if (e.key === "Enter" && !ceremony.hidden && ! $("c-confirm").disabled) { confirmCeremony(); }
});
