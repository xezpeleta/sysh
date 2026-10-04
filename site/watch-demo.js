// sysh site — the watch demo, shared by index.html and usage.html.
// One coherent story on loop: routine execs, one denial, one approval
// request answered in the in-web ceremony (argv fetched fresh, an
// argument typed, the token touch). Nothing is left pending at rest.
(function () {
  "use strict";
  var frame = document.getElementById("wd");
  if (!frame) return;
  var rows = document.getElementById("wd-rows");
  var pending = document.getElementById("wd-pending");
  var prow = document.getElementById("wd-prow");
  var count = document.getElementById("wd-count");
  var modal = document.getElementById("wd-modal");
  var margv = document.getElementById("wd-margv");
  var mtyped = document.getElementById("wd-mtyped");
  var mstate = document.getElementById("wd-mstate");
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var MAXROWS = 7;

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, reduced ? 0 : ms); }); }

  function esc(t) {
    return String(t).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function addRow(ev) {
    var tr = document.createElement("tr");
    var badge = '<span class="wd-badge wd-b-' + ev.d + '">' + ev.d + "</span>" +
                (ev.priv ? '<span class="wd-badge wd-b-priv">root</span>' : "");
    tr.innerHTML =
      '<td class="wd-ts">' + esc(ev.t) + "</td>" +
      '<td class="wd-host">' + esc(ev.host) + "</td>" +
      '<td class="wd-key">' + esc(ev.key) + "</td>" +
      '<td class="wd-argv">' + esc(ev.argv) + "</td>" +
      "<td>" + badge + "</td>" +
      '<td class="wd-exit">' + (ev.exit !== undefined ? esc(ev.exit) : "·") + "</td>";
    rows.appendChild(tr);
    while (rows.children.length > MAXROWS) rows.removeChild(rows.firstChild);
  }

  function showPending(p) {
    pending.hidden = false;
    count.textContent = "● 1 pending";
    prow.innerHTML =
      '<span class="wd-pid">' + esc(p.host) + " · " + esc(p.id) + "</span>" +
      '<span class="wd-pargv">' + esc(p.argv) + "</span>" +
      '<span class="wd-here">✓ approve here</span> <span class="wd-copy dim">▸ run in terminal</span>';
  }

  function hidePending() {
    pending.hidden = true;
    count.textContent = "";
  }

  function openModal() {
    margv.textContent = REQ.argv;
    mtyped.value = "";
    mstate.textContent = "";
    modal.hidden = false;
  }
  function hideModal() { modal.hidden = true; }

  async function typeInto(el, text) {
    for (var i = 0; i < text.length; i++) {
      el.value += text[i];
      await sleep(75);
    }
    await sleep(450);
  }

  var REQ = { host: "web01", id: "req_9b3c41d07aa2", argv: "/usr/bin/systemctl restart mariadb" };

  async function run() {
    for (;;) {
      rows.innerHTML = "";
      hidePending();
      hideModal();
      await sleep(900);

      addRow({ t: "14:02:11", host: "web01", key: "sy/web01", argv: "/usr/bin/systemctl reload apache2", d: "allow", exit: 0 });
      await sleep(850);
      addRow({ t: "14:02:14", host: "db01",  key: "sy/db01",  argv: "/usr/bin/pg_dump -f /var/backups/db.sql", d: "allow", exit: 0 });
      await sleep(1000);
      addRow({ t: "14:02:31", host: "web01", key: "sy/web01", argv: "/usr/bin/systemctl restart mariadb", d: "deny", exit: 125 });
      await sleep(1100);

      // the approval request: parked, pending, waiting for a human
      addRow({ t: "14:02:33", host: "web01", key: "sy/web01", argv: "/usr/bin/systemctl restart mariadb", d: "request", priv: true });
      showPending(REQ);

      // the operator clicks "approve here" — the ceremony opens in
      // the page: argv fetched fresh, an argument to type, then touch
      await sleep(1400);
      openModal();
      await sleep(1000);
      await typeInto(mtyped, "mariadb");
      await sleep(500);
      mstate.textContent = "waiting for your token touch…";
      await sleep(1500);
      mstate.innerHTML = '<span class="wd-ok">✓ signature ok: ops-yubi</span>';
      await sleep(1100);
      hideModal();

      // the outcome flows back into the wall
      await sleep(500);
      addRow({ t: "14:03:02", host: "web01", key: "root",    argv: "/usr/bin/systemctl restart mariadb", d: "approve", priv: true });
      await sleep(650);
      addRow({ t: "14:03:02", host: "web01", key: "sy/web01", argv: "/usr/bin/systemctl restart mariadb", d: "result", exit: 0 });
      hidePending();

      // rest state: everything answered, nothing pending
      await sleep(4200);
    }
  }

  run();
})();
