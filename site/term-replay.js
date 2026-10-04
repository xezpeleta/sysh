// sysh site: animated plain-terminal replay — typed ssh commands against a
// sysh host, with outputs and allow/deny marks. Written for this site
// (MIT, like the repo); the player pattern follows pi-replay.js
// (Apache-2.0): IntersectionObserver start, Skip/Replay button,
// prefers-reduced-motion renders the final state.
//
// Data format (term-demo.json):
//   { "title": "…", "lines": [
//     { "c": "ssh … 'argv'", "o": "output", "m": "ok|deny|priv", "l": "override label" },
//     { "n": "# comment line" } ] }
(function () {
  var CANCELLED = {};
  var observer = null;

  var MARKS = {
    ok: { cls: 'ok', glyph: '✓', label: 'allowed' },
    deny: { cls: 'no', glyph: '✗', label: 'denied by policy — exit 125' },
    req: { cls: 'req', glyph: '?', label: 'operator approval required — exit 30' },
    priv: { cls: 'ok', glyph: '✓', label: 'pre-authorized root verb' },
    c: { cls: 'c', glyph: '', label: '' }
  };

  function node(tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text != null) el.textContent = text;
    return el;
  }

  function reduced() {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function TermReplay(figure, data) {
    this.figure = figure;
    this.data = data;
    this.run = 0;
    this.playing = false;
    this.build();
  }

  TermReplay.prototype.build = function () {
    var self = this;
    var root = node('div', 'term-window');
    root.setAttribute('aria-hidden', 'true');
    var bar = node('div', 'term-bar');
    bar.appendChild(node('i'));
    bar.appendChild(node('i'));
    bar.appendChild(node('i'));
    bar.appendChild(node('span', 'term-title', this.data.title || ''));
    this.body = node('div', 'term-body');
    root.appendChild(bar);
    root.appendChild(this.body);

    var fallback = this.figure.querySelector('.term-replay__fallback');
    if (fallback) fallback.hidden = true;
    var caption = this.figure.querySelector('figcaption');
    this.figure.insertBefore(root, caption || null);

    this.button = node('button', 'term-replay__button', 'Skip');
    this.button.type = 'button';
    this.button.addEventListener('click', function () {
      if (self.playing) self.showFinal();
      else self.play();
    });
    (caption || this.figure).appendChild(this.button);
  };

  TermReplay.prototype.wait = function (run, ms) {
    var self = this;
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        if (run === self.run) resolve(); else reject(CANCELLED);
      }, ms);
    });
  };

  TermReplay.prototype.line = function (cls) {
    var l = node('div', 'tl' + (cls ? ' ' + cls : ''));
    this.body.appendChild(l);
    this.body.scrollTop = this.body.scrollHeight;
    return l;
  };

  TermReplay.prototype.follow = function () {
    this.body.scrollTop = this.body.scrollHeight;
  };

  // Fully renders one entry (used by showFinal and after typing).
  TermReplay.prototype.renderEntry = function (entry) {
    if (entry.n) {
      this.line('c').textContent = entry.n;
      return;
    }
    var cmd = this.line();
    cmd.appendChild(node('span', 'p', '$ '));
    cmd.appendChild(node('span', 'typed', entry.c));
    var last = cmd;
    if (entry.o) {
      var out = entry.o.split('\n');
      for (var i = 0; i < out.length; i++) {
        last = this.line('out');
        last.textContent = out[i];
      }
    }
    if (entry.m) {
      var mk = MARKS[entry.m];
      var mark = node('span', 'mk ' + mk.cls,
        (mk.glyph ? mk.glyph + ' ' : '') + (entry.l || mk.label));
      last.appendChild(mark);
    }
  };

  TermReplay.prototype.showFinal = function () {
    this.run++;
    this.playing = false;
    this.body.textContent = '';
    for (var i = 0; i < this.data.lines.length; i++) {
      this.renderEntry(this.data.lines[i]);
    }
    this.body.scrollTop = 0;
    this.button.textContent = 'Replay';
  };

  TermReplay.prototype.play = function () {
    var self = this;
    var run = ++this.run;
    this.playing = true;
    this.button.textContent = 'Skip';
    this.body.textContent = '';
    this.sequence(run).then(function () {
      if (run !== self.run) return;
      self.playing = false;
      self.button.textContent = 'Replay';
    }, function (error) {
      if (error !== CANCELLED) throw error;
    });
  };

  TermReplay.prototype.sequence = async function (run) {
    var lines = this.data.lines;
    for (var e = 0; e < lines.length; e++) {
      var entry = lines[e];
      if (entry.n) {
        this.line('c').textContent = entry.n;
        await this.wait(run, 400);
        continue;
      }
      // type the command
      var cmd = this.line();
      cmd.appendChild(node('span', 'p', '$ '));
      var typed = node('span', 'typed');
      var cur = node('span', 'cur', ' ');
      cmd.appendChild(typed);
      cmd.appendChild(cur);
      for (var i = 1; i <= entry.c.length; i++) {
        typed.textContent = entry.c.slice(0, i);
        this.follow();
        await this.wait(run, 11 + (entry.c[i - 1] === ' ' ? 22 : 0));
      }
      await this.wait(run, 130);
      cur.remove();
      // output lines
      var last = cmd;
      if (entry.o) {
        var out = entry.o.split('\n');
        for (var o = 0; o < out.length; o++) {
          last = this.line('out');
          last.textContent = out[o];
          this.follow();
          await this.wait(run, 60);
        }
      }
      // mark
      if (entry.m) {
        var mk = MARKS[entry.m];
        var mark = node('span', 'mk ' + mk.cls,
          (mk.glyph ? mk.glyph + ' ' : '') + (entry.l || mk.label));
        last.appendChild(mark);
        this.follow();
      }
      await this.wait(run, 430);
    }
  };

  function start(figure) {
    var replay = figure.__termReplay;
    if (!replay || replay.started) return;
    replay.started = true;
    if (observer) observer.unobserve(figure);
    if (reduced()) replay.showFinal();
    else replay.play();
  }

  function getObserver() {
    if (observer || typeof IntersectionObserver !== 'function') return observer;
    observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) start(entry.target);
      });
    }, { threshold: 0.45 });
    return observer;
  }

  function boot() {
    document.querySelectorAll('[data-term-replay]').forEach(function (figure) {
      if (figure.dataset.replayInitialized) return;
      figure.dataset.replayInitialized = 'true';
      fetch(figure.getAttribute('data-term-replay'))
        .then(function (response) {
          if (!response.ok) throw new Error('HTTP ' + response.status);
          return response.json();
        })
        .then(function (data) {
          if (!figure.isConnected) return;
          figure.__termReplay = new TermReplay(figure, data);
          var obs = getObserver();
          if (obs) obs.observe(figure); else start(figure);
        })
        .catch(function () {
          // Keep the static transcript.
        });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
