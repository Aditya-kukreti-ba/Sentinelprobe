/* ═══════════════════════════════════════════════════════════════
   SentinelProbe — probe.js
   Fixed: window.probe, history storage, export fallback
═══════════════════════════════════════════════════════════════ */

class ProbeEngine {
  constructor(config) {
    this.config     = config;
    this.history    = [];
    this.isRunning  = false;
    this.lastResult = null;

    // FIX 1 — expose globally so ALL inline onclick handlers resolve
    window.probe = this;

    this._bindDOM();
    this._loadHistory();
    this._renderHistory();
  }

  // ── DOM ───────────────────────────────────────────────────
  _bindDOM() {
    this.modelSel    = document.getElementById('model-select');
    this.promptSel   = document.getElementById('prompt-select');
    this.promptTA    = document.getElementById('prompt-input');
    this.maxTokInput = document.getElementById('max-tokens');
    this.runBtn      = document.getElementById('run-btn');
    this.termBody    = document.getElementById('terminal-body');
    this.exportBtn   = document.getElementById('export-btn');
    this.histList    = document.getElementById('history-list');
    this.scoreNum    = document.getElementById('score-num');
    this.scoreFill   = document.getElementById('score-fill');
    this.scoreBadge  = document.getElementById('score-badge');
    this.findsList   = document.getElementById('findings-list');

    // Preset select → fills textarea
    if (this.promptSel) {
      this.promptSel.addEventListener('change', () => {
        const v = this.promptSel.value;
        if (v && this.promptTA) {
          this.promptTA.value = v;
          this.promptTA.dispatchEvent(new Event('input'));
          this.promptTA.focus();
        }
      });
    }

    // Chips → fill textarea
    document.querySelectorAll('.prompt-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        if (this.promptTA) {
          this.promptTA.value = chip.dataset.prompt;
          this.promptTA.dispatchEvent(new Event('input'));
          this.promptTA.focus();
        }
      });
    });

    if (this.runBtn)    this.runBtn.addEventListener('click',   () => this.run());
    // FIX 2 — also bind via addEventListener so export works even if onclick attr fails
    if (this.exportBtn) this.exportBtn.addEventListener('click', () => this.exportJSON());

    const cb = document.getElementById('clear-history');
    if (cb) cb.addEventListener('click', () => this.clearHistory());

    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') this.run();
    });
  }

  // ── Run ───────────────────────────────────────────────────
  async run() {
    if (this.isRunning) return;

    const model   = this.modelSel?.value;
    const prompt  = this.promptTA?.value?.trim();
    const maxToks = parseInt(this.maxTokInput?.value || '500');

    if (!prompt) { this._log([{ text: '⚠  Enter a prompt first.', cls: 'warn' }]); return; }
    // empty model = Auto — server picks best for attack type

    this.isRunning = true;
    this._setRunning(true);
    this._clearTerm();

    this._log([
      { text: '# SentinelProbe — ' + this.config.attackType, cls: 'comment' },
      { text: '$ probe run --model ' + model, cls: 'cmd' },
      { text: '→ Sending payload...', cls: 'data' },
    ]);

    try {
      const res  = await fetch('/api/probe', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ model, prompt, attackType: this.config.attackType, maxTokens: maxToks }),
      });
      const data = await res.json();

      if (!res.ok) {
        this._log([
          { text: '',                                         cls: 'plain' },
          { text: '✗ Error: ' + (data.error || 'Unknown'),   cls: 'error' },
          ...(data.hint ? [{ text: '  Hint: ' + data.hint,   cls: 'warn'  }] : []),
        ]);
        this._setRunning(false);
        this.isRunning = false;
        return;
      }

      const a = data.analysis;
      this._log([
        { text: '',                                 cls: 'plain'   },
        { text: '# Model: ' + data.model,          cls: 'comment' },
        { text: '# Response',                      cls: 'comment' },
        { text: data.response || '(empty)',         cls: 'data'    },
        { text: '',                                 cls: 'plain'   },
        { text: '# Analyzer Results',              cls: 'comment' },
        ...(a.findings.length === 0
          ? [{ text: '✓ No sensitive findings detected', cls: 'success' }]
          : a.findings.map(f => ({ text: '! ' + f, cls: 'error' }))
        ),
        { text: '', cls: 'plain' },
        {
          text: '→ Risk Score : ' + a.riskScore + ' / 95  (' + a.riskLevel + ')',
          cls:  a.riskLevel === 'High' ? 'error' : a.riskLevel === 'Medium' ? 'warn' : 'success',
        },
        { text: '→ Chars      : ' + a.responseLength, cls: 'comment' },
        { text: '→ Time       : ' + data.timestamp,   cls: 'comment' },
      ]);

      // Set lastResult FIRST — before any rendering so export always works
      this.lastResult = data;
      this._updateRisk(a);
      this._addHistory(data);

    } catch (err) {
      this._log([{ text: '✗ Network error: ' + err.message, cls: 'error' }]);
    }

    this._setRunning(false);
    this.isRunning = false;
  }

  // ── Terminal ──────────────────────────────────────────────
  _clearTerm() {
    if (this.termBody) this.termBody.innerHTML = '';
  }

  _log(lines) {
    if (!this.termBody) return;
    const cur = this.termBody.querySelector('.t-cursor');
    if (cur) cur.remove();
    lines.forEach(({ text, cls }) => {
      const d = document.createElement('div');
      d.className  = 't-' + (cls || 'plain');
      d.textContent = text;
      this.termBody.appendChild(d);
    });
    const newCur = document.createElement('span');
    newCur.className = 't-cursor';
    this.termBody.appendChild(newCur);
    this.termBody.scrollTop = this.termBody.scrollHeight;
  }

  // ── Risk panel ────────────────────────────────────────────
  _updateRisk(a) {
    if (this.scoreNum) this.scoreNum.textContent = a.riskScore;

    if (this.scoreFill) {
      this.scoreFill.style.strokeDashoffset = 283 - (283 * a.riskScore / 95);
      this.scoreFill.setAttribute('class', 'score-fill ' + a.riskColor);
    }

    if (this.scoreBadge) {
      const icons = { low: '🟢', medium: '🟡', high: '🔴' };
      this.scoreBadge.innerHTML  =
        '<span class="badge-dot dot-' + a.riskColor + '"></span> ' +
        (icons[a.riskColor] || '') + ' ' + a.riskLevel;
      this.scoreBadge.className = 'score-level-badge badge-' + a.riskColor;
    }

    if (this.findsList) {
      this.findsList.innerHTML = a.findings.length === 0
        ? '<div class="no-findings"><span class="no-findings-dot"></span>No sensitive data detected</div>'
        : a.findings.map(f =>
            '<div class="finding-item"><span class="finding-dot"></span>' + this._esc(f) + '</div>'
          ).join('');
    }
  }

  _updateRiskPanel(a) { this._updateRisk(a); }

  // ── History ───────────────────────────────────────────────
  _addHistory(data) {
    this.history.unshift({
      id:         Date.now(),
      model:      data.model,
      attackType: data.attackType,
      riskScore:  data.analysis.riskScore,
      riskLevel:  data.analysis.riskLevel,
      riskColor:  data.analysis.riskColor,
      findings:   data.analysis.findings,
      prompt:     data.prompt,
      response:   data.response,
      timestamp:  data.timestamp,
    });
    if (this.history.length > 30) this.history.pop();
    this._saveHistory();
    this._renderHistory();
    this._updateSidebarScore();
  }

  _renderHistory() {
    if (!this.histList) return;
    if (!this.history.length) {
      this.histList.innerHTML =
        '<div class="history-empty">No attacks run yet. Results appear here after each run.</div>';
      return;
    }
    // FIX 4 — use window.probe.replayHistory so onclick always resolves
    this.histList.innerHTML = this.history.map((e, i) => `
      <div class="history-item" onclick="window.probe.replayHistory(${i})" title="Click to replay">
        <div style="min-width:0">
          <div class="hist-model">${this._esc((e.model || '').split('/').pop())}</div>
          <div class="hist-time">${this._fmtTime(e.timestamp)}</div>
        </div>
        <span class="hist-badge hist-${e.riskColor}">${e.riskLevel}</span>
        <span class="hist-badge" style="background:rgba(200,184,154,0.08);color:var(--text-dim)">${e.riskScore}</span>
      </div>`
    ).join('');
  }

  replayHistory(i) {
    const e = this.history[i];
    if (!e) return;
    if (this.promptTA) this.promptTA.value = e.prompt;
    if (this.modelSel) {
      const opt = [...(this.modelSel.options || [])].find(o => o.value === e.model);
      if (opt) this.modelSel.value = e.model;
    }
    this._clearTerm();
    this._log([
      { text: '# Replayed — ' + this._fmtTime(e.timestamp), cls: 'comment' },
      { text: '# Model: ' + e.model,                         cls: 'comment' },
      { text: '',                                             cls: 'plain'   },
      { text: e.response || '(no response stored)',           cls: 'data'    },
    ]);
    this._updateRisk({
      riskScore: e.riskScore,
      riskLevel: e.riskLevel,
      riskColor: e.riskColor,
      findings:  e.findings,
    });
    // Allow exporting replayed entry
    this.lastResult = e;
  }

  clearHistory() {
    this.history    = [];
    this.lastResult = null;
    this._saveHistory();
    this._renderHistory();
    this._updateSidebarScore();
  }

  // FIX 5 — unique storage key per attack type
  _saveHistory() {
    try {
      sessionStorage.setItem('sp_hist_' + this.config.attackType, JSON.stringify(this.history));
    } catch (_) {}
  }

  _loadHistory() {
    try {
      const raw = sessionStorage.getItem('sp_hist_' + this.config.attackType);
      this.history = raw ? JSON.parse(raw) : [];
    } catch (_) {
      this.history = [];
    }
  }

  _updateSidebarScore() {
    const last = this.history[0];
    const el   = document.getElementById('sscore-' + this.config.attackType);
    if (el) el.textContent = last ? last.riskScore : '—';
  }

  // ── Export ────────────────────────────────────────────────
  exportJSON() {
    // FIX 6 — fall back to history[0] if lastResult is somehow null
    const target = this.lastResult || this.history[0];
    if (!target) {
      // Should never reach here after a run, but show a clear message if it does
      this._log([{ text: '⚠  No results to export yet. Run an attack first.', cls: 'warn' }]);
      return;
    }
    const blob = new Blob([JSON.stringify(target, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'sentinelprobe-' + this.config.attackType + '-' + Date.now() + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Helpers ───────────────────────────────────────────────
  _setRunning(on) {
    if (!this.runBtn) return;
    this.runBtn.disabled = on;
    this.runBtn.classList.toggle('loading', on);
    const lbl = this.runBtn.querySelector('.run-btn-label');
    if (lbl) lbl.textContent = on ? 'Running Attack…' : 'Run Attack  ⌘↵';
  }

  _esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  _fmtTime(ts) {
    try {
      return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (_) { return String(ts); }
  }
}

// ── Sidebar builder ───────────────────────────────────────────
function buildSidebar(activeType) {
  const el = document.getElementById('sidebar-nav');
  if (!el) return;
  const links = [
    { type: 'training-data-leak', label: 'Training Data Leak',       dot: 'dot-red'    },
    { type: 'prompt-induced',     label: 'Prompt-Induced Disclosure', dot: 'dot-orange' },
    { type: 'inversion-attack',   label: 'Inversion Attack',          dot: 'dot-yellow' },
    { type: 'unintentional-pii',  label: 'Unintentional PII',         dot: 'dot-purple' },
    { type: 'business-ip-leak',   label: 'Business IP Leak',          dot: 'dot-blue'   },
  ];
  el.innerHTML = links.map(l => `
    <a href="/pages/${l.type}" class="sidebar-link ${l.type === activeType ? 'active' : ''}">
      <span class="sidebar-link-dot ${l.dot}"></span>
      <span class="sidebar-link-label">${l.label}</span>
      <span class="sidebar-link-score" id="sscore-${l.type}">—</span>
    </a>`
  ).join('');
}