/**
 * MoodleSec SOC Dashboard — Architecture Visualization
 * Static pipeline diagram for examiner understanding.
 */
const ArchitectureViz = (() => {

  function init() {
    const container = DOM.$('architecture-diagram');
    if (container) _render(container);
  }

  function _render(container) {
    const stages = [
      { id: 'browser', label: 'Browser / Client', sub: 'HTTP Request', icon: _iconGlobe(), color: '#64748b' },
      { id: 'proxy', label: 'Reverse Proxy', sub: 'FastAPI + Middleware', icon: _iconServer(), color: '#3b82f6' },
      { id: 'anomaly', label: 'Anomaly Detector', sub: 'Isolation Forest', icon: _iconSearch(), color: '#22d3ee' },
      { id: 'classifier', label: 'Attack Classifier', sub: 'XGBoost', icon: _iconZap(), color: '#f59e0b' },
      { id: 'fp', label: 'FP Reducer', sub: 'RandomForest', icon: _iconFilter(), color: '#a855f7' },
      { id: 'decision', label: 'Decision Engine', sub: 'BLOCK / ALERT / IGNORE', icon: _iconGitBranch(), color: '#ef4444' },
      { id: 'soc', label: 'SOC Queue', sub: 'PENDING → Admin Review', icon: _iconBell(), color: '#f97316' },
      { id: 'admin', label: 'Admin Decision', sub: 'Human-in-the-Loop', icon: _iconUser(), color: '#22c55e' },
      { id: 'enforce', label: 'Enforcement', sub: 'Block / Allow / Forward', icon: _iconShield(), color: '#ef4444' },
    ];

    container.innerHTML = `
      <div class="arch-pipeline">
        ${stages.map((s, i) => `
          <div class="arch-stage" id="arch-${s.id}">
            <div class="arch-stage-icon" style="background:${s.color}20;color:${s.color};border-color:${s.color}40">
              ${s.icon}
            </div>
            <div class="arch-stage-label">${s.label}</div>
            <div class="arch-stage-sub">${s.sub}</div>
          </div>
          ${i < stages.length - 1 ? '<div class="arch-arrow"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg></div>' : ''}
        `).join('')}
      </div>

      <div class="arch-details-grid">
        <div class="arch-detail-card">
          <h4 style="color:var(--accent-cyan)">ML Pipeline (Pre-Forward)</h4>
          <p>Every HTTP request passes through a <strong>three-stage ML pipeline</strong> BEFORE being forwarded to Moodle:</p>
          <ol style="margin:var(--space-2) 0;padding-left:var(--space-4);font-size:var(--text-xs);color:var(--text-secondary);line-height:1.8">
            <li><strong>Anomaly Detection</strong> — Isolation Forest identifies statistically unusual request patterns using 35 features</li>
            <li><strong>Attack Classification</strong> — XGBoost classifier determines the specific attack type (XSS, SQLi, etc.)</li>
            <li><strong>FP Reduction</strong> — RandomForest trained on Stage 1 outputs suppresses false positive predictions</li>
          </ol>
        </div>
        <div class="arch-detail-card">
          <h4 style="color:var(--color-pending)">SOC Workflow (Human-in-the-Loop)</h4>
          <p>When the pipeline detects a threat, the alert enters a <strong>state machine</strong>:</p>
          <div style="font-family:var(--font-mono);font-size:var(--text-xs);color:var(--text-secondary);margin:var(--space-2) 0;line-height:1.8;padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
            PENDING_ADMIN_ACTION<br>
            &nbsp;&nbsp;├─→ ADMIN_BLOCK &nbsp;→ Fingerprint saved → 403 on replay<br>
            &nbsp;&nbsp;├─→ ADMIN_ALLOW → Request passes through<br>
            &nbsp;&nbsp;├─→ ADMIN_IGNORE → No enforcement<br>
            &nbsp;&nbsp;└─→ RESET &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ ML re-evaluates fresh
          </div>
        </div>
        <div class="arch-detail-card">
          <h4 style="color:var(--color-critical)">Enforcement Memory</h4>
          <p>Admin decisions are <strong>persistent</strong>. Once an admin blocks a pattern:</p>
          <ul style="margin:var(--space-2) 0;padding-left:var(--space-4);font-size:var(--text-xs);color:var(--text-secondary);line-height:1.8">
            <li>Request fingerprint (method + path + IP) is saved</li>
            <li>Future matching requests are automatically blocked (HTTP 403)</li>
            <li>Enforcement survives server restarts (JSON persistence)</li>
            <li>RESET clears fingerprint for re-testing</li>
          </ul>
        </div>
      </div>
    `;
  }

  function _iconGlobe() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>'; }
  function _iconServer() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>'; }
  function _iconSearch() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>'; }
  function _iconZap() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>'; }
  function _iconFilter() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>'; }
  function _iconGitBranch() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 01-9 9"/></svg>'; }
  function _iconBell() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>'; }
  function _iconUser() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'; }
  function _iconShield() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'; }

  return { init };
})();
