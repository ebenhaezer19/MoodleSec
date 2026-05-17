/**
 * MoodleSec SOC Dashboard — Pipeline Trace Visualizer
 * Explainable AI pipeline step-by-step trace rendering.
 */
const PipelineTraceViz = (() => {
  const STAGE_META = {
    request_received:   { label: 'Request Received',   icon: '📥' },
    feature_extraction: { label: 'Feature Extraction',  icon: '🔬' },
    anomaly_detection:  { label: 'Anomaly Detection',   icon: '📡' },
    attack_classifier:  { label: 'Attack Classifier',   icon: '🎯' },
    fp_reducer:         { label: 'FP Reducer',          icon: '🧹' },
    decision_engine:    { label: 'Decision Engine',     icon: '⚖️' },
    soc_queue:          { label: 'SOC Queue',           icon: '📋' },
    enforcement:        { label: 'Enforcement',         icon: '🛡️' },
  };

  const STAGE_ORDER = Object.keys(STAGE_META);

  let _selectedTraceId = null;
  let _showBenign = false;

  function init() {
    State.on('pipelineTraces', _renderTraceSelector);
    State.on('selectedTrace', _renderTraceTimeline);
  }

  // ── Benign filter ──
  // A trace is benign ONLY if ALL of these are true:
  // - No ALERT/BLOCK decision found in any stage
  // - Path is a static asset, OR decision is IGNORE, OR soc_queue is "not queued (benign)"
  const STATIC_PATH_PATTERNS = ['/favicon.ico', '/dashboard/css/', '/dashboard/js/', '/dashboard/img/'];
  const STATIC_EXT_PATTERNS = ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.woff', '.ico'];

  function _isBenignTrace(t) {
    const stages = t.stages || [];
    if (stages.length === 0) return true;

    // First pass: check if any stage has ALERT/BLOCK — if so, NEVER benign
    let hasAlertOrBlock = false;
    let hasIgnoreDecision = false;
    let path = '';

    for (const s of stages) {
      // Extract path
      if (s.stage === 'request_received' && typeof s.details === 'object' && s.details) {
        path = String(s.details.path || '');
      }

      const d = s.details;

      // Check object details for decision
      if (typeof d === 'object' && d) {
        const decision = String(d.decision || '').toUpperCase();
        if (decision === 'ALERT' || decision === 'BLOCK') hasAlertOrBlock = true;
        if (decision === 'IGNORE') hasIgnoreDecision = true;
        // Check status for admin actions
        const status = String(d.status || '').toUpperCase();
        if (status.includes('PENDING') || status.includes('ADMIN_BLOCK') || status.includes('ADMIN_ALLOW')) hasAlertOrBlock = true;
      }

      // Check string details for block/alert signals
      if (typeof d === 'string') {
        const dl = d.toLowerCase();
        if (dl.includes('403') || dl.includes('block') || dl.includes('pending admin') || dl.includes('admin')) hasAlertOrBlock = true;
      }
    }

    // NEVER filter ALERT/BLOCK traces
    if (hasAlertOrBlock) return false;

    // Static asset paths are benign
    if (path && STATIC_PATH_PATTERNS.some(bp => path.includes(bp))) return true;
    if (path && STATIC_EXT_PATTERNS.some(ext => path.endsWith(ext))) return true;

    // IGNORE decision is benign
    if (hasIgnoreDecision) return true;

    // Check for explicit benign markers in soc_queue/enforcement
    for (const s of stages) {
      if (typeof s.details === 'string') {
        const dl = s.details.toLowerCase();
        if (dl === 'forwarded') return true; // bare "forwarded" = benign IGNORE
        if (dl.includes('not queued (benign)')) return true;
        if (dl.includes('skipped (static')) return true;
      }
    }

    // Default: NOT benign (show the trace)
    console.debug('[Timeline Filter] keeping trace:', t.request_id, 'path:', path);
    return false;
  }

  // ── Trace Selector (top of workflow timeline panel) ──

  function _renderTraceSelector() {
    const allTraces = State.get('pipelineTraces') || [];
    const container = DOM.$('pipeline-workflow-timeline');
    if (!container) return;

    // Apply benign filter
    const traces = _showBenign ? allTraces : allTraces.filter(t => !_isBenignTrace(t));
    const hiddenCount = allTraces.length - traces.length;
    console.debug('[Timeline Filter]', { hideBenign: !_showBenign, beforeCount: allTraces.length, afterCount: traces.length, hiddenCount });

    if (allTraces.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
          <div class="empty-state-title">No pipeline traces yet</div>
          <div class="empty-state-description">Traces will appear here when requests are processed</div>
        </div>`;
      return;
    }

    if (traces.length === 0 && !_showBenign) {
      container.innerHTML = `
        <div class="empty-state" style="padding:var(--space-4)">
          <div class="empty-state-title" style="font-size:var(--text-sm)">No suspicious traces</div>
          <div class="empty-state-description">${hiddenCount} benign trace${hiddenCount !== 1 ? 's' : ''} hidden</div>
          <button class="btn btn-ghost btn-sm" id="trace-show-all-btn" style="margin-top:var(--space-2)">Show All</button>
        </div>`;
      const btn = document.getElementById('trace-show-all-btn');
      if (btn) btn.addEventListener('click', () => { _showBenign = true; _renderTraceSelector(); });
      return;
    }

    // Auto-select latest if nothing selected
    if (!_selectedTraceId || !traces.find(t => t.request_id === _selectedTraceId)) {
      _selectedTraceId = traces[0].request_id;
    }

    const selectorHTML = `
      <div style="margin-bottom:var(--space-4);display:flex;align-items:center;gap:var(--space-3);flex-wrap:wrap">
        <label style="font-size:var(--text-xs);color:var(--text-muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Request Trace</label>
        <select id="trace-selector" style="
          background:var(--bg-root);color:var(--text-primary);border:1px solid var(--border-default);
          border-radius:var(--radius-md);padding:var(--space-2) var(--space-3);
          font-size:var(--text-sm);font-family:var(--font-mono);min-width:260px;
        ">
          ${traces.map(t => {
            const stages = t.stages || [];
            const decision = _extractDecision(stages);
            const timeStr = _shortTime(t.started_at);
            const label = `${t.request_id} — ${decision} — ${timeStr}`;
            return `<option value="${t.request_id}" ${t.request_id === _selectedTraceId ? 'selected' : ''}>${label}</option>`;
          }).join('')}
        </select>
        <span style="font-size:var(--text-xs);color:var(--text-muted)" id="trace-count">${traces.length} trace${traces.length !== 1 ? 's' : ''}${hiddenCount > 0 ? ` (${hiddenCount} benign hidden)` : ''}</span>
        <button class="btn btn-ghost btn-sm" id="trace-toggle-benign" style="margin-left:auto;font-size:11px">${_showBenign ? '🔍 Hide Benign' : '👁️ Show All'}</button>
      </div>
      <div id="trace-timeline-body"></div>
    `;

    container.innerHTML = selectorHTML;

    // Wire up selector
    const sel = document.getElementById('trace-selector');
    if (sel) {
      sel.addEventListener('change', (e) => {
        _selectedTraceId = e.target.value;
        const selected = traces.find(t => t.request_id === _selectedTraceId);
        if (selected) State.set('selectedTrace', selected);
      });
    }

    // Wire up toggle
    const toggleBtn = document.getElementById('trace-toggle-benign');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => { _showBenign = !_showBenign; _renderTraceSelector(); });
    }

    // Render current selection
    const selected = traces.find(t => t.request_id === _selectedTraceId);
    if (selected) _renderTraceTimeline(selected);
  }

  // ── Vertical Timeline Rendering ──

  function _renderTraceTimeline(trace) {
    if (!trace) trace = State.get('selectedTrace');
    if (!trace) return;

    const body = document.getElementById('trace-timeline-body');
    if (!body) return;

    // ── Cross-reference with current alert state ──
    const alerts = State.get('alerts') || [];
    const matchingAlert = alerts.find(a => a.request_id === trace.request_id);
    const currentStatus = matchingAlert ? matchingAlert.status : null;
    const isResolved = currentStatus && !currentStatus.includes('PENDING');

    const completedStages = new Map();
    (trace.stages || []).forEach(s => {
      completedStages.set(s.stage, { ...s });
    });

    // Overlay current alert status on soc_queue stage — REPLACE stale status
    if (isResolved && completedStages.has('soc_queue')) {
      const sq = completedStages.get('soc_queue');
      if (typeof sq.details === 'object' && sq.details) {
        // Replace status field directly
        sq.details = { ...sq.details, status: currentStatus };
      } else {
        sq.details = { status: currentStatus };
      }
    }

    // Update enforcement stage string to reflect admin decision
    if (isResolved && completedStages.has('enforcement')) {
      const en = completedStages.get('enforcement');
      if (currentStatus === 'ADMIN_BLOCK' || currentStatus === 'ENFORCED_BLOCK') {
        en.details = 'blocked by admin override';
      } else if (currentStatus === 'ADMIN_ALLOW') {
        en.details = 'forwarded (admin allowed)';
      } else if (currentStatus === 'ADMIN_IGNORE') {
        en.details = 'forwarded (admin ignored)';
      } else if (currentStatus === 'RESET') {
        en.details = 'reset for re-evaluation';
      }
    }

    const rows = STAGE_ORDER.map((stageKey, idx) => {
      const meta = STAGE_META[stageKey];
      const event = completedStages.get(stageKey);
      const isLast = idx === STAGE_ORDER.length - 1;

      let statusColor, statusIcon, statusText, detailsHTML, timeText;

      if (event) {
        if (event.status === 'completed') {
          statusColor = 'var(--color-success, #22c55e)';
          statusIcon = '✔';
          statusText = 'Completed';
        } else if (event.status === 'failed') {
          statusColor = 'var(--color-critical, #ef4444)';
          statusIcon = '✖';
          statusText = 'Failed';
        } else {
          statusColor = 'var(--color-medium, #f59e0b)';
          statusIcon = '▶';
          statusText = event.status;
        }
        timeText = _shortTime(event.timestamp);
        detailsHTML = _formatDetails(event.details);
      } else {
        statusColor = 'var(--text-muted, #6b7280)';
        statusIcon = '○';
        statusText = 'Pending';
        timeText = '';
        detailsHTML = '';
      }

      return `
        <div style="display:flex;gap:var(--space-3);position:relative;min-height:48px">
          <!-- Timeline Connector -->
          <div style="display:flex;flex-direction:column;align-items:center;width:24px;flex-shrink:0">
            <div style="
              width:24px;height:24px;border-radius:50%;
              background:${event ? statusColor : 'transparent'};
              border:2px solid ${statusColor};
              display:flex;align-items:center;justify-content:center;
              font-size:11px;color:${event ? '#fff' : statusColor};font-weight:700;
              flex-shrink:0;
            ">${statusIcon}</div>
            ${!isLast ? `<div style="width:2px;flex:1;background:${event ? statusColor : 'var(--border-default)'};min-height:16px;opacity:0.4"></div>` : ''}
          </div>

          <!-- Content -->
          <div style="flex:1;padding-bottom:var(--space-3)">
            <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:2px">
              <span style="font-size:14px">${meta.icon}</span>
              <span style="font-size:var(--text-sm);font-weight:600;color:var(--text-primary)">${meta.label}</span>
              ${timeText ? `<span style="font-size:var(--text-xs);color:var(--text-muted);margin-left:auto;font-family:var(--font-mono)">${timeText}</span>` : ''}
            </div>
            ${detailsHTML ? `<div style="font-size:var(--text-xs);color:var(--text-secondary);margin-left:22px;margin-top:2px">${detailsHTML}</div>` : ''}
          </div>
        </div>
      `;
    }).join('');

    body.innerHTML = `
      <div style="padding:var(--space-2) 0">
        <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3);font-family:var(--font-mono)">
          Request ID: <span style="color:var(--accent-cyan,#06b6d4);font-weight:600">${trace.request_id}</span>
          ${trace.started_at ? ` • ${_shortTime(trace.started_at)}` : ''}
        </div>
        ${rows}
      </div>
    `;
  }

  // ── Helpers ──

  function _extractDecision(stages) {
    for (let i = stages.length - 1; i >= 0; i--) {
      const d = stages[i].details;
      if (typeof d === 'object' && d && d.decision) return d.decision;
      if (typeof d === 'string' && (d.includes('BLOCK') || d.includes('ALLOW'))) return d.split(' ')[0];
    }
    return 'PROCESSED';
  }

  function _shortTime(isoStr) {
    if (!isoStr) return '';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch { return ''; }
  }

  function _formatDetails(details) {
    if (!details) return '';
    if (typeof details === 'string') return _escapeHtml(details);
    if (typeof details === 'object') {
      return Object.entries(details)
        .map(([k, v]) => `<span style="color:var(--text-muted)">${k}:</span> <span style="color:var(--text-primary)">${_escapeHtml(String(v))}</span>`)
        .join(' &nbsp;·&nbsp; ');
    }
    return String(details);
  }

  function _escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { init };
})();
