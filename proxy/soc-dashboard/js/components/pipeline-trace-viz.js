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

  function init() {
    State.on('pipelineTraces', _renderTraceSelector);
    State.on('selectedTrace', _renderTraceTimeline);
  }

  // ── Trace Selector (top of workflow timeline panel) ──

  function _renderTraceSelector() {
    const traces = State.get('pipelineTraces') || [];
    const container = DOM.$('pipeline-workflow-timeline');
    if (!container) return;

    if (traces.length === 0) {
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
            const last = stages[stages.length - 1];
            const decision = _extractDecision(stages);
            const timeStr = _shortTime(t.started_at);
            const label = `${t.request_id} — ${decision} — ${timeStr}`;
            return `<option value="${t.request_id}" ${t.request_id === _selectedTraceId ? 'selected' : ''}>${label}</option>`;
          }).join('')}
        </select>
        <span style="font-size:var(--text-xs);color:var(--text-muted)" id="trace-count">${traces.length} traces</span>
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

    const completedStages = new Map();
    (trace.stages || []).forEach(s => {
      completedStages.set(s.stage, s);
    });

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
