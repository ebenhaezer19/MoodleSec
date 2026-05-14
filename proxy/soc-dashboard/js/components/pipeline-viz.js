/**
 * MoodleSec SOC Dashboard — ML Pipeline Visualization
 * Animated flow diagram showing the AI security decision pipeline.
 */
const PipelineViz = (() => {
  const NODES = [
    { id: 'pn-request',    label: 'Request',            short: 'REQ' },
    { id: 'pn-features',   label: 'Feature Extraction', short: 'FEAT' },
    { id: 'pn-anomaly',    label: 'Anomaly Detection',  short: 'ANOM' },
    { id: 'pn-classifier', label: 'Attack Classifier',  short: 'CLASS' },
    { id: 'pn-fpreducer',  label: 'FP Reducer',         short: 'FPR' },
    { id: 'pn-decision',   label: 'Decision Engine',    short: 'DEC' },
    { id: 'pn-socqueue',   label: 'SOC Queue',          short: 'SOC' },
    { id: 'pn-enforce',    label: 'Enforcement',        short: 'ENF' },
  ];

  function init() {
    _renderPipeline();
    State.on('alerts', _updatePipelineState);
  }

  function _renderPipeline() {
    const container = DOM.$('pipeline-flow-container');
    if (!container) return;

    const nodesHTML = NODES.map((n, i) => {
      const isLast = i === NODES.length - 1;
      return `
        <div style="display:flex;align-items:center;flex-shrink:0">
          <div class="pipeline-node" id="${n.id}" style="
            background:var(--bg-tertiary);border:1px solid var(--border-default);
            border-radius:var(--radius-lg);padding:var(--space-3) var(--space-4);
            text-align:center;min-width:88px;transition:all var(--transition-base);
            position:relative;
          ">
            <div style="font-size:var(--text-xs);font-weight:600;color:var(--text-primary);margin-bottom:2px">${n.label}</div>
            <div style="font-size:var(--text-xs);color:var(--text-muted)" id="${n.id}-meta">--</div>
            <div style="position:absolute;top:-4px;right:-4px;width:10px;height:10px;border-radius:50%;background:var(--border-default);border:2px solid var(--bg-secondary)" id="${n.id}-dot"></div>
          </div>
          ${!isLast ? `<div style="width:24px;height:2px;background:var(--border-default);flex-shrink:0;position:relative" id="pipe-line-${i}">
            <div style="position:absolute;width:6px;height:6px;background:var(--accent-cyan);border-radius:50%;top:-2px;opacity:0" id="pipe-dot-${i}"></div>
          </div>` : ''}
        </div>`;
    }).join('');

    container.innerHTML = `
      <div style="display:flex;align-items:center;overflow-x:auto;padding:var(--space-4) 0;gap:0;justify-content:center">
        ${nodesHTML}
      </div>
    `;
  }

  function _updatePipelineState() {
    const alerts = State.get('alerts') || [];
    const latest = alerts[0]; // Newest alert
    if (!latest) return;

    // Activate all nodes (pipeline processed)
    NODES.forEach(n => {
      const dot = DOM.$(n.id + '-dot');
      if (dot) {
        dot.style.background = 'var(--color-success)';
        dot.style.boxShadow = '0 0 6px rgba(34,197,94,0.4)';
      }
    });

    // Update meta values
    _setMeta('pn-request', `${latest.method} ${Formatters.truncate(latest.path, 15)}`);
    _setMeta('pn-features', '35 features');
    _setMeta('pn-anomaly', `Score: ${Formatters.decimal(latest.anomaly_score)}`);
    _setMeta('pn-classifier', `${latest.attack_type || 'unknown'}`);
    _setMeta('pn-fpreducer', 'Applied');
    _setMeta('pn-decision', latest.ml_decision_original || 'N/A');
    _setMeta('pn-socqueue', Formatters.statusLabel(latest.status));

    const isBlocked = (latest.status || '').includes('BLOCK');
    _setMeta('pn-enforce', isBlocked ? '403 DENY' : 'Forward');

    // Color the decision node based on result
    const decNode = DOM.$('pn-decision');
    if (decNode) {
      const dec = (latest.ml_decision_original || '').toUpperCase();
      if (dec === 'BLOCK') decNode.style.borderColor = 'var(--color-critical)';
      else if (dec === 'ALERT') decNode.style.borderColor = 'var(--color-medium)';
      else decNode.style.borderColor = 'var(--border-default)';
    }

    // Enforcement node color
    const enfNode = DOM.$('pn-enforce');
    if (enfNode) {
      enfNode.style.borderColor = isBlocked ? 'var(--color-critical)' : 'var(--color-success)';
    }

    // Update latest decision panel
    _renderLatestDecision(latest);

    // Animate flow dots
    _animateFlow();
  }

  function _setMeta(nodeId, text) {
    const el = DOM.$(nodeId + '-meta');
    if (el) el.textContent = text;
  }

  function _renderLatestDecision(alert) {
    const container = DOM.$('pipeline-latest-decision');
    if (!container) return;

    container.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
        <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
          <div style="font-size:var(--text-xs);color:var(--text-muted)">Attack Type</div>
          <div style="font-size:var(--text-md);font-weight:600;color:var(--text-primary);margin-top:2px">${Formatters.attackLabel(alert.attack_type)}</div>
        </div>
        <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
          <div style="font-size:var(--text-xs);color:var(--text-muted)">ML Decision</div>
          <div style="font-size:var(--text-md);font-weight:600;color:var(--text-primary);margin-top:2px">${alert.ml_decision_original || 'N/A'}</div>
        </div>
        <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
          <div style="font-size:var(--text-xs);color:var(--text-muted)">Anomaly Score</div>
          <div style="font-size:var(--text-md);font-weight:600;color:${Formatters.confidenceColor(alert.anomaly_score)};margin-top:2px">${Formatters.decimal(alert.anomaly_score)}</div>
        </div>
        <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
          <div style="font-size:var(--text-xs);color:var(--text-muted)">Confidence</div>
          <div style="font-size:var(--text-md);font-weight:600;color:${Formatters.confidenceColor(alert.confidence)};margin-top:2px">${Formatters.decimal(alert.confidence)}</div>
        </div>
      </div>
      <div style="margin-top:var(--space-3);padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
        <div style="font-size:var(--text-xs);color:var(--text-muted)">Reason</div>
        <div style="font-size:var(--text-sm);color:var(--text-secondary);margin-top:2px">${alert.reason || 'N/A'}</div>
      </div>
      <div style="margin-top:var(--space-3);font-size:var(--text-xs);color:var(--text-muted)">
        Source: ${alert.client_ip} • ${Formatters.timeAgo(alert.timestamp)}
      </div>
    `;
  }

  function _animateFlow() {
    for (let i = 0; i < NODES.length - 1; i++) {
      const dot = DOM.$(`pipe-dot-${i}`);
      if (!dot) continue;
      dot.style.opacity = '1';
      dot.animate([
        { left: '0px', opacity: 0 },
        { left: '4px', opacity: 1 },
        { left: '18px', opacity: 1 },
        { left: '24px', opacity: 0 },
      ], { duration: 1200, delay: i * 150, easing: 'ease-in-out' });
    }
  }

  return { init };
})();
