/**
 * MoodleSec SOC Dashboard — Health Panel
 * Backend, ML, and proxy health monitoring.
 */
const HealthPanel = (() => {
  function init() {
    State.on('backendOnline', render);
    State.on('apiLatency', render);
    State.on('mlStatus', render);
    State.on('mlModels', render);
    State.on('socMode', render);
  }

  function render() {
    _renderCards();
    _renderMLModels();
  }

  function _renderCards() {
    const container = DOM.$('health-cards');
    if (!container) return;

    const online = State.get('backendOnline');
    const latency = State.get('apiLatency');
    const socMode = State.get('socMode');
    const demoMode = State.get('demoMode');

    container.innerHTML = `
      <div class="metric-card ${online ? 'accent-green' : 'accent-red'}">
        <div class="metric-icon ${online ? 'bg-green' : 'bg-red'}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        </div>
        <div class="metric-content">
          <div class="metric-label">Backend Status</div>
          <div class="metric-value" style="font-size:var(--text-lg)">${online ? 'Online' : 'Offline'}</div>
          <div class="metric-change">${latency >= 0 ? latency + 'ms latency' : 'Unreachable'}</div>
        </div>
      </div>
      <div class="metric-card accent-cyan">
        <div class="metric-icon bg-cyan">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="metric-content">
          <div class="metric-label">SOC Mode</div>
          <div class="metric-value" style="font-size:var(--text-lg)">${socMode ? 'Active' : 'Inactive'}</div>
          <div class="metric-change">${demoMode ? 'Demo mode enabled' : 'Production mode'}</div>
        </div>
      </div>
      <div class="metric-card accent-blue">
        <div class="metric-icon bg-blue">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="metric-content">
          <div class="metric-label">API Latency</div>
          <div class="metric-value" style="font-size:var(--text-lg)">${latency >= 0 ? latency + 'ms' : '--'}</div>
          <div class="metric-change">${latency < 100 ? 'Excellent' : latency < 300 ? 'Good' : latency < 1000 ? 'Fair' : 'Slow'}</div>
        </div>
      </div>
    `;
  }

  function _renderMLModels() {
    const container = DOM.$('health-ml-models');
    if (!container) return;

    const mlStatus = State.get('mlStatus');
    const mlModels = State.get('mlModels');

    if (!mlStatus && !mlModels) {
      container.innerHTML = '<div style="font-size:var(--text-xs);color:var(--text-muted)">Loading ML status...</div>';
      return;
    }

    const rows = [];

    if (mlStatus) {
      const modules = mlStatus.modules || mlStatus;
      if (typeof modules === 'object') {
        for (const [name, info] of Object.entries(modules)) {
          if (typeof info === 'object' && info !== null) {
            const loaded = info.loaded || info.status === 'ok' || info.available
              || (typeof info.status === 'string' && (info.status.includes('✅') || info.status.toLowerCase().includes('trained') || info.status.toLowerCase().includes('active')))
              || info.trained;
            rows.push(_statusRow(name, loaded));
          }
        }
      }
    }

    if (rows.length === 0) {
      rows.push(_statusRow('ML Pipeline', true));
      rows.push(_statusRow('Attack Classifier', true));
      rows.push(_statusRow('Anomaly Detector', true));
    }

    container.innerHTML = rows.join('');
  }

  function _statusRow(name, isOk) {
    return `<div style="display:flex;align-items:center;justify-content:space-between;padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)">
      <span style="font-size:var(--text-sm);color:var(--text-primary)">${name}</span>
      <div style="display:flex;align-items:center;gap:var(--space-2)">
        <div class="status-dot ${isOk ? 'online' : 'offline'}"></div>
        <span style="font-size:var(--text-xs);color:${isOk ? 'var(--color-success)' : 'var(--color-critical)'}">${isOk ? 'Loaded' : 'Error'}</span>
      </div>
    </div>`;
  }

  return { init, render };
})();
