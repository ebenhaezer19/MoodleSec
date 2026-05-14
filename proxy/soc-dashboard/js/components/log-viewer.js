/**
 * MoodleSec SOC Dashboard — Log Viewer
 * Terminal-style trace log console with capped buffer, color coding, pause/resume.
 */
const LogViewer = (() => {
  const MAX_ENTRIES = 200;
  let _paused = false;
  let _entries = [];
  let _seenIds = new Set();

  function init() {
    DOM.$('logs-pause-btn').addEventListener('click', _togglePause);
    DOM.$('logs-clear-btn').addEventListener('click', _clear);

    // Pause on hover
    const container = DOM.$('log-viewer-container');
    container.addEventListener('mouseenter', () => { if (!_paused) container.dataset.hoverPause = '1'; });
    container.addEventListener('mouseleave', () => { delete container.dataset.hoverPause; _autoScroll(); });

    State.on('logs', _onLogs);
  }

  function _onLogs(logs) {
    if (_paused) return;
    if (!Array.isArray(logs)) return;

    // Incremental append — only add entries we haven't seen
    let newCount = 0;
    for (const log of logs) {
      const id = log.timestamp + log.type;
      if (_seenIds.has(id)) continue;
      _seenIds.add(id);
      _entries.push(log);
      newCount++;
    }

    // Cap buffer
    while (_entries.length > MAX_ENTRIES) {
      const removed = _entries.shift();
      _seenIds.delete(removed.timestamp + removed.type);
    }

    if (newCount > 0) _render();
  }

  function _render() {
    const container = DOM.$('log-viewer-container');
    if (!container) return;

    if (_entries.length === 0) {
      container.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div>
        <div class="empty-state-title">Trace console ready</div>
        <div class="empty-state-description">Waiting for pipeline trace events...</div>
      </div>`;
      return;
    }

    const lines = _entries.map(log => {
      const time = Formatters.time(log.timestamp);
      const type = (log.type || 'unknown').toUpperCase();
      const color = _typeColor(type);
      const detail = _formatDetail(log);
      return `<div style="display:flex;gap:var(--space-3);padding:1px 0;line-height:1.5">
        <span style="color:var(--text-muted);flex-shrink:0">${time}</span>
        <span style="color:${color};font-weight:500;flex-shrink:0;min-width:160px">[${type}]</span>
        <span style="color:var(--text-secondary)">${detail}</span>
      </div>`;
    });

    container.innerHTML = lines.join('');
    _autoScroll();
  }

  function _typeColor(type) {
    if (type.includes('BLOCK')) return 'var(--color-critical)';
    if (type.includes('ALERT') || type.includes('PENDING')) return 'var(--color-medium)';
    if (type.includes('ANOMALY')) return 'var(--color-high)';
    if (type.includes('ERROR')) return 'var(--color-critical)';
    if (type.includes('BYPASS')) return 'var(--accent-purple)';
    if (type.includes('RESPONSE') || type.includes('TRANSACTION')) return 'var(--accent-cyan)';
    return 'var(--text-muted)';
  }

  function _formatDetail(log) {
    const parts = [];
    if (log.method) parts.push(log.method);
    if (log.path) parts.push(log.path);
    if (log.client_ip) parts.push(`[${log.client_ip}]`);
    if (log.ml_decision) parts.push(`→ ${log.ml_decision}`);
    if (log.ml_attack_type && log.ml_attack_type !== 'normal') parts.push(`(${log.ml_attack_type})`);
    if (log.status_code) parts.push(`HTTP ${log.status_code}`);
    if (log.anomaly_detected) parts.push(`⚠ anomaly:${Formatters.decimal(log.anomaly_score)}`);
    if (log.reason) parts.push(`— ${Formatters.truncate(log.reason, 50)}`);

    if (parts.length === 0) {
      // Fallback: show raw type info
      const skip = new Set(['type', 'timestamp']);
      for (const [k, v] of Object.entries(log)) {
        if (skip.has(k) || typeof v === 'object') continue;
        parts.push(`${k}=${v}`);
        if (parts.length >= 4) break;
      }
    }
    return parts.join(' ');
  }

  function _autoScroll() {
    const container = DOM.$('log-viewer-container');
    if (container && !container.dataset.hoverPause) {
      container.scrollTop = container.scrollHeight;
    }
  }

  function _togglePause() {
    _paused = !_paused;
    const btn = DOM.$('logs-pause-btn');
    if (_paused) {
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Resume';
    } else {
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause';
      // Re-render with current data
      const logs = State.get('logs');
      if (logs) _onLogs(logs);
    }
  }

  function _clear() {
    _entries = [];
    _seenIds.clear();
    _render();
  }

  return { init };
})();
