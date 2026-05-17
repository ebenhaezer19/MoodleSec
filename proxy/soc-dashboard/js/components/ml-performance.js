/**
 * MoodleSec SOC Dashboard — ML Performance Page
 * Displays model metrics, pipeline stages, and evaluation results.
 */
const MLPerformance = (() => {

  function init() {
    State.on('mlPerformance', render);
  }

  function render(data) {
    if (!data || !data.success) return;
    _renderMetricCards(data);
    _renderModelTable(data);
    _renderPipelineSummary(data);
  }

  function _renderMetricCards(data) {
    const container = DOM.$('ml-perf-cards');
    if (!container) return;

    const combined = data.combined_pipeline || {};
    const cards = [
      { label: 'End-to-End Accuracy', value: _pct(combined.end_to_end_accuracy), icon: 'target', color: 'cyan' },
      { label: 'End-to-End F1 Score', value: _pct(combined.end_to_end_f1), icon: 'zap', color: 'blue' },
      { label: 'FP Rate (Before)', value: _pct(combined.false_positive_rate_before_fp_reducer), icon: 'alert-triangle', color: 'orange' },
      { label: 'FP Rate (After)', value: _pct(combined.false_positive_rate_after_fp_reducer), icon: 'shield', color: 'green' },
      { label: 'FP Reduction', value: (combined.fp_reduction_percentage || 0).toFixed(0) + '%', icon: 'trending-down', color: 'purple' },
      { label: 'Dataset Size', value: Formatters.number((data.dataset || {}).total_samples || 0), icon: 'database', color: 'gray' },
    ];

    container.innerHTML = cards.map(c => `
      <div class="metric-card accent-${c.color}">
        <div class="metric-icon bg-${c.color}">
          ${_icon(c.icon)}
        </div>
        <div class="metric-content">
          <div class="metric-label">${c.label}</div>
          <div class="metric-value">${c.value}</div>
        </div>
      </div>
    `).join('');
  }

  function _renderModelTable(data) {
    const container = DOM.$('ml-perf-models');
    if (!container) return;

    const stages = [
      { key: 'stage_1_anomaly_detector', stage: 'Stage 1', color: 'var(--accent-cyan)' },
      { key: 'stage_2_attack_classifier', stage: 'Stage 2', color: 'var(--color-medium)' },
      { key: 'stage_3_fp_reducer', stage: 'Stage 3', color: 'var(--color-success)' },
    ];

    container.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Stage</th>
            <th>Model</th>
            <th>Purpose</th>
            <th>Accuracy</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1</th>
          </tr>
        </thead>
        <tbody>
          ${stages.map(s => {
            const d = data[s.key] || {};
            const m = d.metrics || {};
            return `<tr>
              <td><span style="color:${s.color};font-weight:600">${s.stage}</span></td>
              <td style="font-weight:500">${d.model || '--'}</td>
              <td style="font-size:var(--text-xs);color:var(--text-muted);max-width:200px">${d.purpose || '--'}</td>
              <td>${_pct(m.accuracy)}</td>
              <td>${_pct(m.precision)}</td>
              <td>${_pct(m.recall)}</td>
              <td><strong>${_pct(m.f1_score)}</strong></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    `;
  }

  function _renderPipelineSummary(data) {
    const container = DOM.$('ml-perf-summary');
    if (!container) return;

    const de = data.decision_engine || {};
    const th = de.thresholds || {};
    const ds = data.dataset || {};

    container.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-4)">
        <div>
          <h4 style="color:var(--accent-cyan);margin-bottom:var(--space-3)">Decision Engine</h4>
          <div class="kv-list">
            ${_kv('Type', de.type || 'Rule-based')}
            ${_kv('High Anomaly Threshold', th.high_anomaly)}
            ${_kv('Low Anomaly Threshold', th.low_anomaly)}
            ${_kv('High Confidence Threshold', th.high_confidence)}
            ${_kv('Decisions', (de.decisions || []).join(' / '))}
          </div>
        </div>
        <div>
          <h4 style="color:var(--accent-cyan);margin-bottom:var(--space-3)">Training Data</h4>
          <div class="kv-list">
            ${_kv('Dataset', ds.name || '--')}
            ${_kv('Samples', Formatters.number(ds.total_samples || 0))}
            ${_kv('Train / Val / Test', `${ds.train_split} / ${ds.validation_split} / ${ds.test_split}`)}
            ${_kv('Attack Types', (ds.attack_types || []).join(', '))}
            ${_kv('Evaluation Date', data.evaluation_date || '--')}
          </div>
        </div>
      </div>
    `;
  }

  function _pct(val) {
    if (val === null || val === undefined) return '--';
    return (Number(val) * 100).toFixed(1) + '%';
  }

  function _kv(label, value) {
    return `<div class="kv-row"><span class="kv-label">${label}</span><span class="kv-value">${value || '--'}</span></div>`;
  }

  function _icon(name) {
    const icons = {
      'target': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
      'zap': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
      'alert-triangle': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
      'shield': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
      'trending-down': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/></svg>',
      'database': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    };
    return icons[name] || '';
  }

  return { init, render };
})();
