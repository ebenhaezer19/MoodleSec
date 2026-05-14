/**
 * MoodleSec SOC Dashboard — Statistics Charts
 * Chart.js powered analytics: attack distribution, severity, decision ratio.
 */
const StatsCharts = (() => {
  let _charts = {};

  const CHART_COLORS = {
    cyan: 'rgba(34, 211, 238, 0.8)',
    blue: 'rgba(59, 130, 246, 0.8)',
    purple: 'rgba(139, 92, 246, 0.8)',
    red: 'rgba(239, 68, 68, 0.8)',
    orange: 'rgba(249, 115, 22, 0.8)',
    amber: 'rgba(245, 158, 11, 0.8)',
    green: 'rgba(34, 197, 94, 0.8)',
    gray: 'rgba(100, 116, 139, 0.8)',
  };

  function init() {
    // Set Chart.js defaults for dark theme
    if (window.Chart) {
      Chart.defaults.color = '#94a3b8';
      Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.08)';
      Chart.defaults.font.family = "'Inter', sans-serif";
      Chart.defaults.font.size = 12;
      Chart.defaults.plugins.legend.labels.usePointStyle = true;
      Chart.defaults.plugins.legend.labels.pointStyleWidth = 8;
    }

    State.on('alerts', render);
    State.on('alertStats', renderOverviewCharts);
  }

  function render() {
    const alerts = State.get('alerts') || [];
    _renderAttackDist(alerts);
    _renderSeverityDist(alerts);
    _renderDecisionRatio();
    _renderTopIPs(alerts);
    _renderSummaryCards();
  }

  function renderOverviewCharts() {
    const alerts = State.get('alerts') || [];
    _renderOverviewDecisionChart();
    _renderOverviewAttackChart(alerts);
  }

  function _getOrCreate(canvasId, type, config) {
    if (_charts[canvasId]) {
      const chart = _charts[canvasId];
      Object.assign(chart.data, config.data);
      chart.update('none');
      return chart;
    }
    const canvas = DOM.$(canvasId);
    if (!canvas) return null;
    _charts[canvasId] = new Chart(canvas, { type, ...config });
    return _charts[canvasId];
  }

  function _renderAttackDist(alerts) {
    const counts = {};
    alerts.forEach(a => {
      const type = Formatters.attackLabel(a.attack_type);
      counts[type] = (counts[type] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const colors = [CHART_COLORS.cyan, CHART_COLORS.red, CHART_COLORS.orange, CHART_COLORS.purple, CHART_COLORS.blue, CHART_COLORS.amber, CHART_COLORS.green, CHART_COLORS.gray];

    _getOrCreate('chart-attack-dist', 'bar', {
      data: { labels: sorted.map(s => s[0]), datasets: [{ label: 'Count', data: sorted.map(s => s[1]), backgroundColor: colors.slice(0, sorted.length), borderRadius: 4, maxBarThickness: 40 }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } }, y: { grid: { display: false } } } },
    });
  }

  function _renderSeverityDist(alerts) {
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach(a => { const s = (a.severity||'LOW').toUpperCase(); if (counts[s] !== undefined) counts[s]++; });

    _getOrCreate('chart-severity-dist', 'doughnut', {
      data: { labels: ['High', 'Medium', 'Low'], datasets: [{ data: [counts.HIGH, counts.MEDIUM, counts.LOW], backgroundColor: [CHART_COLORS.red, CHART_COLORS.amber, CHART_COLORS.gray], borderWidth: 0, spacing: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom' } } },
    });
  }

  function _renderDecisionRatio() {
    const stats = State.get('alertStats') || {};

    _getOrCreate('chart-decision-ratio', 'doughnut', {
      data: { labels: ['Blocked', 'Allowed', 'Ignored', 'Pending'], datasets: [{ data: [stats.blocked||0, stats.allowed||0, stats.ignored||0, stats.pending||0], backgroundColor: [CHART_COLORS.red, CHART_COLORS.green, CHART_COLORS.gray, CHART_COLORS.amber], borderWidth: 0, spacing: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom' } } },
    });
  }

  function _renderTopIPs(alerts) {
    const container = DOM.$('stats-top-ips');
    if (!container) return;

    const ipCounts = {};
    alerts.forEach(a => { if (a.client_ip) ipCounts[a.client_ip] = (ipCounts[a.client_ip] || 0) + 1; });
    const sorted = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

    if (sorted.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding:var(--space-4)"><div class="empty-state-title" style="font-size:var(--text-sm)">No data</div></div>';
      return;
    }

    const maxCount = sorted[0][1];
    container.innerHTML = sorted.map(([ip, count]) => `
      <div style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)">
        <code style="font-size:var(--text-xs);min-width:100px">${ip}</code>
        <div style="flex:1;height:6px;background:var(--bg-root);border-radius:var(--radius-full);overflow:hidden">
          <div style="height:100%;width:${(count/maxCount)*100}%;background:var(--accent-cyan);border-radius:var(--radius-full)"></div>
        </div>
        <span style="font-size:var(--text-xs);color:var(--text-secondary);min-width:30px;text-align:right">${count}</span>
      </div>
    `).join('');
  }

  function _renderOverviewDecisionChart() {
    const stats = State.get('alertStats') || {};
    _getOrCreate('chart-decision-dist', 'doughnut', {
      data: { labels: ['Blocked', 'Allowed', 'Ignored', 'Pending'], datasets: [{ data: [stats.blocked||0, stats.allowed||0, stats.ignored||0, stats.pending||0], backgroundColor: [CHART_COLORS.red, CHART_COLORS.green, CHART_COLORS.gray, CHART_COLORS.amber], borderWidth: 0, spacing: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom' } } },
    });
  }

  function _renderOverviewAttackChart(alerts) {
    const counts = {};
    alerts.forEach(a => { const t = a.attack_type || 'unknown'; counts[t] = (counts[t] || 0) + 1; });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const colors = [CHART_COLORS.cyan, CHART_COLORS.red, CHART_COLORS.orange, CHART_COLORS.purple, CHART_COLORS.blue];

    _getOrCreate('chart-attack-types', 'bar', {
      data: { labels: sorted.map(s => s[0]), datasets: [{ label: 'Attacks', data: sorted.map(s => s[1]), backgroundColor: colors, borderRadius: 4, maxBarThickness: 32 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false } }, y: { grid: { display: false }, beginAtZero: true } } },
    });
  }

  function _renderSummaryCards() {
    const container = DOM.$('stats-summary-cards');
    if (!container) return;
    const stats = State.get('alertStats') || {};
    const alerts = State.get('alerts') || [];
    const avgConf = alerts.length > 0 ? alerts.reduce((s, a) => s + (a.confidence||0), 0) / alerts.length : 0;

    container.innerHTML = `
      <div class="metric-card accent-cyan">
        <div class="metric-icon bg-cyan"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg></div>
        <div class="metric-content"><div class="metric-label">Total Alerts</div><div class="metric-value">${Formatters.number(stats.total_alerts||0)}</div></div>
      </div>
      <div class="metric-card accent-red">
        <div class="metric-icon bg-red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div>
        <div class="metric-content"><div class="metric-label">Block Rate</div><div class="metric-value">${stats.total_alerts ? Math.round(((stats.blocked||0)/(stats.total_alerts))*100) : 0}%</div></div>
      </div>
      <div class="metric-card accent-blue">
        <div class="metric-icon bg-blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
        <div class="metric-content"><div class="metric-label">Avg. Confidence</div><div class="metric-value">${Formatters.decimal(avgConf)}</div></div>
      </div>
    `;
  }

  return { init, render, renderOverviewCharts };
})();
