/**
 * MoodleSec SOC Dashboard — Attack Timeline Chart
 * Line chart showing alerts over time, refreshed via polling.
 */
const TimelineChart = (() => {
  let _chart = null;
  let _miniChart = null;

  function init() {
    State.on('timeline', render);
  }

  function render(data) {
    if (!data || !data.buckets) return;
    _renderMainChart(data.buckets);
    _renderMiniChart(data.buckets);
  }

  function _renderMainChart(buckets) {
    const canvas = DOM.$('chart-attack-timeline');
    if (!canvas) return;

    const labels = buckets.map(b => b.time_label);
    const totals = buckets.map(b => b.count);
    const highs = buckets.map(b => (b.by_severity || {}).HIGH || 0);
    const mediums = buckets.map(b => (b.by_severity || {}).MEDIUM || 0);
    const lows = buckets.map(b => (b.by_severity || {}).LOW || 0);

    const config = {
      data: {
        labels,
        datasets: [
          {
            label: 'Total Alerts',
            data: totals,
            borderColor: 'rgba(34, 211, 238, 1)',
            backgroundColor: 'rgba(34, 211, 238, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 2,
            pointHoverRadius: 5,
            borderWidth: 2,
          },
          {
            label: 'High Severity',
            data: highs,
            borderColor: 'rgba(239, 68, 68, 0.8)',
            backgroundColor: 'rgba(239, 68, 68, 0.05)',
            fill: false,
            tension: 0.4,
            pointRadius: 1,
            borderWidth: 1.5,
            borderDash: [4, 4],
          },
          {
            label: 'Medium',
            data: mediums,
            borderColor: 'rgba(245, 158, 11, 0.7)',
            fill: false,
            tension: 0.4,
            pointRadius: 1,
            borderWidth: 1.5,
            borderDash: [4, 4],
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { position: 'top', labels: { usePointStyle: true, pointStyleWidth: 8 } },
          tooltip: {
            callbacks: {
              title: (items) => items[0] ? `Time: ${items[0].label}` : '',
            },
          },
        },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: 'rgba(148, 163, 184, 0.06)' } },
        },
      },
    };

    if (_chart) {
      _chart.data = config.data;
      _chart.update('none');
    } else {
      _chart = new Chart(canvas, { type: 'line', ...config });
    }
  }

  function _renderMiniChart(buckets) {
    const canvas = DOM.$('chart-mini-timeline');
    if (!canvas) return;

    const labels = buckets.map(b => b.time_label);
    const totals = buckets.map(b => b.count);

    const config = {
      data: {
        labels,
        datasets: [{
          data: totals,
          borderColor: 'rgba(34, 211, 238, 1)',
          backgroundColor: 'rgba(34, 211, 238, 0.15)',
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
      },
    };

    if (_miniChart) {
      _miniChart.data = config.data;
      _miniChart.update('none');
    } else {
      _miniChart = new Chart(canvas, { type: 'line', ...config });
    }
  }

  return { init, render };
})();
