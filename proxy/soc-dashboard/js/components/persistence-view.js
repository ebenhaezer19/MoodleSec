/**
 * MoodleSec SOC Dashboard — Persistence View
 * SOC-style display of override rules, queue health, persistence status.
 */
const PersistenceView = (() => {
  function init() {
    State.on('alertStats', render);
    State.on('backendOnline', render);
  }

  function render() {
    const container = DOM.$('health-persistence');
    if (!container) return;

    const stats = State.get('alertStats') || {};
    const online = State.get('backendOnline');

    const items = [
      { label: 'Override Rules Active', value: stats.override_rules_active || 0, icon: '🔒' },
      { label: 'Blocked Fingerprints', value: stats.blocked || 0, icon: '🛑' },
      { label: 'Pending Queue Size', value: stats.pending || 0, icon: '⏳' },
      { label: 'Total Resolved', value: stats.total_resolved || 0, icon: '✅' },
      { label: 'Persistence', value: online ? 'Active' : 'Unknown', icon: '💾' },
    ];

    container.innerHTML = items.map(item => `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)">
        <span style="font-size:var(--text-sm);color:var(--text-secondary)">${item.icon} ${item.label}</span>
        <span style="font-size:var(--text-sm);font-weight:600;color:var(--text-primary)">${item.value}</span>
      </div>
    `).join('');
  }

  return { init, render };
})();
