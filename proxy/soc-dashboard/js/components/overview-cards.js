/**
 * MoodleSec SOC Dashboard — Overview Cards
 * 8 metric cards with animated counters.
 */
const OverviewCards = (() => {
  const CARD_DEFS = [
    { id: 'mc-total',   label: 'Total Alerts',     key: 'total_alerts',         accent: 'accent-cyan',   iconBg: 'bg-cyan',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' },
    { id: 'mc-pending', label: 'Pending Review',    key: 'pending',              accent: 'accent-amber',  iconBg: 'bg-amber',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>' },
    { id: 'mc-blocked', label: 'Blocked',           key: 'blocked',              accent: 'accent-red',    iconBg: 'bg-red',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>' },
    { id: 'mc-allowed', label: 'Allowed',           key: 'allowed',              accent: 'accent-green',  iconBg: 'bg-green',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' },
    { id: 'mc-ignored', label: 'Ignored',           key: 'ignored',              accent: 'accent-purple', iconBg: 'bg-purple', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>' },
    { id: 'mc-rules',   label: 'Active Rules',      key: 'override_rules_active', accent: 'accent-blue',  iconBg: 'bg-blue',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' },
    { id: 'mc-resolved',label: 'Resolved',          key: 'total_resolved',       accent: 'accent-cyan',   iconBg: 'bg-cyan',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>' },
    { id: 'mc-latency', label: 'API Latency',       key: '_latency',             accent: 'accent-cyan',   iconBg: 'bg-cyan',   icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>' },
  ];

  function init() {
    const container = DOM.$('overview-cards');
    if (!container) return;

    container.innerHTML = CARD_DEFS.map(c => `
      <div class="metric-card ${c.accent}" id="${c.id}">
        <div class="metric-icon ${c.iconBg}">${c.icon}</div>
        <div class="metric-content">
          <div class="metric-label">${c.label}</div>
          <div class="metric-value" id="${c.id}-value">0</div>
        </div>
      </div>
    `).join('');

    State.on('alertStats', render);
    State.on('apiLatency', renderLatency);
  }

  function render(stats) {
    if (!stats) return;
    for (const def of CARD_DEFS) {
      if (def.key === '_latency') continue;
      const el = DOM.$(`${def.id}-value`);
      if (el) DOM.animateCounter(el, stats[def.key] || 0);
    }
  }

  function renderLatency() {
    const el = DOM.$('mc-latency-value');
    if (!el) return;
    const latency = State.get('apiLatency');
    el.textContent = latency >= 0 ? `${latency}ms` : 'Offline';
  }

  return { init };
})();
