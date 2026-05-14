/**
 * MoodleSec SOC Dashboard — Alert Feed
 * Realtime alert table with filtering, search, severity coding, row click.
 */
const AlertFeed = (() => {
  let _prevAlertIds = new Set();
  let _searchTerm = '';
  let _filterStatus = '';
  let _filterSeverity = '';

  function init() {
    // Filter listeners
    const searchInput = DOM.$('alert-search');
    const statusSelect = DOM.$('alert-filter-status');
    const severitySelect = DOM.$('alert-filter-severity');

    if (searchInput) searchInput.addEventListener('input', (e) => { _searchTerm = e.target.value.toLowerCase(); _render(); });
    if (statusSelect) statusSelect.addEventListener('change', (e) => { _filterStatus = e.target.value; _render(); });
    if (severitySelect) severitySelect.addEventListener('change', (e) => { _filterSeverity = e.target.value; _render(); });

    // "View All" button on overview
    document.querySelectorAll('[data-page="alerts"]').forEach(btn => {
      btn.addEventListener('click', () => App.navigateTo('alerts'));
    });

    State.on('alerts', _render);
  }

  function _render() {
    const alerts = State.get('alerts') || [];
    _renderTable('alerts-table-body', alerts, true);
    _renderOverviewTable(alerts);
    _updateBadge(alerts);
    _updateTimestamp();
  }

  function _filterAlerts(alerts) {
    let filtered = alerts;
    if (_filterStatus) filtered = filtered.filter(a => a.status === _filterStatus);
    if (_filterSeverity) filtered = filtered.filter(a => (a.severity || '').toUpperCase() === _filterSeverity);
    if (_searchTerm) {
      filtered = filtered.filter(a => {
        const haystack = `${a.client_ip} ${a.path} ${a.attack_type} ${a.alert_id} ${a.reason}`.toLowerCase();
        return haystack.includes(_searchTerm);
      });
    }
    return filtered;
  }

  function _renderTable(containerId, alerts, applyFilters) {
    const tbody = DOM.$(containerId);
    if (!tbody) return;

    const filtered = applyFilters ? _filterAlerts(alerts) : alerts.slice(0, 8);
    const newIds = new Set(filtered.map(a => a.alert_id));

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr><td colspan="8">
          <div class="empty-state">
            <div class="empty-state-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
            <div class="empty-state-title">No active threats detected</div>
            <div class="empty-state-description">The SOC queue is clear. Monitoring continues in real-time.</div>
          </div>
        </td></tr>`;
      _prevAlertIds = newIds;
      return;
    }

    const rows = filtered.map(alert => {
      const isNew = !_prevAlertIds.has(alert.alert_id);
      const sevClass = `severity-${(alert.severity || 'low').toLowerCase()}`;
      const newClass = isNew ? 'alert-row-new' : '';
      const isPending = (alert.status || '').includes('PENDING');

      return `<tr class="${sevClass} ${newClass}" data-alert-id="${alert.alert_id}" onclick="AdminPanel.openAlert('${alert.alert_id}')">
        <td><span class="font-mono" style="font-size:var(--text-xs)">${Formatters.time(alert.timestamp)}</span></td>
        <td><strong>${Formatters.attackLabel(alert.attack_type)}</strong></td>
        <td><span class="badge ${Formatters.severityBadgeClass(alert.severity)}">${(alert.severity || 'LOW').toUpperCase()}</span></td>
        <td>
          <div style="display:flex;align-items:center;gap:var(--space-2)">
            <div class="confidence-bar"><div class="confidence-bar-fill" style="width:${Math.round((alert.confidence || 0) * 100)}%;background:${Formatters.confidenceColor(alert.confidence)}"></div></div>
            <span style="font-size:var(--text-xs);color:var(--text-secondary)">${Formatters.decimal(alert.confidence)}</span>
          </div>
        </td>
        <td><code style="font-size:var(--text-xs)">${alert.client_ip || '--'}</code></td>
        <td><span style="font-size:var(--text-xs)">${Formatters.truncate(alert.path, 25)}</span></td>
        <td><span class="badge ${Formatters.statusBadgeClass(alert.status)}">${Formatters.statusLabel(alert.status)}</span></td>
        <td>${isPending ? `
          <div style="display:flex;gap:var(--space-1)">
            <button class="btn btn-danger btn-sm" onclick="event.stopPropagation();AdminPanel.quickAction('${alert.alert_id}','BLOCK')">Block</button>
            <button class="btn btn-success btn-sm" onclick="event.stopPropagation();AdminPanel.quickAction('${alert.alert_id}','ALLOW')">Allow</button>
          </div>` : `<span style="font-size:var(--text-xs);color:var(--text-muted)">${Formatters.timeAgo(alert.admin_action_timestamp)}</span>`}
        </td>
      </tr>`;
    });

    tbody.innerHTML = rows.join('');
    _prevAlertIds = newIds;
  }

  function _renderOverviewTable(alerts) {
    const body = DOM.$('overview-alerts-body');
    if (!body) return;

    const recent = alerts.slice(0, 6);
    if (recent.length === 0) {
      body.innerHTML = `<div class="empty-state" style="padding:var(--space-6)">
        <div class="empty-state-title" style="font-size:var(--text-sm)">No alerts yet</div>
        <div class="empty-state-description">Monitoring active</div>
      </div>`;
      return;
    }

    body.innerHTML = '<table class="data-table"><tbody>' + recent.map(a => `
      <tr onclick="App.navigateTo('alerts');AdminPanel.openAlert('${a.alert_id}')" style="cursor:pointer">
        <td style="width:60px"><span class="font-mono" style="font-size:var(--text-xs)">${Formatters.time(a.timestamp)}</span></td>
        <td><span style="font-size:var(--text-xs)">${Formatters.attackLabel(a.attack_type)}</span></td>
        <td><span class="badge ${Formatters.severityBadgeClass(a.severity)}">${(a.severity || 'LOW').toUpperCase()}</span></td>
        <td><span class="badge ${Formatters.statusBadgeClass(a.status)}">${Formatters.statusLabel(a.status)}</span></td>
      </tr>
    `).join('') + '</tbody></table>';
  }

  function _updateBadge(alerts) {
    const pending = alerts.filter(a => (a.status || '').includes('PENDING')).length;
    const badge = DOM.$('nav-alerts-badge');
    if (badge) {
      badge.textContent = pending;
      badge.style.display = pending > 0 ? '' : 'none';
    }
  }

  function _updateTimestamp() {
    const el = DOM.$('alerts-last-update');
    if (el) el.textContent = `Last update: ${new Date().toLocaleTimeString('en-GB', { hour12: false })}`;
  }

  return { init };
})();

/** Global handler for the "Reset Queue" button */
async function resetAlertQueue() {
  const btn = document.getElementById('btn-reset-queue');
  if (!btn || btn.disabled) return;
  btn.disabled = true;
  btn.textContent = 'Resetting...';
  try {
    const result = await API.resetAllAlerts();
    if (result && result.success) {
      State.set('alerts', []);
      btn.textContent = 'Cleared!';
      setTimeout(() => { btn.textContent = 'Reset Queue'; btn.disabled = false; }, 2000);
    } else {
      btn.textContent = 'Failed';
      setTimeout(() => { btn.textContent = 'Reset Queue'; btn.disabled = false; }, 2000);
    }
  } catch (err) {
    console.error('[ResetQueue]', err);
    btn.textContent = 'Error';
    setTimeout(() => { btn.textContent = 'Reset Queue'; btn.disabled = false; }, 2000);
  }
}
