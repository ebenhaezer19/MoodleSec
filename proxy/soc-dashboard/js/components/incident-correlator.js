/**
 * MoodleSec SOC Dashboard — Incident Correlator UI
 * Displays correlated incidents on the Overview page and full Incidents page.
 * Clickable cards open a lightweight detail panel.
 */
const IncidentCorrelator = (() => {

  const _viewedIncidents = new Set();

  function init() {
    State.on('incidents', render);
  }

  function render(incidents) {
    _renderOverview(incidents);
    _renderFullPage(incidents);
    _updateBadge(incidents);
  }

  function _renderOverview(incidents) {
    const container = DOM.$('overview-incidents-body');
    if (!container) return;

    if (!incidents || incidents.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding:var(--space-4)">
          <div class="empty-state-title" style="font-size:var(--text-sm)">No incidents correlated</div>
          <div class="empty-state-description">Incidents appear when multiple alerts share the same source IP and attack type</div>
        </div>`;
      return;
    }

    container.innerHTML = incidents.slice(0, 5).map(inc => _incidentRow(inc)).join('');
    _wireClickHandlers(container, incidents);
  }

  function _renderFullPage(incidents) {
    const container = DOM.$('incidents-full-body');
    if (!container) return;

    if (!incidents || incidents.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding:var(--space-6)">
          <div class="empty-state-title">No correlated incidents</div>
          <div class="empty-state-description">Send attack requests from the same IP to trigger incident correlation</div>
        </div>`;
      return;
    }

    container.innerHTML = incidents.map(inc => _incidentRow(inc)).join('');
    _wireClickHandlers(container, incidents);
  }

  function _incidentRow(inc) {
    const sevClass = Formatters.severityBadgeClass(inc.severity);
    const alertCount = inc.alert_count || 0;
    const attackLabel = Formatters.attackLabel(inc.attack_type);
    const timeAgo = Formatters.timeAgo(inc.last_seen);

    const isViewed = _viewedIncidents.has(inc.incident_id);
    const viewedStyle = isViewed
      ? 'opacity:0.7;border-left:3px solid var(--border-subtle)'
      : 'border-left:3px solid var(--accent-cyan)';
    const unreadDot = isViewed ? '' : '<span style="width:6px;height:6px;border-radius:50%;background:var(--accent-cyan);flex-shrink:0" title="Unread"></span>';

    return `
      <div class="incident-row" data-incident-id="${_escapeHtml(inc.incident_id)}" style="cursor:pointer;transition:all 0.15s;${viewedStyle}" onmouseover="this.style.background='var(--bg-elevated)'" onmouseout="this.style.background=''">
        <div class="incident-header">
          ${unreadDot}
          <code class="incident-id">${_escapeHtml(inc.incident_id)}</code>
          <span class="badge ${sevClass}" style="font-size:10px;padding:2px 8px">${(inc.severity || 'LOW').toUpperCase()}</span>
        </div>
        <div class="incident-body">
          <div class="incident-summary">
            <strong>${alertCount}</strong> ${attackLabel} alert${alertCount !== 1 ? 's' : ''} from <code>${_escapeHtml(inc.client_ip)}</code>
          </div>
          <div class="incident-meta">
            ${timeAgo} · Confidence: ${Formatters.decimal(inc.max_confidence)}
          </div>
        </div>
      </div>`;
  }

  function _wireClickHandlers(container, incidents) {
    container.querySelectorAll('.incident-row[data-incident-id]').forEach(row => {
      row.addEventListener('click', () => {
        const incId = row.dataset.incidentId;
        const inc = incidents.find(i => i.incident_id === incId);
        if (inc) {
          _viewedIncidents.add(incId);
          _showIncidentDetail(inc);
          // Re-render to update viewed styling + badge
          render(State.get('incidents') || []);
        }
      });
    });
  }

  // ── Incident Detail Panel ──

  function _showIncidentDetail(inc) {
    // Remove any existing detail panel
    const existing = document.getElementById('incident-detail-panel');
    if (existing) existing.remove();

    const sevClass = Formatters.severityBadgeClass(inc.severity);
    const attackLabel = Formatters.attackLabel(inc.attack_type);
    const alertCount = inc.alert_count || 0;
    const avgConf = inc.max_confidence || 0;
    const paths = (inc.paths || []).slice(0, 10);
    const alertIds = (inc.alert_ids || []).slice(0, 20);

    // Determine severity reason
    let sevReason = '';
    const highestChild = (inc.highest_alert_severity || 'LOW').toUpperCase();
    if (alertCount >= 5) {
      sevReason = `CRITICAL — ${alertCount} correlated alerts exceed threshold (5+)`;
    } else if (alertCount >= 3) {
      sevReason = `HIGH — ${alertCount} correlated alerts exceed threshold (3+)`;
    } else if (highestChild === 'HIGH' || highestChild === 'CRITICAL') {
      sevReason = `${inc.severity} — Inherited from ${highestChild} severity child alert`;
    } else {
      sevReason = `${inc.severity} — Attack type: ${attackLabel}`;
    }

    const panel = document.createElement('div');
    panel.id = 'incident-detail-panel';
    panel.style.cssText = `
      position:fixed;top:0;right:0;width:420px;height:100vh;z-index:1000;
      background:var(--bg-surface);border-left:1px solid var(--border-default);
      box-shadow:-4px 0 24px rgba(0,0,0,0.3);overflow-y:auto;
      animation:slideInRight 0.2s ease;
    `;

    panel.innerHTML = `
      <div style="padding:var(--space-4);border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:space-between">
        <div style="display:flex;align-items:center;gap:var(--space-3)">
          <span style="font-size:16px">📋</span>
          <div>
            <div style="font-weight:600;color:var(--text-primary)">Incident Detail</div>
            <code style="font-size:var(--text-xs);color:var(--accent-cyan)">${_escapeHtml(inc.incident_id)}</code>
          </div>
        </div>
        <button id="incident-detail-close" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px;padding:4px">✕</button>
      </div>

      <div style="padding:var(--space-4)">
        <!-- Severity + Attack Type -->
        <div style="display:flex;align-items:center;gap:var(--space-3);margin-bottom:var(--space-4)">
          <span class="badge ${sevClass}" style="font-size:12px;padding:4px 10px">${(inc.severity || 'LOW').toUpperCase()}</span>
          <span style="font-weight:600;color:var(--text-primary)">${attackLabel}</span>
        </div>

        <!-- Key Metrics -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3);margin-bottom:var(--space-4)">
          <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
            <div style="font-size:var(--text-xs);color:var(--text-muted)">Alerts</div>
            <div style="font-size:var(--text-lg);font-weight:700;color:var(--text-primary)">${alertCount}</div>
          </div>
          <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
            <div style="font-size:var(--text-xs);color:var(--text-muted)">Max Confidence</div>
            <div style="font-size:var(--text-lg);font-weight:700;color:${Formatters.confidenceColor(avgConf)}">${Formatters.decimal(avgConf)}</div>
          </div>
          <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
            <div style="font-size:var(--text-xs);color:var(--text-muted)">Source IP</div>
            <div style="font-size:var(--text-sm);font-weight:600;color:var(--text-primary);font-family:var(--font-mono)">${_escapeHtml(inc.client_ip)}</div>
          </div>
          <div style="padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
            <div style="font-size:var(--text-xs);color:var(--text-muted)">Anomaly Score</div>
            <div style="font-size:var(--text-lg);font-weight:700;color:var(--text-primary)">${Formatters.decimal(inc.max_anomaly_score || 0)}</div>
          </div>
        </div>

        <!-- Timing -->
        <div style="margin-bottom:var(--space-4);padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md)">
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-2);font-weight:600">Timing</div>
          <div style="font-size:var(--text-xs);color:var(--text-secondary)">
            First seen: <span style="color:var(--text-primary)">${Formatters.dateTime(inc.first_seen)}</span><br>
            Last seen: <span style="color:var(--text-primary)">${Formatters.dateTime(inc.last_seen)}</span><br>
            Duration: <span style="color:var(--text-primary)">${Formatters.timeAgo(inc.first_seen)}</span>
          </div>
        </div>

        <!-- Severity Reason -->
        <div style="margin-bottom:var(--space-4);padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md);border-left:3px solid ${_sevColor(inc.severity)}">
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-1);font-weight:600">Escalation Reason</div>
          <div style="font-size:var(--text-xs);color:var(--text-primary)">${sevReason}</div>
        </div>

        <!-- Targeted Paths -->
        ${paths.length > 0 ? `
        <div style="margin-bottom:var(--space-4)">
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-2);font-weight:600">Targeted Paths</div>
          ${paths.map(p => `<div style="font-size:var(--text-xs);font-family:var(--font-mono);color:var(--text-secondary);padding:2px 0;word-break:break-all">${_escapeHtml(p)}</div>`).join('')}
        </div>` : ''}

        <!-- Linked Alert IDs -->
        <div>
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-2);font-weight:600">Linked Alerts (${alertIds.length})</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${alertIds.map(id => `<code style="font-size:10px;padding:2px 6px;background:var(--bg-root);border-radius:var(--radius-sm);color:var(--accent-cyan)">${_escapeHtml(id)}</code>`).join('')}
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(panel);

    // Close handlers
    document.getElementById('incident-detail-close').addEventListener('click', () => panel.remove());
    panel.addEventListener('click', (e) => { if (e.target === panel) panel.remove(); });

    // Escape key
    const escHandler = (e) => { if (e.key === 'Escape') { panel.remove(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
  }

  function _sevColor(severity) {
    const s = String(severity).toUpperCase();
    if (s === 'CRITICAL') return 'var(--color-critical)';
    if (s === 'HIGH') return 'var(--color-critical)';
    if (s === 'MEDIUM') return 'var(--color-medium)';
    return 'var(--text-muted)';
  }

  function _updateBadge(incidents) {
    const badge = DOM.$('nav-incidents-badge');
    if (badge && incidents) {
      // Only count unviewed active incidents
      const count = incidents.filter(i => i.status === 'ACTIVE' && !_viewedIncidents.has(i.incident_id)).length;
      badge.textContent = count;
      badge.style.display = count > 0 ? '' : 'none';
    }
  }

  function _escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  return { init, render };
})();
