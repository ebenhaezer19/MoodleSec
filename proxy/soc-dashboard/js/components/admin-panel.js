/**
 * MoodleSec SOC Dashboard — Admin Panel
 * Alert detail drawer with Decision Explanation, SOC Workflow Timeline,
 * and BLOCK/ALLOW/IGNORE actions with confirmation modal.
 */
const AdminPanel = (() => {

  function init() {
    DOM.$('drawer-close').addEventListener('click', DOM.closeDrawer);
    DOM.$('drawer-backdrop').addEventListener('click', DOM.closeDrawer);
  }

  /** Open alert detail drawer */
  async function openAlert(alertId) {
    const alerts = State.get('alerts') || [];
    const alert = alerts.find(a => a.alert_id === alertId);
    if (!alert) { DOM.toast('Alert not found', 'error'); return; }

    State.set('selectedAlertId', alertId);
    _renderDrawer(alert);
    DOM.openDrawer();
  }

  function _renderDrawer(alert) {
    const body = DOM.$('drawer-body');
    const title = DOM.$('drawer-title');
    title.textContent = `Alert ${alert.alert_id}`;

    const isPending = (alert.status || '').includes('PENDING');
    const sevClass = Formatters.severityBadgeClass(alert.severity);
    const statusClass = Formatters.statusBadgeClass(alert.status);

    body.innerHTML = `
      <!-- Status Banner -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-5)">
        <span class="badge ${sevClass}" style="font-size:var(--text-sm);padding:4px 12px">${(alert.severity||'LOW').toUpperCase()}</span>
        <span class="badge ${statusClass}" style="font-size:var(--text-sm);padding:4px 12px">${Formatters.statusLabel(alert.status)}</span>
      </div>

      <!-- Attack Info -->
      <div class="card" style="margin-bottom:var(--space-4)">
        <h4 style="margin-bottom:var(--space-3);color:var(--accent-cyan)">Attack Information</h4>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
          ${_field('Attack Type', Formatters.attackLabel(alert.attack_type))}
          ${_field('Source IP', alert.client_ip)}
          ${_field('Method', alert.method)}
          ${_field('Path', alert.path)}
          ${_field('Timestamp', Formatters.dateTime(alert.timestamp))}
          ${_field('Alert ID', alert.alert_id)}
        </div>
      </div>

      <!-- Decision Explanation (THESIS KEY) -->
      <div class="card" style="margin-bottom:var(--space-4);border-color:rgba(34,211,238,0.2)">
        <h4 style="margin-bottom:var(--space-3);color:var(--accent-cyan)">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          Decision Explanation
        </h4>
        <div style="background:var(--bg-root);padding:var(--space-4);border-radius:var(--radius-md);margin-bottom:var(--space-3)">
          <p style="color:var(--text-primary);font-size:var(--text-sm);line-height:1.6;margin:0">
            ${_buildExplanation(alert)}
          </p>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3)">
          ${_metricField('Anomaly Score', Formatters.decimal(alert.anomaly_score), _anomalyColor(alert.anomaly_score))}
          ${_metricField('Classifier Confidence', Formatters.decimal(alert.confidence), Formatters.confidenceColor(alert.confidence))}
        </div>
        <div style="margin-top:var(--space-3)">
          ${_metricField('ML Original Decision', alert.ml_decision_original || 'N/A', _decisionColor(alert.ml_decision_original))}
        </div>
      </div>

      <!-- SOC Workflow Timeline -->
      <div class="card" style="margin-bottom:var(--space-4)">
        <h4 style="margin-bottom:var(--space-4);color:var(--accent-cyan)">SOC Workflow Timeline</h4>
        <div class="workflow-timeline">
          ${_buildTimeline(alert)}
        </div>
      </div>

      <!-- Admin Actions -->
      ${isPending ? `
      <div class="card" style="border-color:rgba(245,158,11,0.3)">
        <h4 style="margin-bottom:var(--space-2);color:var(--color-pending)">Admin Decision Required</h4>
        <p style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-4)">
          Future matching requests from this IP will follow your decision automatically.
        </p>
        <div style="display:flex;gap:var(--space-3)">
          <button class="btn btn-danger" onclick="AdminPanel.resolveAction('${alert.alert_id}','BLOCK')" style="flex:1">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            Block
          </button>
          <button class="btn btn-success" onclick="AdminPanel.resolveAction('${alert.alert_id}','ALLOW')" style="flex:1">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            Allow
          </button>
          <button class="btn btn-ghost" onclick="AdminPanel.resolveAction('${alert.alert_id}','IGNORE')" style="flex:1">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            Ignore
          </button>
        </div>
      </div>` : `
      <div class="card">
        <h4 style="margin-bottom:var(--space-2);color:var(--text-secondary)">Decision Applied</h4>
        <p style="font-size:var(--text-sm);color:var(--text-muted)">
          Admin action: <strong style="color:var(--text-primary)">${alert.admin_action || alert.status}</strong><br>
          ${alert.admin_action_timestamp ? 'Resolved: ' + Formatters.dateTime(alert.admin_action_timestamp) : ''}
        </p>
      </div>`}

      <!-- Raw Data -->
      <details style="margin-top:var(--space-4)">
        <summary style="font-size:var(--text-xs);color:var(--text-muted);cursor:pointer;user-select:none">Raw Alert Data</summary>
        <pre style="margin-top:var(--space-2);padding:var(--space-3);background:var(--bg-root);border-radius:var(--radius-md);font-size:var(--text-xs);color:var(--text-secondary);overflow-x:auto;max-height:300px">${JSON.stringify(alert, null, 2)}</pre>
      </details>
    `;
  }

  function _field(label, value) {
    return `<div><div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:2px">${label}</div><div style="font-size:var(--text-sm);color:var(--text-primary);word-break:break-all">${value || '--'}</div></div>`;
  }

  function _metricField(label, value, color) {
    return `<div style="display:flex;align-items:center;justify-content:space-between;padding:var(--space-2) 0;border-bottom:1px solid var(--border-subtle)">
      <span style="font-size:var(--text-xs);color:var(--text-muted)">${label}</span>
      <span style="font-size:var(--text-sm);font-weight:600;color:${color}">${value}</span>
    </div>`;
  }

  function _buildExplanation(alert) {
    const anomaly = Number(alert.anomaly_score || 0);
    const confidence = Number(alert.confidence || 0);
    const attack = Formatters.attackLabel(alert.attack_type);
    const decision = alert.ml_decision_original || 'ALERT';
    const reason = alert.reason || '';

    let explanation = '';

    if (decision === 'BLOCK') {
      explanation = `<strong>Decision: BLOCK</strong> — The ML pipeline determined this is a <strong>${attack}</strong> attack with high confidence (${Formatters.decimal(confidence)}). `;
      if (anomaly >= 0.7) explanation += `The anomaly score of ${Formatters.decimal(anomaly)} exceeds the high-anomaly threshold (0.70), indicating statistically unusual request behavior. `;
      explanation += `Combined with classifier confidence of ${Formatters.decimal(confidence)}, the Decision Engine escalated this to BLOCK status. `;
    } else if (decision === 'ALERT') {
      explanation = `<strong>Decision: ALERT</strong> — Suspicious activity detected as <strong>${attack}</strong>. `;
      if (anomaly >= 0.7 && confidence < 0.7) explanation += `High anomaly score (${Formatters.decimal(anomaly)}) but lower classifier confidence (${Formatters.decimal(confidence)}) suggests this requires human investigation. `;
      else if (anomaly < 0.7) explanation += `Moderate anomaly score (${Formatters.decimal(anomaly)}) with classifier confidence of ${Formatters.decimal(confidence)}. `;
      explanation += 'The request was forwarded but queued for SOC admin review. ';
    } else {
      explanation = `<strong>Decision: ${decision}</strong> — ${reason}. `;
    }

    explanation += '<br><br><em style="color:var(--text-muted)">This request is pending admin review. Your decision will be enforced on all future matching requests from this source.</em>';
    return explanation;
  }

  function _buildTimeline(alert) {
    const isPending = (alert.status || '').includes('PENDING');
    const isBlocked = (alert.status || '').includes('BLOCK');
    const isResolved = !isPending;

    const steps = [
      { label: 'Request Received', meta: `${alert.method} ${alert.path}`, dot: 'completed' },
      { label: 'Feature Extraction', meta: '35 features extracted', dot: 'completed' },
      { label: 'Anomaly Detection', meta: `Score: ${Formatters.decimal(alert.anomaly_score)}`, dot: 'completed' },
      { label: 'Attack Classification', meta: `${Formatters.attackLabel(alert.attack_type)} (${Formatters.decimal(alert.confidence)})`, dot: 'completed' },
      { label: 'FP Reduction', meta: 'False positive check applied', dot: 'completed' },
      { label: 'Decision Engine', meta: `Decision: ${alert.ml_decision_original || 'N/A'}`, dot: 'completed' },
      { label: 'Queued for Admin', meta: `Alert ${alert.alert_id}`, dot: isPending ? 'active' : 'completed' },
    ];

    if (isResolved) {
      steps.push({ label: 'Admin Decision', meta: `${alert.admin_action || alert.status} at ${Formatters.time(alert.admin_action_timestamp)}`, dot: isBlocked ? 'blocked' : 'completed' });
      steps.push({ label: 'Enforcement', meta: isBlocked ? 'Future requests will be blocked (403)' : 'Policy updated', dot: isBlocked ? 'blocked' : 'completed' });
    } else {
      steps.push({ label: 'Awaiting Admin Decision', meta: 'BLOCK / ALLOW / IGNORE', dot: '' });
    }

    return steps.map(s => `
      <div class="timeline-step">
        <div class="timeline-dot ${s.dot}"></div>
        <div class="timeline-content">
          <div class="timeline-label">${s.label}</div>
          <div class="timeline-meta">${s.meta}</div>
        </div>
      </div>
    `).join('');
  }

  function _anomalyColor(val) {
    const v = Number(val);
    if (v >= 0.7) return 'var(--color-critical)';
    if (v >= 0.4) return 'var(--color-medium)';
    return 'var(--color-success)';
  }

  function _decisionColor(dec) {
    const d = String(dec).toUpperCase();
    if (d === 'BLOCK') return 'var(--color-critical)';
    if (d === 'ALERT') return 'var(--color-medium)';
    return 'var(--text-secondary)';
  }

  /** Quick action from table row buttons */
  async function quickAction(alertId, action) {
    if (action === 'BLOCK') {
      const confirmed = await DOM.confirm(
        'Confirm Block',
        `Block all future requests matching this pattern? This will return HTTP 403 for matching requests from this IP.`,
        'Block', 'btn-danger'
      );
      if (!confirmed) return;
    }
    await _doResolve(alertId, action);
  }

  /** Resolve from drawer */
  async function resolveAction(alertId, action) {
    if (action === 'BLOCK') {
      const confirmed = await DOM.confirm(
        'Confirm Block',
        'Block all future matching requests from this IP? Enforcement is immediate and persistent.',
        'Block', 'btn-danger'
      );
      if (!confirmed) return;
    }
    await _doResolve(alertId, action);
  }

  async function _doResolve(alertId, action) {
    try {
      const result = await API.resolveAlert(alertId, action);
      if (result && result.success) {
        DOM.toast(`Alert ${alertId} → ${action}`, 'success');
        DOM.closeDrawer();
        // Force immediate refresh
        const data = await API.getAlerts({ limit: 100 });
        if (data) State.set('alerts', data.alerts || []);
        const stats = await API.getAlertStats();
        if (stats) State.set('alertStats', stats);
      } else {
        DOM.toast(`Failed to resolve alert`, 'error');
      }
    } catch (err) {
      DOM.toast(`Error: ${err.message}`, 'error');
    }
  }

  return { init, openAlert, quickAction, resolveAction };
})();
