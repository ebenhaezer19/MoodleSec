/**
 * MoodleSec SOC Dashboard — Threat Activity Feed
 * Sidebar showing latest activity: blocked IPs, attack types, admin actions.
 */
const ThreatFeed = (() => {
  function init() {
    State.on('alerts', render);
    State.on('alertStats', render);
  }

  function render() {
    const body = DOM.$('threat-feed-body');
    if (!body) return;

    const alerts = State.get('alerts') || [];
    const stats = State.get('alertStats') || {};

    if (alerts.length === 0) {
      body.innerHTML = `<div class="empty-state" style="padding:var(--space-4)">
        <div class="empty-state-title" style="font-size:var(--text-sm)">No activity yet</div>
        <div class="empty-state-description">Threat events will appear here</div>
      </div>`;
      return;
    }

    const items = [];

    // Pending count
    const pending = stats.pending || 0;
    if (pending > 0) {
      items.push(_item('⏳', `${pending} alert${pending>1?'s':''} pending review`, 'var(--color-pending)'));
    }

    // Latest blocked
    const lastBlocked = alerts.find(a => (a.status||'').includes('BLOCK'));
    if (lastBlocked) {
      items.push(_item('🛑', `Blocked ${lastBlocked.client_ip} — ${Formatters.attackLabel(lastBlocked.attack_type)}`, 'var(--color-critical)'));
    }

    // Latest XSS
    const lastXSS = alerts.find(a => (a.attack_type||'').toLowerCase() === 'xss');
    if (lastXSS) {
      items.push(_item('⚡', `XSS detected from ${lastXSS.client_ip}`, 'var(--color-medium)'));
    }

    // Latest SQLi
    const lastSQLi = alerts.find(a => (a.attack_type||'').toLowerCase().includes('sql'));
    if (lastSQLi) {
      items.push(_item('💉', `SQLi attempt from ${lastSQLi.client_ip}`, 'var(--color-high)'));
    }

    // Latest admin action
    const lastResolved = alerts.find(a => a.admin_action_timestamp);
    if (lastResolved) {
      items.push(_item('👤', `Admin: ${lastResolved.admin_action} — ${Formatters.timeAgo(lastResolved.admin_action_timestamp)}`, 'var(--accent-cyan)'));
    }

    // Active enforcement rules
    const rules = stats.override_rules_active || 0;
    if (rules > 0) {
      items.push(_item('🔒', `${rules} active enforcement rule${rules>1?'s':''}`, 'var(--accent-blue)'));
    }

    // Total stats
    items.push(_item('📊', `${stats.total_alerts || 0} total alerts processed`, 'var(--text-muted)'));

    body.innerHTML = items.join('');
  }

  function _item(icon, text, color) {
    return `<div style="display:flex;align-items:flex-start;gap:var(--space-3);padding:var(--space-3) 0;border-bottom:1px solid var(--border-subtle)">
      <span style="font-size:var(--text-md);flex-shrink:0;line-height:1">${icon}</span>
      <span style="font-size:var(--text-xs);color:${color};line-height:1.4">${text}</span>
    </div>`;
  }

  return { init, render };
})();
