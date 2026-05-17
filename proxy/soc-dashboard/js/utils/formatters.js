/**
 * MoodleSec SOC Dashboard — Formatters
 * Date, number, severity, and display formatting utilities.
 */
const Formatters = (() => {
  /**
   * Format ISO timestamp to short display: "14:32:05"
   */
  function time(isoString) {
    if (!isoString) return '--:--:--';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return '--:--:--';
      return d.toLocaleTimeString('en-GB', { hour12: false });
    } catch { return '--:--:--'; }
  }

  /**
   * Format ISO timestamp to date+time: "May 11, 14:32"
   */
  function dateTime(isoString) {
    if (!isoString) return '--';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return '--';
      const month = d.toLocaleString('en', { month: 'short' });
      const day = d.getDate();
      const t = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
      return `${month} ${day}, ${t}`;
    } catch { return '--'; }
  }

  /**
   * Relative time: "2m ago", "1h ago"
   */
  function timeAgo(isoString) {
    if (!isoString) return '--';
    try {
      const d = new Date(isoString);
      const now = new Date();
      const diffMs = now - d;
      const diffS = Math.floor(diffMs / 1000);
      if (diffS < 5) return 'just now';
      if (diffS < 60) return `${diffS}s ago`;
      const diffM = Math.floor(diffS / 60);
      if (diffM < 60) return `${diffM}m ago`;
      const diffH = Math.floor(diffM / 60);
      if (diffH < 24) return `${diffH}h ago`;
      const diffD = Math.floor(diffH / 24);
      return `${diffD}d ago`;
    } catch { return '--'; }
  }

  /**
   * Format number with locale separators: 1234 -> "1,234"
   */
  function number(val) {
    if (val === null || val === undefined) return '0';
    return Number(val).toLocaleString('en-US');
  }

  /**
   * Format float to fixed decimals: 0.8523 -> "0.85"
   */
  function percent(val, decimals = 0) {
    if (val === null || val === undefined) return '0%';
    return (Number(val) * 100).toFixed(decimals) + '%';
  }

  function decimal(val, decimals = 2) {
    if (val === null || val === undefined) return '0.00';
    return Number(val).toFixed(decimals);
  }

  /**
   * Severity to CSS badge class
   */
  function severityBadgeClass(severity) {
    const s = String(severity).toUpperCase();
    const map = {
      'CRITICAL': 'badge-critical', 'HIGH': 'badge-high',
      'MEDIUM': 'badge-medium', 'LOW': 'badge-low', 'INFO': 'badge-info',
    };
    return map[s] || 'badge-info';
  }

  /**
   * Status to CSS badge class
   */
  function statusBadgeClass(status) {
    const s = String(status).toUpperCase();
    if (s === 'RESET') return 'badge-allow';
    if (s.includes('BLOCK')) return 'badge-block';
    if (s.includes('ALLOW')) return 'badge-allow';
    if (s.includes('IGNORE')) return 'badge-ignore';
    if (s.includes('PENDING')) return 'badge-pending';
    return 'badge-info';
  }

  /**
   * Status to short display label
   */
  function statusLabel(status) {
    const s = String(status).toUpperCase();
    if (s === 'RESET') return '🟢 RESET (RETESTABLE)';
    if (s.includes('PENDING')) return 'PENDING';
    if (s.includes('ENFORCED_BLOCK') || s === 'ENFORCED_BLOCK') return '🔴 BLOCKED';
    if (s.includes('BLOCK')) return 'BLOCKED';
    if (s.includes('ALLOW')) return 'ALLOWED';
    if (s.includes('IGNORE')) return 'IGNORED';
    return status;
  }

  /**
   * Confidence to color
   */
  function confidenceColor(val) {
    const v = Number(val);
    if (v >= 0.7) return 'var(--color-critical)';
    if (v >= 0.4) return 'var(--color-medium)';
    return 'var(--color-success)';
  }

  /**
   * Attack type to readable label
   */
  function attackLabel(type) {
    if (!type) return 'Unknown';
    const map = {
      'xss': 'Cross-Site Scripting (XSS)',
      'sqli': 'SQL Injection',
      'sql injection': 'SQL Injection',
      'command injection': 'Command Injection',
      'rce': 'Remote Code Execution',
      'path traversal': 'Path Traversal',
      'directory traversal': 'Directory Traversal',
      'lfi': 'Local File Inclusion',
      'rfi': 'Remote File Inclusion',
      'ssrf': 'Server-Side Request Forgery (SSRF)',
      'server-side request forgery': 'Server-Side Request Forgery (SSRF)',
      'normal': 'Normal Traffic',
      'unknown': 'Unknown',
    };
    return map[String(type).toLowerCase()] || type;
  }

  /**
   * Truncate string with ellipsis
   */
  function truncate(str, maxLen = 30) {
    if (!str) return '';
    const s = String(str);
    return s.length > maxLen ? s.substring(0, maxLen) + '…' : s;
  }

  return {
    time, dateTime, timeAgo, number, percent, decimal,
    severityBadgeClass, statusBadgeClass, statusLabel,
    confidenceColor, attackLabel, truncate,
  };
})();
