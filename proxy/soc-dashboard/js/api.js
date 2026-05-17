/**
 * MoodleSec SOC Dashboard — API Client
 * Centralized API layer with error handling, timeout, and stale request cancellation.
 */
const API = (() => {
  const BASE_URL = window.location.origin;
  const TIMEOUT_MS = 8000;

  // Active AbortControllers for cancellation
  const _controllers = new Map();

  /**
   * Core fetch wrapper with timeout + abort support.
   * @param {string} endpoint - API path (e.g. "/soc/alerts")
   * @param {object} options  - fetch options override
   * @param {string} key      - optional dedup key for stale cancellation
   */
  async function request(endpoint, options = {}, key = null) {
    // Cancel previous in-flight request for the same key
    if (key && _controllers.has(key)) {
      _controllers.get(key).abort();
    }

    const controller = new AbortController();
    if (key) _controllers.set(key, controller);

    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const resp = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });

      clearTimeout(timeoutId);
      if (key) _controllers.delete(key);

      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status}: ${body.slice(0, 200)}`);
      }

      return await resp.json();
    } catch (err) {
      clearTimeout(timeoutId);
      if (key) _controllers.delete(key);

      if (err.name === 'AbortError') {
        return null; // Cancelled or timed out — not an error
      }
      throw err;
    }
  }

  // ── SOC Endpoints ────────────────────────────────────

  /** GET /soc/alerts — list alerts with optional filters */
  function getAlerts(params = {}) {
    const qs = new URLSearchParams();
    if (params.status) qs.set('status', params.status);
    if (params.severity) qs.set('severity', params.severity);
    if (params.limit) qs.set('limit', params.limit);
    const query = qs.toString();
    return request(`/soc/alerts${query ? '?' + query : ''}`, {}, 'alerts');
  }

  /** GET /soc/alerts/stats */
  function getAlertStats() {
    return request('/soc/alerts/stats', {}, 'alert-stats');
  }

  /** GET /soc/alerts/:id */
  function getAlertDetail(alertId) {
    return request(`/soc/alerts/${alertId}`);
  }

  /** POST /soc/alerts/:id/resolve */
  function resolveAlert(alertId, action) {
    return request(`/soc/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
  }

  /** GET /soc/status */
  function getSOCStatus() {
    return request('/soc/status', {}, 'soc-status');
  }

  // ── Health / System Endpoints ────────────────────────

  /** GET /health */
  function getHealth() {
    return request('/health', {}, 'health');
  }

  /** GET /ml/status */
  function getMLStatus() {
    return request('/ml/status', {}, 'ml-status');
  }

  /** GET /ml/models/info */
  function getMLModelsInfo() {
    return request('/ml/models/info', {}, 'ml-models');
  }

  /** GET /ml/demo-status */
  function getDemoStatus() {
    return request('/ml/demo-status', {}, 'demo-status');
  }

  /** GET /ml/anomalies/recent */
  function getRecentAnomalies(limit = 20) {
    return request(`/ml/anomalies/recent?limit=${limit}`, {}, 'anomalies');
  }

  /** GET /ml/anomalies/runtime */
  function getAnomalyRuntime() {
    return request('/ml/anomalies/runtime', {}, 'anomaly-runtime');
  }

  // ── Logs ─────────────────────────────────────────────

  /** GET /logs */
  function getLogs(limit = 50) {
    return request(`/logs?limit=${limit}`, {}, 'logs');
  }

  // ── Pipeline Trace ───────────────────────────────────

  /** GET /soc/pipeline/trace/latest */
  function getLatestTraces(limit = 20) {
    return request(`/soc/pipeline/trace/latest?limit=${limit}`, {}, 'pipeline-traces');
  }

  /** GET /soc/pipeline/trace/:requestId */
  function getPipelineTrace(requestId) {
    return request(`/soc/pipeline/trace/${requestId}`);
  }

  // ── Latency measurement ──────────────────────────────

  /** Measure API round-trip time in ms */
  async function measureLatency() {
    const start = performance.now();
    try {
      await request('/health', {}, 'latency');
      return Math.round(performance.now() - start);
    } catch {
      return -1; // offline
    }
  }

  /** POST /soc/alerts/reset-all — clear entire alert queue */
  function resetAllAlerts() {
    return request('/soc/alerts/reset-all', { method: 'POST' });
  }

  /** GET /soc/incidents — correlated incidents */
  function getIncidents(limit = 50) {
    return request(`/soc/incidents?limit=${limit}`, {}, 'incidents');
  }

  /** GET /soc/timeline — alert timeline buckets */
  function getTimeline(minutes = 60, bucket = 5) {
    return request(`/soc/timeline?minutes=${minutes}&bucket=${bucket}`, {}, 'timeline');
  }

  /** GET /ml/performance — ML metrics */
  function getMLPerformance() {
    return request('/ml/performance', {}, 'ml-performance');
  }

  return {
    request, getAlerts, getAlertStats, getAlertDetail, resolveAlert,
    getSOCStatus, getHealth, getMLStatus, getMLModelsInfo, getDemoStatus,
    getRecentAnomalies, getAnomalyRuntime, getLogs, measureLatency,
    getLatestTraces, getPipelineTrace, resetAllAlerts,
    getIncidents, getTimeline, getMLPerformance,
  };
})();
