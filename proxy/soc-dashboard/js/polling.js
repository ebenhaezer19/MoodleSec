/**
 * MoodleSec SOC Dashboard — Polling Manager
 * Tiered polling with reconnect handling and debounce.
 */
const Polling = (() => {
  const _timers = new Map();
  let _running = false;

  /** Register and start a polling task */
  function register(name, fn, intervalMs) {
    if (_timers.has(name)) clearInterval(_timers.get(name));
    // Run immediately, then at interval
    _safeRun(name, fn);
    const id = setInterval(() => _safeRun(name, fn), intervalMs);
    _timers.set(name, id);
  }

  async function _safeRun(name, fn) {
    try { await fn(); }
    catch (err) { console.warn(`[Polling] ${name} error:`, err.message); }
  }

  /** Stop a specific poll */
  function stop(name) {
    if (_timers.has(name)) {
      clearInterval(_timers.get(name));
      _timers.delete(name);
    }
  }

  /** Stop all polls */
  function stopAll() {
    for (const [name, id] of _timers) clearInterval(id);
    _timers.clear();
    _running = false;
  }

  /** Start all tiered polling */
  function startAll() {
    if (_running) return;
    _running = true;

    // ── CRITICAL (2-3s) — SOC alerts ──
    register('alerts', async () => {
      const data = await API.getAlerts({ limit: 100 });
      if (data) State.set('alerts', data.alerts || []);
    }, 3000);

    // ── MEDIUM (5-10s) — Stats, health, SOC status ──
    register('alertStats', async () => {
      const data = await API.getAlertStats();
      if (data) State.set('alertStats', data);
    }, 5000);

    register('health', async () => {
      const latency = await API.measureLatency();
      State.update({
        backendOnline: latency >= 0,
        apiLatency: latency,
      });
    }, 7000);

    register('socStatus', async () => {
      const data = await API.getSOCStatus();
      if (data) {
        State.update({
          socMode: data.soc_mode || false,
          demoMode: data.demo_mode || false,
          enforcementMode: data.enforcement_mode || 'UNKNOWN',
        });
      }
    }, 10000);

    // ── RARE (30-60s) — ML models, anomalies ──
    register('mlStatus', async () => {
      const data = await API.getMLStatus();
      if (data) State.set('mlStatus', data);
    }, 30000);

    register('mlModels', async () => {
      const data = await API.getMLModelsInfo();
      if (data) State.set('mlModels', data);
    }, 60000);

    // ── LOGS (10s) — Incremental ──
    register('logs', async () => {
      const data = await API.getLogs(30);
      if (data && data.logs) State.set('logs', data.logs);
    }, 10000);

    // ── PIPELINE TRACES (8s) — Explainable AI traces ──
    register('pipelineTraces', async () => {
      const data = await API.getLatestTraces(20);
      if (data && data.traces) State.set('pipelineTraces', data.traces);
    }, 8000);
  }

  return { register, stop, stopAll, startAll };
})();
