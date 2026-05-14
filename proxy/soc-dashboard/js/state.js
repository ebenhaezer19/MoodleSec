/**
 * MoodleSec SOC Dashboard — State Manager
 * Centralized reactive state store.
 */
const State = (() => {
  const _state = {
    // Connection
    backendOnline: false,
    apiLatency: -1,

    // SOC Mode
    socMode: false,
    demoMode: false,
    enforcementMode: 'UNKNOWN',

    // Alerts
    alerts: [],
    alertStats: { total_alerts: 0, pending: 0, blocked: 0, allowed: 0, ignored: 0, override_rules_active: 0 },

    // ML
    mlStatus: null,
    mlModels: null,

    // Logs
    logs: [],

    // UI
    currentPage: 'overview',
    selectedAlertId: null,
    lastUpdated: {},
  };

  const _listeners = new Map();

  /** Subscribe to state key changes */
  function on(key, callback) {
    if (!_listeners.has(key)) _listeners.set(key, []);
    _listeners.get(key).push(callback);
  }

  /** Notify listeners for a key */
  function _notify(key) {
    const cbs = _listeners.get(key) || [];
    for (const cb of cbs) {
      try { cb(_state[key]); } catch (e) { console.error(`[State] listener error for ${key}:`, e); }
    }
  }

  /** Get state value */
  function get(key) {
    return _state[key];
  }

  /** Set state value and notify listeners */
  function set(key, value) {
    _state[key] = value;
    _state.lastUpdated[key] = Date.now();
    _notify(key);
  }

  /** Batch update multiple keys, notify once per key */
  function update(obj) {
    const now = Date.now();
    for (const [key, value] of Object.entries(obj)) {
      _state[key] = value;
      _state.lastUpdated[key] = now;
    }
    for (const key of Object.keys(obj)) {
      _notify(key);
    }
  }

  return { on, get, set, update };
})();
