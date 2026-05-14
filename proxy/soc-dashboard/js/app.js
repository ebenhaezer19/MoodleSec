/**
 * MoodleSec SOC Dashboard — App Orchestrator
 * Initializes components, handles navigation, starts polling, updates clock.
 */
const App = (() => {
  const PAGE_TITLES = {
    overview: 'Overview',
    alerts: 'SOC Alert Queue',
    pipeline: 'ML Pipeline',
    statistics: 'Statistics',
    health: 'System Health',
    logs: 'Trace Logs',
  };

  function init() {
    console.log('[MoodleSec] SOC Dashboard initializing...');

    // Init all components
    OverviewCards.init();
    AlertFeed.init();
    AdminPanel.init();
    ThreatFeed.init();
    PipelineViz.init();
    StatsCharts.init();
    HealthPanel.init();
    PersistenceView.init();
    LogViewer.init();
    PipelineTraceViz.init();

    // Navigation
    document.querySelectorAll('.sidebar-item[data-page]').forEach(item => {
      item.addEventListener('click', () => navigateTo(item.dataset.page));
    });

    // Sidebar status indicators
    State.on('backendOnline', _updateBackendStatus);
    State.on('socMode', _updateSOCStatus);

    // Clock
    _updateClock();
    setInterval(_updateClock, 1000);

    // Start polling
    Polling.startAll();

    console.log('[MoodleSec] SOC Dashboard ready');
  }

  function navigateTo(page) {
    if (!PAGE_TITLES[page]) return;

    // Update sidebar
    document.querySelectorAll('.sidebar-item').forEach(el => el.classList.remove('active'));
    const navItem = document.querySelector(`.sidebar-item[data-page="${page}"]`);
    if (navItem) navItem.classList.add('active');

    // Update pages
    document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
    const pageEl = DOM.$(`page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    // Update title
    DOM.$('page-title').textContent = PAGE_TITLES[page];
    State.set('currentPage', page);
  }

  function _updateBackendStatus(online) {
    const dot = DOM.$('sidebar-backend-dot');
    const label = DOM.$('sidebar-backend-label');
    const apiDot = DOM.$('navbar-api-dot');
    const apiLabel = DOM.$('navbar-api-label');

    if (dot) { dot.className = `sidebar-status-dot ${online ? 'online' : 'offline'}`; }
    if (label) { label.textContent = online ? 'Backend Online' : 'Backend Offline'; }
    if (apiDot) { apiDot.className = `dot ${online ? '' : 'error'}`; }
    if (apiLabel) { apiLabel.textContent = online ? 'API Connected' : 'API Disconnected'; }
  }

  function _updateSOCStatus(socMode) {
    const dot = DOM.$('sidebar-soc-dot');
    const label = DOM.$('sidebar-soc-label');
    const modeDot = DOM.$('navbar-mode-dot');
    const modeLabel = DOM.$('navbar-mode-label');

    if (dot) { dot.className = `sidebar-status-dot ${socMode ? 'online' : 'warning'}`; }
    if (label) { label.textContent = socMode ? 'SOC Mode Active' : 'SOC Mode Inactive'; }
    if (modeDot) { modeDot.className = `dot ${socMode ? '' : 'warning'}`; }
    if (modeLabel) { modeLabel.textContent = socMode ? 'SOC Mode' : 'Demo Mode'; }
  }

  function _updateClock() {
    const el = DOM.$('navbar-clock');
    if (el) el.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
  }

  // Boot
  document.addEventListener('DOMContentLoaded', init);

  return { navigateTo };
})();
