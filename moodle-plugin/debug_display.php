<?php
/**
 * Debug Display Component for Payload Injection Tracking
 * 
 * Shows real-time debug information about:
 * - Payloads loaded
 * - Injection attempts
 * - Success/failure status
 * - Errors encountered
 * 
 * Can be displayed in a modal or panel during scanning
 */

// This is a reusable component - include it with:
// require_once(__DIR__ . '/debug_display.php');
// display_debug_panel($scan_id, $proxy_url);

function display_debug_panel($scan_id, $proxy_url = 'http://localhost:8999') {
    ?>
    <style>
        .debug-panel {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .debug-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #dee2e6;
            margin-bottom: 15px;
        }
        
        .debug-title {
            font-size: 14px;
            font-weight: bold;
            color: #212529;
        }
        
        .debug-controls {
            display: flex;
            gap: 10px;
        }
        
        .debug-btn {
            padding: 5px 12px;
            font-size: 11px;
            border: 1px solid #dee2e6;
            background: white;
            cursor: pointer;
            border-radius: 4px;
            transition: all 0.2s;
        }
        
        .debug-btn:hover {
            background: #e9ecef;
            border-color: #adb5bd;
        }
        
        .debug-btn.refresh {
            background: #007bff;
            color: white;
            border-color: #0056b3;
        }
        
        .debug-btn.refresh:hover {
            background: #0056b3;
        }
        
        .debug-btn.clear {
            background: #dc3545;
            color: white;
            border-color: #bd2130;
        }
        
        .debug-btn.clear:hover {
            background: #bd2130;
        }
        
        .debug-logs {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
        }
        
        .debug-log-entry {
            padding: 8px;
            border-left: 3px solid #dee2e6;
            margin: 5px 0;
            background: #f8f9fa;
        }
        
        .debug-log-entry.payload-loaded {
            border-left-color: #28a745;
            background: #f1f7f4;
        }
        
        .debug-log-entry.payload-injected {
            border-left-color: #ffc107;
            background: #fffbf0;
        }
        
        .debug-log-entry.scan-start {
            border-left-color: #17a2b8;
            background: #f0f8fa;
        }
        
        .debug-log-entry.scan-complete {
            border-left-color: #28a745;
            background: #f1f7f4;
        }
        
        .debug-log-entry.error {
            border-left-color: #dc3545;
            background: #fdf7f7;
        }
        
        .debug-timestamp {
            color: #6c757d;
            font-size: 10px;
            margin-right: 10px;
        }
        
        .debug-event-type {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 10px;
            margin-right: 10px;
            min-width: 80px;
            text-align: center;
        }
        
        .event-payload-loaded {
            background: #28a745;
            color: white;
        }
        
        .event-payload-injected {
            background: #ffc107;
            color: #000;
        }
        
        .event-scan-start {
            background: #17a2b8;
            color: white;
        }
        
        .event-scan-complete {
            background: #28a745;
            color: white;
        }
        
        .event-error {
            background: #dc3545;
            color: white;
        }
        
        .debug-details {
            margin-top: 5px;
            color: #495057;
            line-height: 1.4;
        }
        
        .debug-injection-point {
            display: inline-block;
            background: #e7e7e7;
            padding: 2px 6px;
            border-radius: 3px;
            margin: 0 5px;
        }
        
        .debug-status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 10px;
        }
        
        .status-success {
            background: #28a745;
            color: white;
        }
        
        .status-failed {
            background: #dc3545;
            color: white;
        }
        
        .status-attempt {
            background: #ffc107;
            color: #000;
        }
        
        .debug-empty {
            padding: 20px;
            text-align: center;
            color: #6c757d;
        }
        
        .debug-loading {
            text-align: center;
            padding: 20px;
            color: #6c757d;
        }
        
        .debug-spinner {
            display: inline-block;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            margin-right: 10px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .debug-statistics {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 2px solid #dee2e6;
        }
        
        .debug-stat-box {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
            text-align: center;
        }
        
        .debug-stat-label {
            color: #6c757d;
            font-size: 11px;
            margin-bottom: 5px;
        }
        
        .debug-stat-value {
            font-size: 18px;
            font-weight: bold;
            color: #212529;
        }
    </style>
    
    <script>
        let debugLogsInterval = null;
        
        function fetchDebugLogs() {
            const scanId = '<?php echo $scan_id; ?>';
            const proxyUrl = '<?php echo $proxy_url; ?>';
            
            if (!scanId) {
                console.warn('Debug: scan_id not set');
                return;
            }
            
            fetch(`${proxyUrl}/api/debug/scan/${scanId}/logs`)
                .then(response => response.json())
                .then(data => {
                    displayDebugLogs(data);
                })
                .catch(error => {
                    console.error('Failed to fetch debug logs:', error);
                    updateDebugStatus('Failed to fetch logs: ' + error.message, 'error');
                });
        }
        
        function displayDebugLogs(data) {
            const logsContainer = document.getElementById('debug-logs-container');
            
            if (!data.logs || data.logs.length === 0) {
                logsContainer.innerHTML = '<div class="debug-empty">No debug logs yet...</div>';
                return;
            }
            
            let html = '';
            let injectionCount = 0;
            let successCount = 0;
            let errorCount = 0;
            
            data.logs.forEach(log => {
                const eventType = log.event_type.toLowerCase();
                const timestamp = new Date(log.timestamp).toLocaleTimeString();
                
                if (log.event_type === 'PAYLOAD_INJECTED') {
                    injectionCount++;
                    if (log.status === 'SUCCESS') successCount++;
                    if (log.error_message) errorCount++;
                }
                
                let entryClass = 'debug-log-entry ';
                let eventClass = 'debug-event-type event-';
                
                if (log.event_type === 'PAYLOAD_LOADED') {
                    entryClass += 'payload-loaded';
                    eventClass += 'payload-loaded';
                } else if (log.event_type === 'PAYLOAD_INJECTED') {
                    entryClass += 'payload-injected';
                    eventClass += 'payload-injected';
                } else if (log.event_type === 'SCAN_START') {
                    entryClass += 'scan-start';
                    eventClass += 'scan-start';
                } else if (log.event_type === 'SCAN_COMPLETE') {
                    entryClass += 'scan-complete';
                    eventClass += 'scan-complete';
                } else if (log.error_message) {
                    entryClass += 'error';
                    eventClass += 'error';
                }
                
                html += `<div class="${entryClass}">`;
                html += `<span class="debug-timestamp">${timestamp}</span>`;
                html += `<span class="${eventClass}">${log.event_type}</span>`;
                
                if (log.event_type === 'PAYLOAD_LOADED') {
                    html += `Loaded <strong>${log.category}</strong> payloads`;
                } else if (log.event_type === 'PAYLOAD_INJECTED') {
                    const statusClass = `debug-status-badge status-${log.status.toLowerCase()}`;
                    html += `<span class="${statusClass}">${log.status}</span>`;
                    html += `<div class="debug-details">`;
                    html += `Category: <strong>${log.category}</strong> | `;
                    html += `Point: <span class="debug-injection-point">${log.injection_point}</span><br/>`;
                    html += `Payload: <code style="background: #e7e7e7; padding: 2px 4px;">${escapeHtml(log.payload_text)}</code><br/>`;
                    html += `URL: <code>${log.target_url}</code>`;
                    if (log.error_message) {
                        html += `<br/><span style="color: #dc3545;">Error: ${escapeHtml(log.error_message)}</span>`;
                    }
                    html += `</div>`;
                } else if (log.event_type === 'SCAN_START') {
                    html += `Starting scan on ${log.target_url}`;
                } else if (log.event_type === 'SCAN_COMPLETE') {
                    html += `Scan completed`;
                }
                
                html += `</div>`;
            });
            
            logsContainer.innerHTML = html;
            
            // Update statistics
            updateDebugStatistics(data.logs.length, injectionCount, successCount, errorCount);
        }
        
        function updateDebugStatistics(total, injections, successes, errors) {
            const statsDiv = document.getElementById('debug-statistics');
            if (!statsDiv) return;
            
            const successRate = injections > 0 ? Math.round((successes / injections) * 100) : 0;
            
            statsDiv.innerHTML = `
                <div class="debug-stat-box">
                    <div class="debug-stat-label">Total Events</div>
                    <div class="debug-stat-value">${total}</div>
                </div>
                <div class="debug-stat-box">
                    <div class="debug-stat-label">Injections</div>
                    <div class="debug-stat-value">${injections}</div>
                </div>
                <div class="debug-stat-box">
                    <div class="debug-stat-label">Success Rate</div>
                    <div class="debug-stat-value" style="color: ${successRate >= 80 ? '#28a745' : successRate >= 50 ? '#ffc107' : '#dc3545'};">
                        ${successRate}%
                    </div>
                </div>
                <div class="debug-stat-box">
                    <div class="debug-stat-label">Errors</div>
                    <div class="debug-stat-value" style="color: ${errors > 0 ? '#dc3545' : '#28a745'};">
                        ${errors}
                    </div>
                </div>
            `;
        }
        
        function updateDebugStatus(message, type = 'info') {
            const statusDiv = document.getElementById('debug-status');
            if (!statusDiv) return;
            
            const color = type === 'error' ? '#dc3545' : '#007bff';
            statusDiv.innerHTML = `<div style="color: ${color}; padding: 10px; background: ${type === 'error' ? '#fdf7f7' : '#f0f8ff'}; border-radius: 4px;">${message}</div>`;
        }
        
        function startAutoRefresh(interval = 2000) {
            debugLogsInterval = setInterval(fetchDebugLogs, interval);
            console.log('Debug logs auto-refresh started (interval: ' + interval + 'ms)');
        }
        
        function stopAutoRefresh() {
            if (debugLogsInterval) {
                clearInterval(debugLogsInterval);
                debugLogsInterval = null;
                console.log('Debug logs auto-refresh stopped');
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Auto-start refresh when panel loads
        document.addEventListener('DOMContentLoaded', function() {
            const debugPanel = document.getElementById('debug-panel');
            if (debugPanel) {
                startAutoRefresh(2000);
                // Initial fetch
                fetchDebugLogs();
            }
        });
    </script>
    
    <div id="debug-panel" class="debug-panel">
        <div class="debug-header">
            <div class="debug-title">
                🔍 Payload Injection Debug Logs
                <span style="color: #6c757d; font-size: 11px; font-weight: normal;">
                    (Scan ID: <?php echo htmlspecialchars($scan_id); ?>)
                </span>
            </div>
            <div class="debug-controls">
                <button class="debug-btn refresh" onclick="fetchDebugLogs()">🔄 Refresh</button>
                <button class="debug-btn" onclick="stopAutoRefresh()">⏸ Pause</button>
                <button class="debug-btn" onclick="startAutoRefresh()">▶ Resume</button>
                <button class="debug-btn clear" onclick="document.getElementById('debug-logs-container').innerHTML='';">✕ Clear</button>
            </div>
        </div>
        
        <div id="debug-status"></div>
        
        <div id="debug-logs-container" class="debug-logs">
            <div class="debug-loading">
                <div class="debug-spinner"></div>
                Loading debug logs...
            </div>
        </div>
        
        <div id="debug-statistics" class="debug-statistics">
            <!-- Statistics will be populated here -->
        </div>
    </div>
    
    <?php
}

/**
 * Display debug panel in a modal (useful for fixed overlay)
 */
function display_debug_modal($scan_id, $proxy_url = 'http://localhost:8999') {
    ?>
    <style>
        .debug-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .debug-modal-content {
            background: white;
            border-radius: 8px;
            width: 90%;
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }
        
        .debug-modal-header {
            padding: 20px;
            border-bottom: 2px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .debug-modal-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #6c757d;
        }
        
        .debug-modal-close:hover {
            color: #212529;
        }
        
        .debug-modal-body {
            padding: 20px;
        }
    </style>
    
    <div id="debug-modal-overlay" class="debug-modal-overlay" style="display: none;">
        <div class="debug-modal-content">
            <div class="debug-modal-header">
                <h3 style="margin: 0;">Debug Logs</h3>
                <button class="debug-modal-close" onclick="document.getElementById('debug-modal-overlay').style.display='none';">×</button>
            </div>
            <div class="debug-modal-body">
                <?php display_debug_panel($scan_id, $proxy_url); ?>
            </div>
        </div>
    </div>
    
    <script>
        function showDebugModal() {
            document.getElementById('debug-modal-overlay').style.display = 'flex';
        }
        
        function hideDebugModal() {
            stopAutoRefresh();
            document.getElementById('debug-modal-overlay').style.display = 'none';
        }
    </script>
    
    <?php
}

?>
