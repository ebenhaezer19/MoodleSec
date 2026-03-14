<?php
/**
 * English language strings for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  2024 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
 
$string['pluginname'] = 'Security Dashboard';
$string['security_dashboard'] = 'Security Dashboard';
$string['dashboard'] = 'Dashboard';
$string['scan_results'] = 'Scan Results';
$string['vulnerability_summary'] = 'Vulnerability Summary';
$string['recent_scans'] = 'Recent Scans';
$string['critical'] = 'Critical';
$string['high'] = 'High';
$string['medium'] = 'Medium';
$string['low'] = 'Low';
$string['info'] = 'Info';
$string['scan_now'] = 'Scan Now';
$string['view_details'] = 'View Details';
$string['no_scans'] = 'No scans available';
$string['last_scan'] = 'Last Scan';
$string['total_vulnerabilities'] = 'Total Vulnerabilities';
$string['proxy_url'] = 'Proxy Service URL';
$string['proxy_url_desc'] = 'URL of the security proxy service (e.g., http://localhost:8999)';
$string['cvss_url'] = 'CVSS Engine URL';
$string['cvss_url_desc'] = 'URL of the CVSS calculator service (e.g., http://localhost:8001)';
$string['settings'] = 'Settings';
$string['scan_path'] = 'Scan Path';
$string['scan_method'] = 'HTTP Method';
$string['trigger_scan'] = 'Trigger Scan';
$string['scan_success'] = 'Scan completed successfully';
$string['scan_error'] = 'Error triggering scan';
$string['connection_error'] = 'Cannot connect to security services';

// ML Dashboard
$string['ml_dashboard'] = 'ML Dashboard';
$string['ml_system_status'] = 'Machine Learning System Status';
$string['ml_enabled'] = 'ML Enabled';
$string['ml_disabled'] = 'ML Disabled';
$string['ml_models'] = 'ML Models';
$string['ml_training'] = 'Training Information';
$string['ml_performance'] = 'Performance Metrics';
$string['ml_management'] = 'Management';
$string['retrain_models'] = 'Retrain Models';
$string['export_models'] = 'Export Models';

// Capabilities
$string['security_dashboard:view'] = 'View security dashboard';
$string['security_dashboard:scan'] = 'Trigger security scans';
$string['security_dashboard:viewreports'] = 'View security reports';
$string['security_dashboard:downloadreports'] = 'Download security reports';
$string['security_dashboard:manageschedule'] = 'Manage scan schedule';

// Tasks
$string['scan_task'] = 'Scheduled security scan';
$string['scheduled_scan_paths'] = 'Scheduled scan paths';
$string['scheduled_scan_paths_desc'] = 'Comma-separated list of paths to scan automatically (e.g., /login/index.php, /course/view.php)';

// ZAP Integration Settings
$string['zap_settings'] = 'ZAP Settings';
$string['zap_host'] = 'ZAP Server Host';
$string['zap_host_desc'] = 'Hostname or IP address of the ZAP server';
$string['zap_port'] = 'ZAP Server Port';
$string['zap_port_desc'] = 'Port number the ZAP server is listening on (default: 8080)';
$string['zap_api_key'] = 'ZAP API Key';
$string['zap_api_key_desc'] = 'API key for authenticating with ZAP server';
$string['scan_settings'] = 'Scan Settings';
$string['scan_spider_depth'] = 'Spider Depth';
$string['scan_spider_depth_desc'] = 'Maximum depth for spider crawling (1-5)';
$string['scan_policy'] = 'Scanning Policy';
$string['scan_policy_desc'] = 'Default scanning policy (low, medium, high)';
$string['ml_settings'] = 'Machine Learning Settings';
$string['ml_filtering_enabled'] = 'Enable ML Filtering';
$string['ml_filtering_enabled_desc'] = 'Apply machine learning to reduce false positives';
$string['ml_confidence_threshold'] = 'ML Confidence Threshold';
$string['ml_confidence_threshold_desc'] = 'Minimum confidence score for accepting findings (0-1)';
$string['notification_settings'] = 'Notification Settings';
$string['email_on_high_risk'] = 'Email on High Risk Findings';
$string['email_on_high_risk_desc'] = 'Send email notification when high-risk vulnerabilities are found';
$string['email_recipients'] = 'Email Recipients';
$string['email_recipients_desc'] = 'Email addresses to notify (one per line)';

// ZAP Scanning
$string['zap_scan'] = 'ZAP Vulnerability Scan';
$string['zap_scan_title'] = 'Trigger ZAP Scan';
$string['zap_status'] = 'ZAP Server Status';
$string['connection_status'] = 'Connection Status';
$string['zap_connected'] = 'Connected';
$string['zap_disconnected'] = 'Disconnected';
$string['zap_version'] = 'ZAP Version';
$string['scan_type'] = 'Scan Type';
$string['scan_unauthenticated'] = 'Unauthenticated Scan';
$string['scan_authenticated'] = 'Authenticated Scan';
$string['scan_api'] = 'API Scan';
$string['target_url'] = 'Target URL';
$string['target_url_placeholder'] = 'Enter URL to scan (e.g., http://www.example.com)';
$string['trigger_scan_button'] = 'Start Scan';
$string['scanning_in_progress'] = 'Scanning in progress...';
$string['recent_scans_list'] = 'Recent Scans';
$string['scan_id'] = 'Scan ID';
$string['scan_type_label'] = 'Type';
$string['target'] = 'Target';
$string['started'] = 'Started';
$string['duration_seconds'] = 'Duration (s)';
$string['findings_count'] = 'Findings';
$string['view_scan'] = 'View Results';

// ZAP Results
$string['zap_results'] = 'ZAP Scan Results';
$string['scan_summary'] = 'Scan Summary';
$string['total_findings'] = 'Total Findings';
$string['high_risk'] = 'High Risk';
$string['medium_risk'] = 'Medium Risk';
$string['low_risk'] = 'Low Risk';
$string['findings_list'] = 'Vulnerability Findings';
$string['finding_type'] = 'Type';
$string['finding_severity'] = 'Severity';
$string['finding_url'] = 'Vulnerable URL';
$string['finding_evidence'] = 'Evidence';
$string['finding_description'] = 'Description';
$string['finding_solution'] = 'Remediation';
$string['export_pdf'] = 'Export as PDF';
$string['export_json'] = 'Export as JSON';

// ZAP Trends
$string['zap_trends'] = 'Vulnerability Trends';
$string['trends_title'] = 'Security Trends & Analysis';
$string['overall_statistics'] = 'Overall Statistics';
$string['trending_direction'] = 'Trending';
$string['vulnerability_chart'] = 'Vulnerability Timeline';
$string['top_vulnerability_types'] = 'Top Vulnerability Types';
$string['vulnerability_type'] = 'Vulnerability Type';
$string['count'] = 'Count';
$string['severity'] = 'Severity';
$string['monthly_summary'] = 'Monthly Summary';
$string['export_csv'] = 'Export as CSV';

// ZAP Compliance
$string['zap_compliance'] = 'Compliance & Audit';
$string['compliance_report'] = 'Compliance Report';
$string['compliance_score'] = 'Compliance Score';
$string['audit_status'] = 'Audit Status';
$string['security_checklist'] = 'Security Checklist';
$string['owasp_top10'] = 'OWASP Top 10 Coverage';
$string['remediation_actions'] = 'Remediation Actions';
$string['audit_trail'] = 'Audit Trail';
$string['event_type'] = 'Event Type';
$string['event_user'] = 'User';
$string['event_details'] = 'Details';
$string['event_time'] = 'Time';
$string['cert_export'] = 'Export Certificate';
$string['export_html'] = 'Export as HTML';

// ZAP Settings 
$string['zap_configuration'] = 'ZAP Configuration';
$string['zap_server_settings'] = 'ZAP Server Settings';
$string['zap_server_settings_desc'] = 'Settings for ZAP server integration.';
$string['zap_enabled'] = 'Enable ZAP Integration';
$string['zap_enabled_desc'] = 'Enable or disable ZAP vulnerability scanning integration.';
$string['zap_disabled'] = 'ZAP integration is currently disabled. Please enable it in the settings to use ZAP scanning features.';
$string['scan_settings_desc'] = 'Configure scanning behavior and policies.';
$string['scan_authenticated_desc'] = 'Perform authenticated scans using test credentials.';
$string['scan_test_user'] = 'Test Username';
$string['scan_test_user_desc'] = 'Username to use for authenticated scans.';
$string['ml_filtering'] = 'Machine Learning Filtering';
$string['ml_filtering_desc'] = 'Configure machine learning settings to filter false positives.';
$string['notification_settings_desc'] = 'Configure notifications for security findings.';