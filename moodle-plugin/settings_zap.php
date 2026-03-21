<?php
/**
 * ZAP Integration Settings and Configuration
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

global $CFG;

// Settings for ZAP Integration
if ($hassiteconfig) {
    // Create ZAP Configuration category
    $settings_zap = new admin_settingpage('local_security_dashboard_zap',
        new lang_string('zap_configuration', 'local_security_dashboard'));
    
    // ZAP Server Settings
    $settings_zap->add(new admin_setting_heading('local_security_dashboard/zap_server',
        new lang_string('zap_server_settings', 'local_security_dashboard'),
        new lang_string('zap_server_settings_desc', 'local_security_dashboard')));
    
    // ZAP Host
    $settings_zap->add(new admin_setting_configtext('local_security_dashboard/zap_host',
        new lang_string('zap_host', 'local_security_dashboard'),
        new lang_string('zap_host_desc', 'local_security_dashboard'),
        'localhost',
        PARAM_HOST));
    
    // ZAP Port
    $settings_zap->add(new admin_setting_configtext('local_security_dashboard/zap_port',
        new lang_string('zap_port', 'local_security_dashboard'),
        new lang_string('zap_port_desc', 'local_security_dashboard'),
        '8080',
        PARAM_INT));
    
    // ZAP API Key
    $settings_zap->add(new admin_setting_configpasswordunmask('local_security_dashboard/zap_api_key',
        new lang_string('zap_api_key', 'local_security_dashboard'),
        new lang_string('zap_api_key_desc', 'local_security_dashboard'),
        '.'));
    
    // ZAP Enabled
    $settings_zap->add(new admin_setting_configcheckbox('local_security_dashboard/zap_enabled',
        new lang_string('zap_enabled', 'local_security_dashboard'),
        new lang_string('zap_enabled_desc', 'local_security_dashboard'),
        1));
    
    // Scanning Configuration
    $settings_zap->add(new admin_setting_heading('local_security_dashboard/scan_settings',
        new lang_string('scan_settings', 'local_security_dashboard'),
        new lang_string('scan_settings_desc', 'local_security_dashboard')));
    
    // Spider Depth
    $settings_zap->add(new admin_setting_configtext('local_security_dashboard/scan_spider_depth',
        new lang_string('scan_spider_depth', 'local_security_dashboard'),
        new lang_string('scan_spider_depth_desc', 'local_security_dashboard'),
        '3',
        PARAM_INT));
    
    // Scan Policy
    $policies = [
        'low' => 'Low (Fast)',
        'medium' => 'Medium (Balanced)',
        'high' => 'High (Thorough)',
    ];
    $settings_zap->add(new admin_setting_configselect('local_security_dashboard/scan_policy',
        new lang_string('scan_policy', 'local_security_dashboard'),
        new lang_string('scan_policy_desc', 'local_security_dashboard'),
        'medium',
        $policies));
    
    // Enable Authentication
    $settings_zap->add(new admin_setting_configcheckbox('local_security_dashboard/scan_authenticated',
        new lang_string('scan_authenticated', 'local_security_dashboard'),
        new lang_string('scan_authenticated_desc', 'local_security_dashboard'),
        1));
    
    // Authentication Settings Section
    $settings_zap->add(new admin_setting_heading('local_security_dashboard/auth_settings',
        'Authenticated Scanning Settings',
        'Configure how ZAP authenticates to Moodle for authenticated scanning'));
    
    // Authentication Method
    $auth_methods = [
        'manual' => 'Manual Credentials (Admin enters username/password)',
        'auto_admin' => 'Auto-Detect Admin User (scans as first admin)',
        'session_token' => 'Session Token (uses Moodle login flow)',
    ];
    $settings_zap->add(new admin_setting_configselect('local_security_dashboard/auth_method',
        'Authentication Method',
        'Select how ZAP should authenticate. Manual = store credentials. Auto = use existing admin. Token = more secure.',
        'auto_admin',
        $auth_methods));
    
    // Test User (for manual auth method)
    $settings_zap->add(new admin_setting_configtext('local_security_dashboard/scan_test_user',
        'Scan Test Username',
        'Username to use for authenticated scanning (used if "Manual Credentials" method selected)',
        'admin',
        PARAM_USERNAME));
    
    // Test User Password (encrypted storage)
    $settings_zap->add(new admin_setting_configpasswordunmask('local_security_dashboard/scan_test_password',
        'Scan Test Password',
        'Password for the test user (will be encrypted). Leave empty to skip authenticated scanning.',
        '',
        PARAM_RAW));
    
    // ML Filtering Configuration
    $settings_zap->add(new admin_setting_heading('local_security_dashboard/ml_settings',
        new lang_string('ml_filtering', 'local_security_dashboard'),
        new lang_string('ml_filtering_desc', 'local_security_dashboard')));
    
    // Enable ML Filtering
    $settings_zap->add(new admin_setting_configcheckbox('local_security_dashboard/ml_filtering_enabled',
        new lang_string('ml_filtering_enabled', 'local_security_dashboard'),
        new lang_string('ml_filtering_enabled_desc', 'local_security_dashboard'),
        1));
    
    // ML Confidence Threshold
    $settings_zap->add(new admin_setting_configtext('local_security_dashboard/ml_confidence_threshold',
        new lang_string('ml_confidence_threshold', 'local_security_dashboard'),
        new lang_string('ml_confidence_threshold_desc', 'local_security_dashboard'),
        '0.75',
        PARAM_FLOAT));
    
    // Notification Settings
    $settings_zap->add(new admin_setting_heading('local_security_dashboard/notification_settings',
        new lang_string('notification_settings', 'local_security_dashboard'),
        new lang_string('notification_settings_desc', 'local_security_dashboard')));
    
    // Email on High Risk
    $settings_zap->add(new admin_setting_configcheckbox('local_security_dashboard/email_on_high_risk',
        new lang_string('email_on_high_risk', 'local_security_dashboard'),
        new lang_string('email_on_high_risk_desc', 'local_security_dashboard'),
        1));
    
    // Email Recipients
    $settings_zap->add(new admin_setting_configtextarea('local_security_dashboard/email_recipients',
        new lang_string('email_recipients', 'local_security_dashboard'),
        new lang_string('email_recipients_desc', 'local_security_dashboard'),
        '',
        PARAM_RAW));
    
    $ADMIN->add('local_security_dashboard', $settings_zap);
}
