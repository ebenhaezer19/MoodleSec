<?php
/**
 * Settings for Security Dashboard plugin
 *
 * @package    local_security_dashboard
 * @copyright  2024 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();


if ($hassiteconfig) {
    // Don't create $settings if we're adding a category
    // Create main category for Security Dashboard
    $ADMIN->add('localplugins', new admin_category('local_security_dashboard', 
        get_string('pluginname', 'local_security_dashboard')));
    
    // Add Dashboard page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_dashboard',
        'Dashboard',
        new moodle_url('/local/security_dashboard/index.php'),
        'moodle/site:config'
    ));
    
    // Add Reports page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_reports',
        'Reports',
        new moodle_url('/local/security_dashboard/reports.php'),
        'moodle/site:config'
    ));
    
    // Add Scheduler page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_scheduler',
        'Scheduler',
        new moodle_url('/local/security_dashboard/scheduler.php'),
        'moodle/site:config'
    ));
    
    // Add Phishing Scanner page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_phishing',
        'Phishing Content Scanner',
        new moodle_url('/local/security_dashboard/scan_phishing_content.php'),
        'moodle/site:config'
    ));
    
    // Add Login Monitor page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_login',
        'Login Activity Monitor',
        new moodle_url('/local/security_dashboard/login_monitor.php'),
        'moodle/site:config'
    ));
    
    // Add Trends page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_trends',
        'Trends',
        new moodle_url('/local/security_dashboard/trends.php'),
        'moodle/site:config'
    ));
    
    // Add ML Dashboard page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_ml',
        'ML Dashboard',
        new moodle_url('/local/security_dashboard/ml_dashboard.php'),
        'moodle/site:config'
    ));
    
    // Add Phase 2: Payload Management page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_payload_mgmt',
        '🚀 Phase 2: Payload Management',
        new moodle_url('/local/security_dashboard/payload_management.php'),
        'moodle/site:config'
    ));
    
    // Add Advanced Payload Manager UI
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_payload_manager_ui',
        '⚙️ Payload Manager (Advanced)',
        new moodle_url('/local/security_dashboard/payload_manager_ui.php'),
        'moodle/site:config'
    ));
    
    // Add Settings page at the end
    $settingspage = new admin_settingpage('local_security_dashboard_settings', 
        'Settings');

    // Proxy service URL
    $settingspage->add(new admin_setting_configtext(
        'local_security_dashboard/proxy_url',
        get_string('proxy_url', 'local_security_dashboard'),
        get_string('proxy_url_desc', 'local_security_dashboard'),
        'http://localhost:8999',
        PARAM_URL
    ));

    // CVSS engine URL
    $settingspage->add(new admin_setting_configtext(
        'local_security_dashboard/cvss_url',
        get_string('cvss_url', 'local_security_dashboard'),
        get_string('cvss_url_desc', 'local_security_dashboard'),
        'http://localhost:8001',
        PARAM_URL
    ));
    
    // Scheduled scan paths
    $settingspage->add(new admin_setting_configtextarea(
        'local_security_dashboard/scheduled_scan_paths',
        get_string('scheduled_scan_paths', 'local_security_dashboard'),
        get_string('scheduled_scan_paths_desc', 'local_security_dashboard'),
        '/login/index.php',
        PARAM_TEXT
    ));
    
    // Database path for vulnerability map - DISABLED (requires external SQLite setup)
    // $settingspage->add(new admin_setting_configtext(
    //     'local_security_dashboard/db_path',
    //     'SQLite Database Path',
    //     'Full path to moodlesec.db file (e.g., /root/TA/adaptive-moodle-security/MoodleSec/proxy/moodlesec.db). Leave empty to auto-detect.',
    //     '',
    //     PARAM_TEXT
    // ));

    $ADMIN->add('local_security_dashboard', $settingspage);

    // Include ZAP Integration settings
    $zap_settings_file = $CFG->dirroot . '/local/security_dashboard/settings_zap.php';
    if (file_exists($zap_settings_file)) {
        require_once($zap_settings_file);
    }
}
