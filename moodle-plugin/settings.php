<?php
/**
 * Settings for Security Dashboard plugin
 *
 * @package    local_security_dashboard
 * @copyright  2024 Your Name
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
    
    // Add Auth & API Scan page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_auth',
        'Auth & API Scan',
        new moodle_url('/local/security_dashboard/auth_scan.php'),
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
    
    // Add Trends page
    $ADMIN->add('local_security_dashboard', new admin_externalpage(
        'local_security_dashboard_trends',
        'Trends',
        new moodle_url('/local/security_dashboard/trends.php'),
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

    $ADMIN->add('local_security_dashboard', $settingspage);
}
