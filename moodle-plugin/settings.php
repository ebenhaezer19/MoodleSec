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
    $settings = new admin_settingpage('local_security_dashboard', get_string('pluginname', 'local_security_dashboard'));

    // Proxy service URL
    $settings->add(new admin_setting_configtext(
        'local_security_dashboard/proxy_url',
        get_string('proxy_url', 'local_security_dashboard'),
        get_string('proxy_url_desc', 'local_security_dashboard'),
        'http://localhost:8999',
        PARAM_URL
    ));

    // CVSS engine URL
    $settings->add(new admin_setting_configtext(
        'local_security_dashboard/cvss_url',
        get_string('cvss_url', 'local_security_dashboard'),
        get_string('cvss_url_desc', 'local_security_dashboard'),
        'http://localhost:8001',
        PARAM_URL
    ));

    $ADMIN->add('localplugins', $settings);
    
    // Add external pages
    $ADMIN->add('localplugins', new admin_category('local_security_dashboard_cat', 
        get_string('pluginname', 'local_security_dashboard')));
    
    $ADMIN->add('local_security_dashboard_cat', new admin_externalpage(
        'local_security_dashboard_dashboard',
        'Dashboard',
        new moodle_url('/local/security_dashboard/index.php')
    ));
    
    $ADMIN->add('local_security_dashboard_cat', new admin_externalpage(
        'local_security_dashboard_auth',
        'Auth & API Scan',
        new moodle_url('/local/security_dashboard/auth_scan.php')
    ));
    
    $ADMIN->add('local_security_dashboard_cat', new admin_externalpage(
        'local_security_dashboard_reports',
        'Reports',
        new moodle_url('/local/security_dashboard/reports.php')
    ));
    
    $ADMIN->add('local_security_dashboard_cat', new admin_externalpage(
        'local_security_dashboard_scheduler',
        'Scheduler',
        new moodle_url('/local/security_dashboard/scheduler.php')
    ));
    
    $ADMIN->add('local_security_dashboard_cat', new admin_externalpage(
        'local_security_dashboard_trends',
        'Trends',
        new moodle_url('/local/security_dashboard/trends.php')
    ));
}
