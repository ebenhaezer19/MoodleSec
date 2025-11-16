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
}
