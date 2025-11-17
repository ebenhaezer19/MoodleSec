<?php
/**
 * Upgrade script for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  2024 Your Name
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Execute upgrade from the given old version
 *
 * @param int $oldversion
 * @return bool
 */
function xmldb_local_security_dashboard_upgrade($oldversion) {
    global $DB;
    $dbman = $DB->get_manager();

    if ($oldversion < 2024111601) {
        // Add any future upgrade steps here
        
        upgrade_plugin_savepoint(true, 2024111601, 'local', 'security_dashboard');
    }

    return true;
}
