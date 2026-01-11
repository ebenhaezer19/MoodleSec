<?php
/**
 * Upgrade script for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  Krisopras & Nathanael 2025
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

    // Add phishing findings table
    if ($oldversion < 2026011100) {
        
        // Define table local_security_phishing to be created.
        $table = new xmldb_table('local_security_phishing');

        // Adding fields to table local_security_phishing.
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('content_type', XMLDB_TYPE_CHAR, '50', null, XMLDB_NOTNULL, null, null);
        $table->add_field('content_id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('user_id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('risk_level', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, null);
        $table->add_field('risk_score', XMLDB_TYPE_NUMBER, '4, 2', null, XMLDB_NOTNULL, null, null);
        $table->add_field('suspicious_url', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('indicators', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('content_preview', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('recommendation', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('status', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, 'open');
        $table->add_field('notified', XMLDB_TYPE_INTEGER, '1', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('detected_by', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('resolved_by', XMLDB_TYPE_INTEGER, '10', null, null, null, null);
        $table->add_field('resolved_at', XMLDB_TYPE_INTEGER, '10', null, null, null, null);
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timemodified', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);

        // Adding keys to table local_security_phishing.
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);
        $table->add_key('user_id', XMLDB_KEY_FOREIGN, ['user_id'], 'user', ['id']);
        $table->add_key('detected_by', XMLDB_KEY_FOREIGN, ['detected_by'], 'user', ['id']);
        $table->add_key('resolved_by', XMLDB_KEY_FOREIGN, ['resolved_by'], 'user', ['id']);

        // Adding indexes to table local_security_phishing.
        $table->add_index('content_type', XMLDB_INDEX_NOTUNIQUE, ['content_type']);
        $table->add_index('risk_level', XMLDB_INDEX_NOTUNIQUE, ['risk_level']);
        $table->add_index('status', XMLDB_INDEX_NOTUNIQUE, ['status']);
        $table->add_index('timecreated', XMLDB_INDEX_NOTUNIQUE, ['timecreated']);
        $table->add_index('content_lookup', XMLDB_INDEX_NOTUNIQUE, ['content_type', 'content_id']);

        // Conditionally launch create table for local_security_phishing.
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }

        // Security_dashboard savepoint reached.
        upgrade_plugin_savepoint(true, 2026011100, 'local', 'security_dashboard');
    }

    // Add content_url field and whitelist table
    if ($oldversion < 2026011101) {
        
        // Add content_url field to local_security_phishing
        $table = new xmldb_table('local_security_phishing');
        $field = new xmldb_field('content_url', XMLDB_TYPE_TEXT, null, null, null, null, null, 'content_id');
        
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }
        
        // Create whitelist table
        $table = new xmldb_table('local_security_phishing_whitelist');
        
        // Adding fields
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('whitelist_type', XMLDB_TYPE_CHAR, '20', null, XMLDB_NOTNULL, null, null);
        $table->add_field('whitelist_value', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('reason', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('source', XMLDB_TYPE_CHAR, '50', null, XMLDB_NOTNULL, null, null);
        $table->add_field('created_by', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timemodified', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        
        // Adding keys
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);
        $table->add_key('created_by', XMLDB_KEY_FOREIGN, ['created_by'], 'user', ['id']);
        
        // Adding indexes
        $table->add_index('whitelist_type', XMLDB_INDEX_NOTUNIQUE, ['whitelist_type']);
        
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }
        
        upgrade_plugin_savepoint(true, 2026011101, 'local', 'security_dashboard');
    }

    // Add login monitoring tables
    if ($oldversion < 2026011200) {
        
        // Define table local_security_login_log
        $table = new xmldb_table('local_security_login_log');
        
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('userid', XMLDB_TYPE_INTEGER, '10', null, null, null, null);
        $table->add_field('username', XMLDB_TYPE_CHAR, '100', null, null, null, null);
        $table->add_field('success', XMLDB_TYPE_INTEGER, '1', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('ip_address', XMLDB_TYPE_CHAR, '45', null, XMLDB_NOTNULL, null, null);
        $table->add_field('user_agent', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('country', XMLDB_TYPE_CHAR, '100', null, null, null, null);
        $table->add_field('city', XMLDB_TYPE_CHAR, '100', null, null, null, null);
        $table->add_field('region', XMLDB_TYPE_CHAR, '100', null, null, null, null);
        $table->add_field('isp', XMLDB_TYPE_CHAR, '255', null, null, null, null);
        $table->add_field('latitude', XMLDB_TYPE_NUMBER, '10, 6', null, null, null, null);
        $table->add_field('longitude', XMLDB_TYPE_NUMBER, '10, 6', null, null, null, null);
        $table->add_field('is_suspicious', XMLDB_TYPE_INTEGER, '1', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('risk_score', XMLDB_TYPE_INTEGER, '3', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('fail_reason', XMLDB_TYPE_CHAR, '255', null, null, null, null);
        $table->add_field('session_id', XMLDB_TYPE_CHAR, '100', null, null, null, null);
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);
        $table->add_key('userid', XMLDB_KEY_FOREIGN, ['userid'], 'user', ['id']);
        
        $table->add_index('success', XMLDB_INDEX_NOTUNIQUE, ['success']);
        $table->add_index('ip_address', XMLDB_INDEX_NOTUNIQUE, ['ip_address']);
        $table->add_index('timecreated', XMLDB_INDEX_NOTUNIQUE, ['timecreated']);
        $table->add_index('is_suspicious', XMLDB_INDEX_NOTUNIQUE, ['is_suspicious']);
        
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }
        
        // Define table local_security_ip_blocklist
        $table = new xmldb_table('local_security_ip_blocklist');
        
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('ip_address', XMLDB_TYPE_CHAR, '45', null, XMLDB_NOTNULL, null, null);
        $table->add_field('reason', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('block_type', XMLDB_TYPE_CHAR, '50', null, XMLDB_NOTNULL, null, null);
        $table->add_field('fail_count', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('first_seen', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('last_seen', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('blocked_by', XMLDB_TYPE_INTEGER, '10', null, null, null, null);
        $table->add_field('expires', XMLDB_TYPE_INTEGER, '10', null, null, null, null);
        $table->add_field('is_active', XMLDB_TYPE_INTEGER, '1', null, XMLDB_NOTNULL, null, '1');
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timemodified', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);
        $table->add_key('blocked_by', XMLDB_KEY_FOREIGN, ['blocked_by'], 'user', ['id']);
        
        $table->add_index('ip_address_unique', XMLDB_INDEX_UNIQUE, ['ip_address']);
        $table->add_index('is_active', XMLDB_INDEX_NOTUNIQUE, ['is_active']);
        
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }
        
        upgrade_plugin_savepoint(true, 2026011200, 'local', 'security_dashboard');
    }

    return true;
}
