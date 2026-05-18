<?php
define('CLI_SCRIPT', true);
require('C:/Users/natha/CIT/MoodleWindowsInstaller-latest-38/server/moodle/config.php');

if ($DB->get_manager()->table_exists('local_security_phish_wlist')) {
    echo "✓ SUCCESS: Table 'local_security_phish_wlist' exists!\n";
    
    // Get table columns
    $columns = $DB->get_columns('local_security_phish_wlist');
    echo "\nColumns:\n";
    foreach ($columns as $column) {
        echo "  - {$column->name} ({$column->type})\n";
    }
} else {
    echo "✗ ERROR: Table 'local_security_phish_wlist' not found!\n";
}
