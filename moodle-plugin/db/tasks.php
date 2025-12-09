<?php
/**
 * Task definitions for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$tasks = [
    [
        'classname' => 'local_security_dashboard\task\scan_task',
        'blocking' => 0,
        'minute' => '0',
        'hour' => '2',      // Run at 2 AM
        'day' => '*',
        'dayofweek' => '*',
        'month' => '*'
    ],
];
