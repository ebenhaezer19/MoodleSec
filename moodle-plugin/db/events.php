<?php
/**
 * Event observers configuration
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$observers = [
    [
        'eventname' => '\core\event\user_loggedin',
        'callback' => '\local_security_dashboard\login_observer::user_loggedin',
        'includefile' => null,
        'internal' => false,
        'priority' => 200,
    ],
    [
        'eventname' => '\core\event\user_login_failed',
        'callback' => '\local_security_dashboard\login_observer::user_login_failed',
        'includefile' => null,
        'internal' => false,
        'priority' => 200,
    ],
];
