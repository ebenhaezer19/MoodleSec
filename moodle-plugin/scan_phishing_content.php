<?php
/**
 * MoodleSec - Phishing Content Scanner
 * Scans user-generated content (bio, comments) for phishing attempts
 * 
 * @package    local_securityscanner
 * @copyright  2025 MoodleSec
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/lib.php');

// Check admin access
require_login();
require_capability('moodle/site:config', context_system::instance());

admin_externalpage_setup('local_securityscanner_phishing');

$PAGE->set_url(new moodle_url('/local/securityscanner/scan_phishing_content.php'));
$PAGE->set_title(get_string('phishing_scanner', 'local_securityscanner'));
$PAGE->set_heading(get_string('phishing_scanner', 'local_securityscanner'));

// Get proxy service URL from config
$proxy_url = get_config('local_securityscanner', 'proxy_url') ?: 'http://localhost:8999';

/**
 * Scan user profiles for phishing
 * 
 * @return array Scan results
 */
function scan_user_profiles_phishing($proxy_url) {
    global $DB;
    
    // Get users with custom bio/description
    $sql = "SELECT id, username, firstname, lastname, description
            FROM {user}
            WHERE deleted = 0 
            AND suspended = 0
            AND description IS NOT NULL
            AND description != ''
            LIMIT 1000"; // Scan max 1000 users per run
    
    $users = $DB->get_records_sql($sql);
    
    $results = [];
    $suspicious_count = 0;
    
    foreach ($users as $user) {
        // Skip if no description
        if (empty(trim($user->description))) {
            continue;
        }
        
        // Call phishing detection API
        $scan_result = call_phishing_api(
            $proxy_url,
            'profile',
            $user->id,
            $user->description
        );
        
        if ($scan_result && $scan_result['findings_count'] > 0) {
            $results[] = [
                'user_id' => $user->id,
                'username' => $user->username,
                'fullname' => fullname($user),
                'findings_count' => $scan_result['findings_count'],
                'max_risk_score' => $scan_result['max_risk_score'],
                'findings' => $scan_result['findings']
            ];
            $suspicious_count++;
        }
    }
    
    return [
        'total_scanned' => count($users),
        'suspicious_count' => $suspicious_count,
        'results' => $results
    ];
}

/**
 * Scan forum posts for phishing
 * 
 * @return array Scan results
 */
function scan_forum_posts_phishing($proxy_url) {
    global $DB;
    
    // Get recent forum posts (last 30 days)
    $timeago = time() - (30 * 24 * 60 * 60);
    
    $sql = "SELECT fp.id, fp.userid, fp.message, fp.created,
                   u.username, u.firstname, u.lastname
            FROM {forum_posts} fp
            JOIN {user} u ON fp.userid = u.id
            WHERE fp.created > :timeago
            AND fp.message IS NOT NULL
            ORDER BY fp.created DESC
            LIMIT 500"; // Scan max 500 posts per run
    
    $posts = $DB->get_records_sql($sql, ['timeago' => $timeago]);
    
    $results = [];
    $suspicious_count = 0;
    
    foreach ($posts as $post) {
        // Call phishing detection API
        $scan_result = call_phishing_api(
            $proxy_url,
            'comment',
            $post->id,
            $post->message,
            'forum_post'
        );
        
        if ($scan_result && $scan_result['findings_count'] > 0) {
            $results[] = [
                'post_id' => $post->id,
                'user_id' => $post->userid,
                'username' => $post->username,
                'fullname' => fullname($post),
                'created' => userdate($post->created),
                'findings_count' => $scan_result['findings_count'],
                'max_risk_score' => $scan_result['max_risk_score'],
                'findings' => $scan_result['findings']
            ];
            $suspicious_count++;
        }
    }
    
    return [
        'total_scanned' => count($posts),
        'suspicious_count' => $suspicious_count,
        'results' => $results
    ];
}

/**
 * Scan comments for phishing
 * 
 * @return array Scan results
 */
function scan_comments_phishing($proxy_url) {
    global $DB;
    
    // Get recent comments (last 30 days)
    $timeago = time() - (30 * 24 * 60 * 60);
    
    $sql = "SELECT c.id, c.userid, c.content, c.timecreated,
                   u.username, u.firstname, u.lastname
            FROM {comments} c
            JOIN {user} u ON c.userid = u.id
            WHERE c.timecreated > :timeago
            AND c.content IS NOT NULL
            ORDER BY c.timecreated DESC
            LIMIT 500"; // Scan max 500 comments per run
    
    $comments = $DB->get_records_sql($sql, ['timeago' => $timeago]);
    
    $results = [];
    $suspicious_count = 0;
    
    foreach ($comments as $comment) {
        // Call phishing detection API
        $scan_result = call_phishing_api(
            $proxy_url,
            'comment',
            $comment->id,
            $comment->content,
            'comment'
        );
        
        if ($scan_result && $scan_result['findings_count'] > 0) {
            $results[] = [
                'comment_id' => $comment->id,
                'user_id' => $comment->userid,
                'username' => $comment->username,
                'fullname' => fullname($comment),
                'created' => userdate($comment->timecreated),
                'findings_count' => $scan_result['findings_count'],
                'max_risk_score' => $scan_result['max_risk_score'],
                'findings' => $scan_result['findings']
            ];
            $suspicious_count++;
        }
    }
    
    return [
        'total_scanned' => count($comments),
        'suspicious_count' => $suspicious_count,
        'results' => $results
    ];
}

/**
 * Call phishing detection API
 */
function call_phishing_api($proxy_url, $type, $id, $content, $context = null) {
    $endpoint = ($type === 'profile') 
        ? '/phishing/scan/profile' 
        : '/phishing/scan/comment';
    
    $data = [
        ($type === 'profile' ? 'user_id' : 'comment_id') => $id,
        ($type === 'profile' ? 'bio_content' : 'comment_content') => $content
    ];
    
    if ($context) {
        $data['context'] = $context;
    }
    
    $ch = curl_init($proxy_url . $endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 200 && $response) {
        return json_decode($response, true);
    }
    
    return null;
}

// Handle scan request
$scan_type = optional_param('scan_type', '', PARAM_ALPHA);
$scan_results = null;

if ($scan_type && confirm_sesskey()) {
    switch ($scan_type) {
        case 'profiles':
            $scan_results = scan_user_profiles_phishing($proxy_url);
            break;
        case 'forums':
            $scan_results = scan_forum_posts_phishing($proxy_url);
            break;
        case 'comments':
            $scan_results = scan_comments_phishing($proxy_url);
            break;
    }
}

// Output page
echo $OUTPUT->header();

echo html_writer::tag('h2', get_string('phishing_content_scanner', 'local_securityscanner'));

echo html_writer::div(
    'This tool scans user-generated content (profile bio, forum posts, comments) for potential phishing attempts. ' .
    'It detects suspicious URLs, link text mismatches, URL shorteners, and social engineering patterns.',
    'alert alert-info'
);

// Scan buttons
echo html_writer::start_tag('div', ['class' => 'mb-3']);
echo html_writer::tag('h4', 'Select Content Type to Scan:');

$scan_buttons = [
    'profiles' => 'Scan User Profiles (Bio)',
    'forums' => 'Scan Forum Posts',
    'comments' => 'Scan Comments'
];

foreach ($scan_buttons as $type => $label) {
    $url = new moodle_url('/local/securityscanner/scan_phishing_content.php', [
        'scan_type' => $type,
        'sesskey' => sesskey()
    ]);
    echo html_writer::link(
        $url,
        $label,
        ['class' => 'btn btn-primary mr-2']
    );
}

echo html_writer::end_tag('div');

// Display scan results
if ($scan_results) {
    echo html_writer::start_tag('div', ['class' => 'scan-results mt-4']);
    
    echo html_writer::tag('h3', 'Scan Results');
    
    // Summary
    $summary_class = $scan_results['suspicious_count'] > 0 ? 'alert-warning' : 'alert-success';
    echo html_writer::div(
        html_writer::tag('strong', 'Summary:') . '<br>' .
        "Total Scanned: {$scan_results['total_scanned']}<br>" .
        "Suspicious Items: {$scan_results['suspicious_count']}",
        "alert {$summary_class}"
    );
    
    // Detailed results
    if ($scan_results['suspicious_count'] > 0) {
        echo html_writer::start_tag('table', ['class' => 'table table-striped']);
        echo html_writer::start_tag('thead');
        echo html_writer::start_tag('tr');
        echo html_writer::tag('th', 'User/ID');
        echo html_writer::tag('th', 'Risk Score');
        echo html_writer::tag('th', 'Findings');
        echo html_writer::tag('th', 'Details');
        echo html_writer::end_tag('tr');
        echo html_writer::end_tag('thead');
        
        echo html_writer::start_tag('tbody');
        foreach ($scan_results['results'] as $result) {
            echo html_writer::start_tag('tr');
            
            // User info
            $user_info = isset($result['username']) 
                ? "{$result['fullname']} ({$result['username']})"
                : "ID: {$result['user_id']}";
            echo html_writer::tag('td', $user_info);
            
            // Risk score with badge
            $risk = $result['max_risk_score'];
            $badge_class = 'badge-danger';
            if ($risk < 4) $badge_class = 'badge-warning';
            if ($risk < 6) $badge_class = 'badge-warning';
            
            echo html_writer::tag('td', 
                html_writer::span(number_format($risk, 1), "badge {$badge_class}")
            );
            
            // Findings count
            echo html_writer::tag('td', $result['findings_count']);
            
            // Details (collapsible)
            $details_html = '';
            foreach ($result['findings'] as $finding) {
                $details_html .= html_writer::tag('strong', $finding['severity']) . ': ';
                $details_html .= html_writer::tag('small', implode(', ', array_slice($finding['indicators'], 0, 2)));
                $details_html .= html_writer::empty_tag('br');
                if (!empty($finding['suspicious_url'])) {
                    $details_html .= html_writer::tag('code', substr($finding['suspicious_url'], 0, 50) . '...');
                    $details_html .= html_writer::empty_tag('br');
                }
            }
            echo html_writer::tag('td', $details_html, ['style' => 'font-size: 0.9em;']);
            
            echo html_writer::end_tag('tr');
        }
        echo html_writer::end_tag('tbody');
        echo html_writer::end_tag('table');
    } else {
        echo html_writer::div(
            html_writer::tag('p', '✓ No suspicious content detected.', ['class' => 'text-success']),
            'alert alert-success'
        );
    }
    
    echo html_writer::end_tag('div');
}

echo $OUTPUT->footer();
