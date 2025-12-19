# Phishing Detection Integration Guide

## Overview

This guide explains how to integrate the ML-powered phishing detector into Moodle to automatically check user-generated content for malicious content.

## Architecture

```
Moodle Plugin → HTTP API → ML Proxy → Phishing Detector → Result
```

## API Endpoint

**URL:** `http://localhost:8999/api/check-phishing`

**Method:** POST

**Request Body:**
```json
{
  "content": "text to analyze",
  "context": {
    "user_id": 123,
    "post_id": 456,
    "type": "comment"
  }
}
```

**Response:**
```json
{
  "success": true,
  "is_malicious": false,
  "confidence": 0.85,
  "threat_type": "html_injection, phishing_url",
  "details": [
    "HTML injection pattern detected",
    "Suspicious URL detected"
  ],
  "recommendation": "Remove content and investigate user account"
}
```

## Integration Methods

### Method 1: Event Observer (Recommended)

Monitor Moodle events and check content automatically.

**File:** `db/events.php`

```php
$observers = [
    [
        'eventname' => '\mod_forum\event\post_created',
        'callback' => '\local_securityscanner\observer::check_forum_post',
    ],
    [
        'eventname' => '\core\event\comment_created',
        'callback' => '\local_securityscanner\observer::check_comment',
    ],
];
```

**File:** `classes/observer.php`

```php
namespace local_securityscanner;

class observer {
    
    public static function check_forum_post(\mod_forum\event\post_created $event) {
        global $DB;
        
        $post = $DB->get_record('forum_posts', ['id' => $event->objectid]);
        if (!$post) {
            return;
        }
        
        $checker = new phishing_checker();
        $result = $checker->check_forum_post($post);
        
        if ($result['is_malicious'] && $result['confidence'] > 0.7) {
            // High confidence malicious content
            self::handle_malicious_content($post, $result);
        }
    }
    
    public static function check_comment(\core\event\comment_created $event) {
        global $DB;
        
        $comment = $DB->get_record('comments', ['id' => $event->objectid]);
        if (!$comment) {
            return;
        }
        
        $checker = new phishing_checker();
        $result = $checker->check_comment($comment);
        
        if ($result['is_malicious'] && $result['confidence'] > 0.7) {
            self::handle_malicious_content($comment, $result);
        }
    }
    
    private static function handle_malicious_content($object, $result) {
        global $DB;
        
        // Option 1: Delete immediately
        // $DB->delete_records('forum_posts', ['id' => $object->id]);
        
        // Option 2: Flag for review
        $DB->set_field('forum_posts', 'flagged', 1, ['id' => $object->id]);
        
        // Option 3: Notify admin
        $message = sprintf(
            "Malicious content detected\nType: %s\nConfidence: %.1f%%\nDetails: %s",
            $result['threat_type'],
            $result['confidence'] * 100,
            implode(', ', $result['details'])
        );
        
        // Send notification to admin
        self::notify_admin($message);
        
        // Log the incident
        \local_securityscanner\logger::log_phishing_attempt($object, $result);
    }
    
    private static function notify_admin($message) {
        // Implementation depends on your notification system
        // Could use Moodle messaging, email, or Slack
    }
}
```

### Method 2: Form Validation

Check content before saving.

**Example for custom form:**

```php
class my_form extends \moodleform {
    
    public function validation($data, $files) {
        $errors = parent::validation($data, $files);
        
        if (!empty($data['content'])) {
            $checker = new \local_securityscanner\phishing_checker();
            $result = $checker->check_content($data['content']);
            
            if ($result['is_malicious'] && $result['confidence'] > 0.7) {
                $errors['content'] = sprintf(
                    'Malicious content detected: %s. %s',
                    $result['threat_type'],
                    $result['recommendation']
                );
            }
        }
        
        return $errors;
    }
}
```

### Method 3: Manual Check

Check existing content in bulk.

```php
// Check all forum posts
$posts = $DB->get_records('forum_posts');
$checker = new \local_securityscanner\phishing_checker();

foreach ($posts as $post) {
    $result = $checker->check_forum_post($post);
    
    if ($result['is_malicious']) {
        echo "Malicious post found: {$post->id}\n";
        echo "Threat: {$result['threat_type']}\n";
        echo "Confidence: " . ($result['confidence'] * 100) . "%\n";
    }
}
```

## Configuration

**Admin Settings:**

1. Navigate to: Site administration → Plugins → Local plugins → Security Scanner
2. Set Proxy URL: `http://localhost:8999`
3. Enable phishing detection
4. Configure action on detection:
   - Delete immediately
   - Flag for review
   - Notify admin only

## Testing

**Test the integration:**

```bash
# 1. Start the proxy
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
python app.py

# 2. Test API endpoint
curl -X POST http://localhost:8999/api/check-phishing \
  -H "Content-Type: application/json" \
  -d '{
    "content": "<script>alert(\"XSS\")</script>",
    "context": {"type": "test"}
  }'

# Expected response:
# {
#   "success": true,
#   "is_malicious": true,
#   "confidence": 0.4,
#   "threat_type": "html_injection",
#   ...
# }
```

**Test in Moodle:**

1. Create a forum post with malicious content
2. Check Moodle logs for detection
3. Verify admin notification
4. Confirm content is flagged/deleted

## Performance Considerations

**Caching:**
```php
// Cache results for 1 hour
$cache = \cache::make('local_securityscanner', 'phishing_results');
$cache_key = md5($content);

if ($cached = $cache->get($cache_key)) {
    return $cached;
}

$result = $checker->check_content($content);
$cache->set($cache_key, $result);
```

**Async Processing:**
```php
// Queue for background processing
$task = new \local_securityscanner\task\check_phishing_task();
$task->set_custom_data([
    'content' => $content,
    'post_id' => $post->id
]);
\core\task\manager::queue_adhoc_task($task);
```

## Security Best Practices

1. **Always sanitize** detected malicious content before displaying
2. **Log all detections** for audit trail
3. **Rate limit** API calls to prevent abuse
4. **Fallback** to basic checks if API is unavailable
5. **Notify users** when their content is flagged (optional)

## Troubleshooting

**API not responding:**
- Check proxy is running: `curl http://localhost:8999/health`
- Check firewall settings
- Verify proxy URL in config

**False positives:**
- Adjust confidence threshold (default: 0.7)
- Review detection details
- Provide feedback to improve ML model

**Performance issues:**
- Enable caching
- Use async processing
- Increase API timeout

## Example: Complete Integration

```php
// In your Moodle code
use local_securityscanner\phishing_checker;

// Check content
$checker = new phishing_checker();
$result = $checker->check_content($user_input, [
    'user_id' => $USER->id,
    'type' => 'forum_post'
]);

// Handle result
if ($result['is_malicious'] && $result['confidence'] > 0.7) {
    // High confidence - block immediately
    throw new moodle_exception(
        'maliciouscontent',
        'local_securityscanner',
        '',
        $result['threat_type']
    );
} else if ($result['is_malicious'] && $result['confidence'] > 0.4) {
    // Medium confidence - flag for review
    flag_for_review($user_input, $result);
    show_warning($USER, $result['recommendation']);
}
```

## Support

For issues or questions:
- Check logs: `proxy/logs/`
- Test endpoint: `http://localhost:8999/api/check-phishing`
- Review documentation: `PHISHING_INTEGRATION.md`
