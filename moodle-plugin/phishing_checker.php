<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

namespace local_securityscanner;

defined('MOODLE_INTERNAL') || die();

/**
 * Phishing and HTML Injection Checker
 *
 * Integrates with ML-powered phishing detector to check user-generated
 * content for malicious content including HTML injection and phishing attempts.
 *
 * @package    local_securityscanner
 * @copyright  2024 Your Name
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class phishing_checker {

    /** @var string Proxy API URL */
    private $proxy_url;

    /** @var int Request timeout in seconds */
    private $timeout = 10;

    /**
     * Constructor
     */
    public function __construct() {
        $this->proxy_url = get_config('local_securityscanner', 'proxy_url');
        if (empty($this->proxy_url)) {
            $this->proxy_url = 'http://localhost:8999';
        }
    }

    /**
     * Check content for phishing/HTML injection
     *
     * @param string $content Content to check (comment, post, etc.)
     * @param array $context Additional context (user_id, post_id, type)
     * @return array Detection result
     */
    public function check_content($content, $context = []) {
        if (empty($content)) {
            return [
                'success' => true,
                'is_malicious' => false,
                'confidence' => 0.0,
                'threat_type' => 'none',
                'details' => [],
                'recommendation' => 'No content to check'
            ];
        }

        try {
            $url = rtrim($this->proxy_url, '/') . '/api/check-phishing';
            
            $data = [
                'content' => $content,
                'context' => $context
            ];

            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'Accept: application/json'
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);

            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($http_code === 200 && $response) {
                $result = json_decode($response, true);
                if ($result && isset($result['success']) && $result['success']) {
                    return $result;
                }
            }

            // Fallback if API fails
            return $this->fallback_check($content);

        } catch (\Exception $e) {
            debugging('Phishing checker error: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return $this->fallback_check($content);
        }
    }

    /**
     * Fallback check using basic pattern matching
     *
     * @param string $content Content to check
     * @return array Detection result
     */
    private function fallback_check($content) {
        $is_malicious = false;
        $details = [];

        // Check for dangerous HTML tags
        $dangerous_patterns = [
            '/<script/i' => 'Script tag detected',
            '/<iframe/i' => 'Iframe tag detected',
            '/<form/i' => 'Form tag detected',
            '/javascript:/i' => 'JavaScript protocol detected',
            '/on\w+\s*=/i' => 'Event handler detected'
        ];

        foreach ($dangerous_patterns as $pattern => $message) {
            if (preg_match($pattern, $content)) {
                $is_malicious = true;
                $details[] = $message;
            }
        }

        return [
            'success' => true,
            'is_malicious' => $is_malicious,
            'confidence' => $is_malicious ? 0.7 : 0.0,
            'threat_type' => $is_malicious ? 'html_injection' : 'none',
            'details' => $details,
            'recommendation' => $is_malicious ? 
                'Remove HTML tags and sanitize input' : 
                'Content appears safe',
            'fallback' => true
        ];
    }

    /**
     * Check forum post for malicious content
     *
     * @param object $post Forum post object
     * @return array Detection result
     */
    public function check_forum_post($post) {
        $context = [
            'user_id' => $post->userid ?? 0,
            'post_id' => $post->id ?? 0,
            'type' => 'forum_post'
        ];

        return $this->check_content($post->message ?? '', $context);
    }

    /**
     * Check comment for malicious content
     *
     * @param object $comment Comment object
     * @return array Detection result
     */
    public function check_comment($comment) {
        $context = [
            'user_id' => $comment->userid ?? 0,
            'comment_id' => $comment->id ?? 0,
            'type' => 'comment'
        ];

        return $this->check_content($comment->content ?? '', $context);
    }

    /**
     * Sanitize malicious content
     *
     * @param string $content Content to sanitize
     * @return string Sanitized content
     */
    public function sanitize_content($content) {
        // Remove all HTML tags
        $content = strip_tags($content);
        
        // Remove JavaScript
        $content = preg_replace('/javascript:/i', '', $content);
        
        // Remove event handlers
        $content = preg_replace('/on\w+\s*=/i', '', $content);
        
        return $content;
    }
}
