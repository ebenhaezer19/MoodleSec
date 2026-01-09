"""
MoodleSec - Phishing Detection REST API
Provides endpoints for scanning Moodle user content for phishing attempts
"""

from flask import Blueprint, request, jsonify
from typing import Dict, List
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.phishing_detector import PhishingDetector

# Create Blueprint
phishing_api = Blueprint('phishing_api', __name__)

# Global detector instance (will be initialized with config)
detector: PhishingDetector = None

def init_phishing_detector(moodle_domain: str):
    """Initialize phishing detector with Moodle domain"""
    global detector
    detector = PhishingDetector(moodle_base_domain=moodle_domain)

@phishing_api.route('/phishing/scan/profile', methods=['POST'])
def scan_user_profile():
    """
    Scan user profile bio for phishing
    
    Request Body:
    {
        "user_id": 123,
        "bio_content": "User bio HTML/text"
    }
    
    Response:
    {
        "success": true,
        "user_id": 123,
        "scan_type": "profile_bio",
        "findings_count": 2,
        "max_risk_score": 7.0,
        "findings": [...]
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'user_id' not in data or 'bio_content' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: user_id, bio_content'
            }), 400
        
        user_id = data['user_id']
        bio_content = data['bio_content']
        
        # Perform scan
        result = detector.scan_user_profile(user_id, bio_content)
        result['success'] = True
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@phishing_api.route('/phishing/scan/comment', methods=['POST'])
def scan_comment():
    """
    Scan comment/forum post for phishing
    
    Request Body:
    {
        "comment_id": 456,
        "comment_content": "Comment HTML/text",
        "context": "comment" | "forum_post" | "assignment_feedback"
    }
    
    Response:
    {
        "success": true,
        "comment_id": 456,
        "scan_type": "comment",
        "findings_count": 1,
        "max_risk_score": 5.0,
        "findings": [...]
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'comment_id' not in data or 'comment_content' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: comment_id, comment_content'
            }), 400
        
        comment_id = data['comment_id']
        comment_content = data['comment_content']
        context = data.get('context', 'comment')
        
        # Perform scan
        result = detector.scan_comment(comment_id, comment_content, context)
        result['success'] = True
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@phishing_api.route('/phishing/scan/batch', methods=['POST'])
def scan_batch_content():
    """
    Scan multiple content items in batch
    
    Request Body:
    {
        "items": [
            {
                "type": "profile" | "comment",
                "id": 123,
                "content": "...",
                "context": "..."
            }
        ]
    }
    
    Response:
    {
        "success": true,
        "total_items": 10,
        "suspicious_items": 3,
        "results": [...]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'items' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: items'
            }), 400
        
        items = data['items']
        results = []
        suspicious_count = 0
        
        for item in items:
            item_type = item.get('type')
            item_id = item.get('id')
            content = item.get('content')
            context = item.get('context', 'unknown')
            
            if not all([item_type, item_id, content]):
                results.append({
                    'id': item_id,
                    'error': 'Missing required fields'
                })
                continue
            
            # Scan based on type
            if item_type == 'profile':
                result = detector.scan_user_profile(item_id, content)
            elif item_type == 'comment':
                result = detector.scan_comment(item_id, content, context)
            else:
                results.append({
                    'id': item_id,
                    'error': f'Unknown type: {item_type}'
                })
                continue
            
            results.append(result)
            
            if result['findings_count'] > 0:
                suspicious_count += 1
        
        return jsonify({
            'success': True,
            'total_items': len(items),
            'suspicious_items': suspicious_count,
            'results': results
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@phishing_api.route('/phishing/stats', methods=['GET'])
def get_detection_stats():
    """
    Get phishing detection statistics
    
    Response:
    {
        "success": true,
        "moodle_domain": "university.ac.id",
        "detector_ready": true,
        "detection_methods": [...]
    }
    """
    try:
        return jsonify({
            'success': True,
            'moodle_domain': detector.moodle_domain,
            'detector_ready': detector is not None,
            'detection_methods': [
                'URL Shortener Detection',
                'IP-based URL Detection',
                'Suspicious TLD Analysis',
                'Domain Spoofing (Typosquatting)',
                'Link Text vs URL Mismatch',
                'URL Obfuscation Detection',
                'Homograph Attack Detection',
                'Social Engineering Keyword Analysis'
            ],
            'suspicious_tlds': detector.SUSPICIOUS_TLDS,
            'url_shorteners': detector.URL_SHORTENERS
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
