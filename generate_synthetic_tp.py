#!/usr/bin/env python3
"""
Generate Synthetic TP Examples for Missing Vulnerability Categories

Adds 40 realistic True Positive examples to training dataset:
- SQL Injection (10)
- Cross-site Scripting/XSS (10) 
- CSRF (5)
- Authentication Bypass (5)
- Business Logic Flaws (5)
- Path Traversal (5)

These fill gaps in 1308 existing TP examples to improve model generalization.
"""

import json
from pathlib import Path
from datetime import datetime
import random

# Synthetic TP findings based on OWASP Top 10 + Common Real Vulns
SYNTHETIC_TP = [
    # SQL Injection variants (10)
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'SQL injection vulnerability in user login parameter',
        'evidence': "UNION-based SQL injection detected: payload 'OR 1=1-- resulted in database error disclosure and unauthorized data access",
        'url': 'http://localhost/login.php?username=admin',
        'cvss_score': 9.8,
        'risk_score': 9.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.98,
        'reason': 'Evidence-based: actual SQL error message in response indicates real injection',
        'strategy': 'Evidence detected in response - database error patterns confirm vulnerability'
    },
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'Time-based blind SQL injection in product search',
        'evidence': "Blind SQL injection via SLEEP() function: response time delay (5s) on payload 'OR SLEEP(5)-- confirms backend SQL execution",
        'url': 'http://localhost/search.php?q=product',
        'cvss_score': 9.5,
        'risk_score': 9.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: timing side-channel proves SQL query manipulation',
        'strategy': 'Time-based inference with measurable response delay proves SQL execution'
    },
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'Stacked queries SQL injection in database update endpoint',
        'evidence': "Multiple SQL statements executed in single request: DROP TABLE attempted in error message, indicating stacked query vulnerability",
        'url': 'http://localhost/api/user/update.php?id=1',
        'cvss_score': 10.0,
        'risk_score': 9.8,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.99,
        'reason': 'Evidence-based: error messages show multiple query execution capability',
        'strategy': 'Direct evidence of stacked query execution in error responses'
    },
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'Second-order SQL injection in user profile display',
        'evidence': "Injected payload stored in database and executed on profile view: <script> tag from injected SQL executed in browser context",
        'url': 'http://localhost/profile.php?user_id=123',
        'cvss_score': 9.3,
        'risk_score': 9.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: script execution from database-sourced content',
        'strategy': 'Payload execution detected in stored data context'
    },
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'SQL injection in ORDER BY clause allowing column enumeration',
        'evidence': "Column enumeration via ORDER BY injection: SELECT * FROM users ORDER BY 1 successful, ORDER BY 99 causes error, indicating column count discovery",
        'url': 'http://localhost/list.php?sort=name',
        'cvss_score': 8.8,
        'risk_score': 8.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: error behavior pattern proves SQL injection',
        'strategy': 'Order by injection behavior matches known SQL error patterns'
    },
    {
        'severity': 'critical',
        'category': 'SQL Injection',
        'description': 'Union-based SQLi with database enumeration (information_schema)',
        'evidence': "UNION SELECT successfully retrieved table names from information_schema.tables, proving unauthorized database metadata access",
        'url': 'http://localhost/products.php?id=1',
        'cvss_score': 9.6,
        'risk_score': 9.4,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.98,
        'reason': 'Evidence-based: actual database structure enumeration confirmed',
        'strategy': 'Evidence shows successful UNION query with metadata retrieval'
    },
    {
        'severity': 'high',
        'category': 'SQL Injection',
        'description': 'Boolean-based SQL injection in login form (authentication bypass)',
        'evidence': "Boolean-based injection: authentic_user AND 1=1 logs in successfully, authentic_user AND 1=2 fails, proving condition manipulation",
        'url': 'http://localhost/admin/login.php',
        'cvss_score': 8.2,
        'risk_score': 8.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: boolean logic manipulation confirmed through observable behavior',
        'strategy': 'Behavior-based SQL injection with authentication bypass capability'
    },
    {
        'severity': 'high',
        'category': 'SQL Injection',
        'description': 'SQL injection in database export feature allowing file write',
        'evidence': "INTO OUTFILE injection detected: SQL query writing malicious PHP code to web-accessible directory",
        'url': 'http://localhost/export.php?format=csv',
        'cvss_score': 9.1,
        'risk_score': 8.8,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: file write capability via SQL injection proven',
        'strategy': 'Evidence of file system write via SQL injection'
    },
    {
        'severity': 'high',
        'category': 'SQL Injection',
        'description': 'SQL injection in comment functionality with data extraction',
        'evidence': "Extracting user email addresses via UNION SELECT injection: 50+ email addresses successfully retrieved from users table",
        'url': 'http://localhost/comments.php?post_id=1',
        'cvss_score': 8.5,
        'risk_score': 8.3,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: actual sensitive data extraction confirmed',
        'strategy': 'Evidence of successful data exfiltration'
    },
    {
        'severity': 'high',
        'category': 'SQL Injection',
        'description': 'Nested SQL injection in stored procedure call parameter',
        'evidence': "Stored procedure parameter injection: sp_executesql executing injected T-SQL, creating new admin user account",
        'url': 'http://localhost/api/procedure.php?name=CreateUser',
        'cvss_score': 9.2,
        'risk_score': 9.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: account manipulation via SQL injection proven',
        'strategy': 'Evidence of privilege escalation via stored procedure injection'
    },

    # XSS variants (10)
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'Stored XSS in user profile bio field',
        'evidence': "<script>alert('XSS')</script> tag stored in database and executed in all user profile views without HTML encoding",
        'url': 'http://localhost/profile.php?user=admin',
        'cvss_score': 7.8,
        'risk_score': 7.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: JavaScript execution from user-controlled data confirmed',
        'strategy': 'Evidence of script execution in browser via stored payload'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'Reflected XSS in search results parameter',
        'evidence': "Search parameter reflected unescaped: <img src=x onerror=alert(1)> tag appears directly in HTML response without encoding",
        'url': 'http://localhost/search.php?q=test',
        'cvss_score': 7.6,
        'risk_score': 7.3,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: raw HTML injection confirmed in response',
        'strategy': 'Evidence of unencoded user input in HTML context'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'DOM-based XSS via JavaScript location manipulation',
        'evidence': "window.location parameter directly used in eval(): attacker can control JavaScript execution context via fragment identifier",
        'url': 'http://localhost/redirect.php',
        'cvss_score': 7.4,
        'risk_score': 7.1,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: JavaScript context manipulation confirmed',
        'strategy': 'Evidence of unsafe eval with user-controlled input'
    },
    {
        'severity': 'medium',
        'category': 'Cross-site Scripting',
        'description': 'XSS via SVG attribute injection in image upload',
        'evidence': "<svg onload=alert(1)> tag in uploaded SVG file executes when rendered, bypassing image upload restrictions",
        'url': 'http://localhost/upload.php',
        'cvss_score': 6.8,
        'risk_score': 6.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: SVG payload execution in browser confirmed',
        'strategy': 'Evidence of payload execution in file upload context'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'Stored XSS in comment system with markdown parsing',
        'evidence': "Markdown parser fails to sanitize JavaScript protocol: [link](javascript:alert(1)) executes on click in all comment views",
        'url': 'http://localhost/comments.php?post=123',
        'cvss_score': 7.5,
        'risk_score': 7.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: javascript: protocol execution in HTML links confirmed',
        'strategy': 'Evidence of unsafe markdown rendering'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'XSS via HTTP header injection (Referer header)',
        'evidence': "Referer header reflected in error page without encoding: <script> tag in Referer header executed in error response",
        'url': 'http://localhost/error.php',
        'cvss_score': 7.3,
        'risk_score': 7.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: HTTP header reflection confirmed',
        'strategy': 'Evidence of unencoded header value in HTML'
    },
    {
        'severity': 'medium',
        'category': 'Cross-site Scripting',
        'description': 'Mutation XSS (mXSS) via HTML5 parsing quirks',
        'evidence': "<noscript><p title=</noscript><img src=x onerror=alert(1)> exploits HTML5 parser mutation behavior",
        'url': 'http://localhost/article.php?id=1',
        'cvss_score': 6.5,
        'risk_score': 6.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.93,
        'reason': 'Evidence-based: HTML parser mutation confirmed',
        'strategy': 'Evidence of browser mutation XSS exploitation'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'Stored XSS in message board subject with insufficient sanitization',
        'evidence': "<iframe src=javascript:alert(1)> tag stored in subject field, executes in all message preview views",
        'url': 'http://localhost/board/thread.php?id=42',
        'cvss_score': 7.7,
        'risk_score': 7.4,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: iframe execution with javascript: protocol confirmed',
        'strategy': 'Evidence of unsafe HTML in stored data'
    },
    {
        'severity': 'high',
        'category': 'Cross-site Scripting',
        'description': 'XSS via CSS expression evaluation in IE legacy (if applicable)',
        'evidence': "CSS expression: width:expression(alert(1)) evaluated in IE, executing arbitrary JavaScript",
        'url': 'http://localhost/style.php?theme=dark',
        'cvss_score': 7.2,
        'risk_score': 6.9,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.92,
        'reason': 'Evidence-based: CSS expression execution confirmed',
        'strategy': 'Evidence of CSS expression evaluation'
    },

    # CSRF (5)
    {
        'severity': 'high',
        'category': 'Cross-Site Request Forgery',
        'description': 'CSRF vulnerability in user password change endpoint',
        'evidence': "POST /user/change-password accepts requests without CSRF token validation or SameSite cookie protection",  
        'url': 'http://localhost/user/change-password.php',
        'cvss_score': 7.5,
        'risk_score': 7.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: state-changing action without CSRF protection confirmed',
        'strategy': 'Evidence of missing CSRF token and SameSite attributes'
    },
    {
        'severity': 'high',
        'category': 'Cross-Site Request Forgery',
        'description': 'CSRF in fund transfer with weak validation',
        'evidence': "Transfer endpoint processes GET request: /transfer.php?to=attacker&amount=1000 executed via img src, bypasses CSRF checks",
        'url': 'http://localhost/bank/transfer.php',
        'cvss_score': 8.2,
        'risk_score': 8.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: GET-based state change with CSRF vulnerability confirmed',
        'strategy': 'Evidence of idempotent CSRF checks allowing GET requests'
    },
    {
        'severity': 'medium',
        'category': 'Cross-Site Request Forgery',
        'description': 'CSRF in profile settings modification',
        'evidence': "No Referer/Origin validation: POST /profile/update processes requests from external domains without validation",
        'url': 'http://localhost/profile/update.php',
        'cvss_score': 6.8,
        'risk_score': 6.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: missing origin validation confirmed',
        'strategy': 'Evidence of weak CSRF token validation'
    },
    {
        'severity': 'high',
        'category': 'Cross-Site Request Forgery',
        'description': 'CSRF in admin user creation via JSON POST',
        'evidence': "JSON endpoint /api/admin/create-user accepts requests without CSRF token despite state-changing operation",
        'url': 'http://localhost/api/admin/create-user',
        'cvss_score': 8.0,
        'risk_score': 7.8,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: privilege escalation via CSRF confirmed',
        'strategy': 'Evidence of CSRF on privileged operations'
    },
    {
        'severity': 'medium',
        'category': 'Cross-Site Request Forgery',
        'description': 'CSRF in email subscription change',
        'evidence': "GET request /update-subscription.php?email=attacker@evil.com processed without CSRF protection, allowing email hijacking via CSRF",
        'url': 'http://localhost/update-subscription.php',
        'cvss_score': 6.5,
        'risk_score': 6.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: email modification via CSRF confirmed',
        'strategy': 'Evidence of account hijacking via CSRF'
    },

    # Authentication Bypass (5)
    {
        'severity': 'critical',
        'category': 'Authentication Bypass',
        'description': 'Direct object reference (IDOR) allowing unauthorized admin access',
        'evidence': "User ID parameter in /admin/user.php?id=1 increment allows viewing all admin users and their data without authentication",
        'url': 'http://localhost/admin/user.php',
        'cvss_score': 9.1,
        'risk_score': 8.8,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: unauthorized admin data access confirmed',
        'strategy': 'Evidence of missing authorization checks on sensitive params'
    },
    {
        'severity': 'critical',
        'category': 'Authentication Bypass',
        'description': 'Session fixation allowing attacker to hijack user session',
        'evidence': "Application accepts pre-set session ID from attacker: attacker sends session_id=attacker_controlled, then victim's login creates admin session for attacker",
        'url': 'http://localhost/login.php',
        'cvss_score': 8.8,
        'risk_score': 8.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: session fixation vulnerability confirmed',
        'strategy': 'Evidence of session reuse after authentication'
    },
    {
        'severity': 'high',
        'category': 'Authentication Bypass',
        'description': 'JWT token signature bypass (algorithm confusion)',
        'evidence': "JWT algorithm changed from RS256 to HS256: attacker can forge tokens using shared secret, impersonating any user",
        'url': 'http://localhost/api/auth',
        'cvss_score': 8.5,
        'risk_score': 8.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: JWT signature validation bypass confirmed',
        'strategy': 'Evidence of cryptographic algorithm confusion'
    },
    {
        'severity': 'high',
        'category': 'Authentication Bypass',
        'description': 'Password reset token reuse allowing account takeover',
        'evidence': "Password reset token never invalidated after use: same token accepted multiple times for different accounts",
        'url': 'http://localhost/reset-password.php',
        'cvss_score': 8.2,
        'risk_score': 8.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: token reuse vulnerability confirmed',
        'strategy': 'Evidence of insufficient token invalidation'
    },
    {
        'severity': 'high',
        'category': 'Authentication Bypass',
        'description': 'Case-insensitive username authentication allowing privilege escalation',
        'evidence': "Login with 'ADMIN' instead of 'admin' provides admin privileges due to case-insensitive comparison with insufficient authorization",
        'url': 'http://localhost/login.php',
        'cvss_score': 7.8,
        'risk_score': 7.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: privilege escalation via case manipulation confirmed',
        'strategy': 'Evidence of case-sensitivity bypass'
    },

    # Business Logic Flaws (5)
    {
        'severity': 'high',
        'category': 'Business Logic Flaw',
        'description': 'Race condition in concurrent transaction processing',
        'evidence': "Simultaneous duplicate purchase requests both approved: race condition allows purchasing same item multiple times with single payment",
        'url': 'http://localhost/cart/checkout.php',
        'cvss_score': 7.8,
        'risk_score': 7.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: duplicate transaction processing confirmed',
        'strategy': 'Evidence of missing transaction locking'
    },
    {
        'severity': 'high',
        'category': 'Business Logic Flaw',
        'description': 'Integer overflow in price calculation allowing negative totals',
        'evidence': "Price parameter accepts large integer causing overflow: total becomes negative, resulting in credit instead of payment due",
        'url': 'http://localhost/api/order/total',
        'cvss_score': 7.5,
        'risk_score': 7.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: mathematical manipulation confirmed',
        'strategy': 'Evidence of integer bounds violation'
    },
    {
        'severity': 'medium',
        'category': 'Business Logic Flaw',
        'description': 'Discount code unlimited reuse allowing arbitrary discount application',
        'evidence': "Single-use discount code: 'WELCOME50' can be applied unlimited times to multiple items in same order",
        'url': 'http://localhost/apply-discount.php',
        'cvss_score': 6.8,
        'risk_score': 6.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.93,
        'reason': 'Evidence-based: discount control bypass confirmed',
        'strategy': 'Evidence of missing discount reuse prevention'
    },
    {
        'severity': 'high',
        'category': 'Business Logic Flaw',
        'description': 'Workflow bypass allowing order completion without payment verification',
        'evidence': "Modify hidden order_status parameter from 'pending' to 'confirmed' in POST request, bypassing payment gateway",
        'url': 'http://localhost/order/review.php',
        'cvss_score': 8.0,
        'risk_score': 7.8,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: state machine bypass confirmed',
        'strategy': 'Evidence of hidden parameter manipulation'
    },
    {
        'severity': 'medium',
        'category': 'Business Logic Flaw',
        'description': 'Quantity validation flaw allowing free items',
        'evidence': "Negative quantity parameter accepted: -1 units at $10 each = $-10, applied as account credit instead of purchase",
        'url': 'http://localhost/api/cart/add',
        'cvss_score': 6.5,
        'risk_score': 6.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.92,
        'reason': 'Evidence-based: validation bypass confirmed',
        'strategy': 'Evidence of missing input bounds checking'
    },

    # Path Traversal (5)
    {
        'severity': 'high',
        'category': 'Path Traversal',
        'description': 'Directory traversal in file download parameter',
        'evidence': "Parameter /download.php?file=../../../../etc/passwd allows downloading system files outside intended directory",
        'url': 'http://localhost/download.php',
        'cvss_score': 8.3,
        'risk_score': 8.0,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.97,
        'reason': 'Evidence-based: system file access confirmed',
        'strategy': 'Evidence of traversal sequence successful'
    },
    {
        'severity': 'high',
        'category': 'Path Traversal',
        'description': 'LFI in template loader allowing arbitrary PHP inclusion',
        'evidence': "Parameter /page.php?template=../../config includes local config.php, exposing database credentials",
        'url': 'http://localhost/page.php',
        'cvss_score': 8.1,
        'risk_score': 7.9,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.96,
        'reason': 'Evidence-based: credential exposure via LFI confirmed',
        'strategy': 'Evidence of PHP execution via inclusion'
    },
    {
        'severity': 'high',
        'category': 'Path Traversal',
        'description': 'Null byte injection bypassing file extension check',
        'evidence': "Parameter /upload.php?file=shell.php%00.jpg bypasses .jpg restriction due to null byte handling, uploading executable PHP",
        'url': 'http://localhost/upload.php',
        'cvss_score': 8.0,
        'risk_score': 7.7,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.95,
        'reason': 'Evidence-based: file type bypass confirmed',
        'strategy': 'Evidence of null byte string termination'
    },
    {
        'severity': 'medium',
        'category': 'Path Traversal',
        'description': 'Directory listing via traversal in backup files',
        'evidence': "Parameter /backup.php?date=2024-01-01/.. allows directory listing and accessing backup files outside intended location",
        'url': 'http://localhost/backup.php',
        'cvss_score': 6.5,
        'risk_score': 6.2,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.93,
        'reason': 'Evidence-based: directory access confirmed',
        'strategy': 'Evidence of traversal successful'
    },
    {
        'severity': 'high',
        'category': 'Path Traversal',
        'description': 'Symlink following in file serving function',
        'evidence': "Web server follows symlinks: /download.php?file=link_to_private_key successfully retrieves SSH private key",
        'url': 'http://localhost/download.php',
        'cvss_score': 7.8,
        'risk_score': 7.5,
        'label': 0,
        'label_name': 'TP',
        'confidence': 0.94,
        'reason': 'Evidence-based: private key access via symlink confirmed',
        'strategy': 'Evidence of symlink traversal'
    }
]


def augment_training_data():
    """Generate augmented training dataset with synthetic TP examples."""
    
    print("\n" + "="*80)
    print("GENERATING SYNTHETIC TP EXAMPLES FOR AUGMENTATION")
    print("="*80)
    
    # Load existing labeled data
    original_path = 'proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled.json'
    print(f"\n[LOAD] Loading original labeled data: {original_path}")
    
    with open(original_path, 'r', encoding='utf-8') as f:
        original_data = json.load(f)
    
    print(f"[OK] Loaded {len(original_data)} original records")
    
    # Add synthetic examples
    print(f"\n[AUGMENT] Adding {len(SYNTHETIC_TP)} synthetic TP examples:")
    
    category_counts = {}
    for example in SYNTHETIC_TP:
        cat = example.get('category', 'Unknown')
        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    for cat, count in sorted(category_counts.items()):
        print(f"   {count:2d} x {cat}")
    
    # Combine
    augmented_data = original_data + SYNTHETIC_TP
    
    print(f"\n[COMBINE] Original: {len(original_data)} + Synthetic: {len(SYNTHETIC_TP)} = Total: {len(augmented_data)}")
    
    # Count by label
    tp_count = sum(1 for d in augmented_data if d.get('label_name') == 'TP' or d.get('label') == 0)
    fp_count = sum(1 for d in augmented_data if d.get('label_name') == 'FP' or d.get('label') == 1)
    potential_count = sum(1 for d in augmented_data if d.get('label_name') == 'Potential')
    
    print(f"\n[STATS] Augmented Dataset Distribution:")
    print(f"   True Positives (TP): {tp_count}")
    print(f"   False Positives (FP): {fp_count}")
    print(f"   Potential: {potential_count}")
    print(f"   Imbalance Ratio: {tp_count/fp_count:.1f}:1 (TP:FP)")
    
    # Save augmented dataset
    augmented_path = 'proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled_augmented.json'
    
    with open(augmented_path, 'w', encoding='utf-8') as f:
        json.dump(augmented_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[SAVE] Augmented dataset saved to: {augmented_path}")
    
    # Summary
    print(f"\n" + "="*80)
    print("AUGMENTATION COMPLETE")
    print("="*80)
    print(f"\nNext step: python train_augmented_fp_reducer.py")
    print(f"This will train on {len(augmented_data)} samples with better vulnerability diversity\n")
    
    return augmented_path


if __name__ == '__main__':
    augment_training_data()
