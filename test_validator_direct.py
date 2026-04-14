#!/usr/bin/env python3
"""Test SmartResponseValidator directly with Moodle error response."""

import sys
sys.path.insert(0, 'proxy')

from scanners.response_validator import SmartResponseValidator

# Normal response (baseline)
normal_response = """<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
<title>Log in to the site</title>
</head>
<body>
<h1>Login Form</h1>
<form>
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</body>
</html>"""

# Response WITH SQL injection error (from user test)
sqli_error_response = """<div class="notifytiny debuggingmessage" data-rel="debugging">Exception encountered in event observer '\\local_security_dashboard\\login_observer::user_login_failed': Error writing to database (Data too long for column 'username' at row 1
INSERT INTO mdl_local_security_login_log (userid,username,success,ip_address,user_agent,country,city,region,isp,latitude,longitude,is_suspicious,risk_score,fail_reason,session_id,timecreated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
-- line 1494 of /lib/dml/mysqli_native_moodle_database.php</div><!DOCTYPE html>
<html dir="ltr" lang="en" xml:lang="en">
<head>
<title>Log in to the site</title>
</head>
</html>"""

print("=" * 80)
print("SMARTRESPONSEVALIDATOR DIRECT TEST")
print("=" * 80)

validator = SmartResponseValidator()

# Set baseline with normal response
print("\n[1] Setting baseline with normal response...")
validator.set_baseline(
    endpoint="http://localhost:8998/login/index.php",
    response_text=normal_response,
    response_code=200,
    response_length=len(normal_response)
)
print(f"    Baseline length: {len(normal_response)} bytes")

# Test with SQLi error response
print("\n[2] Testing SQLi error response...")
print(f"    Response length: {len(sqli_error_response)} bytes")
print(f"    Length difference: {abs(len(sqli_error_response) - len(normal_response))} bytes")

detection = validator.validate_response(
    endpoint="http://localhost:8998/login/index.php",
    response_text=sqli_error_response,
    response_code=200,
    response_time=0.5
)

print("\n[3] Detection Results:")
print(f"    Is Vulnerable: {detection.is_vulnerable}")
print(f"    Confidence: {detection.confidence:.2f}")
print(f"    Detection Types: {[str(t) for t in detection.detection_types]}")
print(f"    Evidence: {detection.evidence}")

print("\n" + "=" * 80)
if detection.is_vulnerable:
    print("✅ SUCCESS: SQLi error DETECTED by validator!")
else:
    print("❌ FAILED: SQLi error NOT detected")
    print("\nDebugging info:")
    print(f"  - Response contains 'Data too long': {'Data too long' in sqli_error_response}")
    print(f"  - Response contains 'Error writing': {'Error writing' in sqli_error_response}")
    print(f"  - Response contains 'INSERT INTO': {'INSERT INTO' in sqli_error_response}")
    print(f"  - Response contains 'Exception': {'Exception' in sqli_error_response}")
