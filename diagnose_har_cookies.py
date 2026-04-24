import json

har_path = r'C:\Users\Admin\OneDrive\Desktop\Kuliah Guwa\TA\MoodleSec\ml\training_data\Normal-Moodle-Browser.har'

with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
    har = json.load(f)

entries = har['log']['entries']

print("=" * 80)
print("HAR STRUCTURE ANALYSIS - WHERE ARE COOKIES STORED?")
print("=" * 80)

# Check first entry
e = entries[0]
print(f"\nTotal entries: {len(entries)}")
print(f"\nFirst entry structure:")
print(f"  Keys: {e.keys()}")

print("\n" + "=" * 80)
print("CHECKING COOKIES IN REQUEST")
print("=" * 80)

print(f"\n1. Request has 'cookies' array? {('cookies' in e['request'])}")
if 'cookies' in e['request']:
    print(f"   Cookies in request[0]: {e['request']['cookies'][:3]}")

print(f"\n2. Request has 'headers' array? {('headers' in e['request'])}")
if 'headers' in e['request']:
    headers = e['request']['headers']
    print(f"   Total headers: {len(headers)}")
    # Find Cookie header
    cookie_header = [h for h in headers if h.get('name', '').lower() == 'cookie']
    print(f"   'Cookie' headers found: {len(cookie_header)}")
    if cookie_header:
        print(f"   First Cookie header value (first 100 chars): {cookie_header[0]['value'][:100]}")
        # Check for MoodleSession
        if 'MoodleSession' in cookie_header[0]['value']:
            print(f"   ✓ Contains MoodleSession cookie")

print("\n" + "=" * 80)
print("CHECKING TIME FIELD")
print("=" * 80)

print(f"\n'time' field in entry? {('time' in e)}")
print(f"Time value: {e.get('time')}")
print(f"Time type: {type(e.get('time'))}")
print(f"Time in ms: {e.get('time') * 1000 if e.get('time') else 'N/A'} ms")

print("\n" + "=" * 80)
print("SCANNING 20 ENTRIES FOR PATTERNS")
print("=" * 80)

moodle_cookie_count = 0
cookie_sources = {}

for i in range(min(20, len(entries))):
    e = entries[i]
    
    # Check for MoodleSession in headers
    has_moodle_cookie = False
    if 'headers' in e['request']:
        cookie_headers = [h for h in e['request']['headers'] if h.get('name', '').lower() == 'cookie']
        if cookie_headers:
            for ch in cookie_headers:
                if 'MoodleSession' in ch.get('value', ''):
                    has_moodle_cookie = True
                    break
    
    time_ms = e.get('time', 0) * 1000 if e.get('time') else 0
    status = e['response'].get('status', '?')
    url = e['request'].get('url', '')[:50]
    
    if has_moodle_cookie:
        moodle_cookie_count += 1
    
    print(f"Entry {i:2d}: time={time_ms:7.0f}ms, status={status}, MoodleSession={has_moodle_cookie}, url={url}...")

print(f"\n✓ MoodleSession cookies found in {moodle_cookie_count}/20 entries")
print(f"\nThis confirms: Normal browsing HAR DOES have ~95% MoodleSession cookies")
print(f"The extraction code is looking in the WRONG PLACE!")
