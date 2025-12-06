#!/usr/bin/env python3
"""
Count findings in large OWASP ZAP JSON files using streaming parser
"""
import sys
import re
from pathlib import Path

def count_zap_alerts_streaming(json_file):
    """
    Count ZAP alerts in large files without loading entire JSON into memory.
    Uses regex to find "alerts" arrays and count their elements.
    """
    try:
        file_size_mb = Path(json_file).stat().st_size / (1024 * 1024)
        print(f"[*] Processing: {Path(json_file).name} ({file_size_mb:.1f} MB)")
        
        alert_count = 0
        
        # Read file in chunks and count "alertRef" occurrences
        # Each alert in ZAP has an "alertRef" field
        with open(json_file, 'r', encoding='utf-8') as f:
            chunk_size = 1024 * 1024  # 1MB chunks
            buffer = ""
            
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                buffer += chunk
                
                # Count "alertRef" occurrences in buffer
                # This is a unique identifier for each alert
                matches = re.findall(r'"alertRef":', buffer)
                alert_count += len(matches)
                
                # Keep last 1000 chars in buffer to handle split patterns
                buffer = buffer[-1000:]
        
        print(f"[+] Found {alert_count} alerts")
        return alert_count
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return 0

def main():
    if len(sys.argv) < 2:
        print("Usage: python count_large_zap.py <json_file>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    if not Path(json_file).exists():
        print(f"[!] File not found: {json_file}")
        sys.exit(1)
    
    total_alerts = count_zap_alerts_streaming(json_file)
    
    print(f"\n{'='*60}")
    print(f"Total Alerts: {total_alerts}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
