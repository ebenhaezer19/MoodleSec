# 🔌 IMPLEMENTATION GUIDE: Payload Reuse & ZAP Integration

## OPTION A: Record & Reuse Payloads dari Custom Scanner

### Step 1: Add Payload Tracking Database

```python
# File: MoodleSec/proxy/database/payload_tracker.py
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional

class PayloadTracker:
    """Track payloads used in scans for reuse and analysis."""
    
    def __init__(self, db_path: str = "data/payloads.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize payload tracking database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table untuk menyimpan payloads yang digunakan
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL,           -- "XSS", "SQLi", "CSRF"
                payload_type TEXT NOT NULL,       -- "reflected", "stored", "header"
                payload_text TEXT NOT NULL,       -- Payload aktual
                description TEXT,                 -- Apa yang dilakukan
                source TEXT,                      -- "zap", "custom", "manual"
                success_count INTEGER DEFAULT 0,  -- Berapa kali berhasil
                failure_count INTEGER DEFAULT 0,  -- Berapa kali gagal
                last_used TIMESTAMP,              -- Terakhir digunakan
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table untuk mapping payload → finding
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_findings (
                id INTEGER PRIMARY KEY,
                payload_id INTEGER,
                finding_id INTEGER,
                scan_id TEXT,
                success BOOLEAN,
                response_snippet TEXT,           -- First 500 chars of response
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (payload_id) REFERENCES payloads(id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_payload(self, category: str, payload_type: str, 
                   payload_text: str, description: str, 
                   source: str = "custom") -> int:
        """Tambah payload ke database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO payloads 
            (category, payload_type, payload_text, description, source)
            VALUES (?, ?, ?, ?, ?)
        """, (category, payload_type, payload_text, description, source))
        
        conn.commit()
        payload_id = cursor.lastrowid
        conn.close()
        
        return payload_id
    
    def get_payloads_by_category(self, category: str) -> List[Dict]:
        """Get all payloads untuk kategori tertentu."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM payloads 
            WHERE category = ? 
            ORDER BY success_count DESC
        """, (category,))
        
        payloads = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return payloads
    
    def record_usage(self, payload_id: int, finding_id: int, 
                    scan_id: str, success: bool, 
                    response_snippet: str = ""):
        """Record penggunaan payload."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Update success/failure count
        if success:
            cursor.execute(
                "UPDATE payloads SET success_count = success_count + 1 WHERE id = ?",
                (payload_id,)
            )
        else:
            cursor.execute(
                "UPDATE payloads SET failure_count = failure_count + 1 WHERE id = ?",
                (payload_id,)
            )
        
        # Update last_used
        cursor.execute(
            "UPDATE payloads SET last_used = CURRENT_TIMESTAMP WHERE id = ?",
            (payload_id,)
        )
        
        # Record finding
        cursor.execute("""
            INSERT INTO payload_findings 
            (payload_id, finding_id, scan_id, success, response_snippet)
            VALUES (?, ?, ?, ?, ?)
        """, (payload_id, finding_id, scan_id, success, response_snippet[:500]))
        
        conn.commit()
        conn.close()
```

### Step 2: Modify Custom Scanners to Track Payloads

```python
# File: MoodleSec/proxy/scanners/xss_detector.py (modified)
from scanners.payload_tracker import PayloadTracker

class XSSDetector:
    def __init__(self):
        self.payload_tracker = PayloadTracker()
        self._load_payloads()
    
    def _load_payloads(self):
        """Load previously successful payloads."""
        self.payloads = {
            'reflected': self.payload_tracker.get_payloads_by_category('XSS'),
            'stored': self.payload_tracker.get_payloads_by_category('XSS_Stored'),
            'dom': self.payload_tracker.get_payloads_by_category('XSS_DOM')
        }
    
    def test_payload(self, url: str, param_name: str, 
                     payload: str) -> tuple[bool, str]:
        """Test individual payload."""
        try:
            response = requests.get(url, params={param_name: payload})
            
            # Check if payload is in response unescaped
            if payload in response.text and not self._is_html_encoded(payload, response.text):
                return True, response.text[:500]
            
            return False, response.text[:500]
        except Exception as e:
            return False, str(e)[:500]
    
    def scan_endpoint(self, url: str, method: str = "GET") -> List[Dict]:
        """Scan endpoint using both new and previously successful payloads."""
        findings = []
        
        # Get URL parameters
        params = self._extract_params(url)
        
        for param_name in params:
            # Try previously successful payloads first (REUSE)
            for old_payload in self.payloads.get('reflected', []):
                success, response = self.test_payload(url, param_name, old_payload['payload_text'])
                
                if success:
                    # Record success
                    self.payload_tracker.record_usage(
                        old_payload['id'], 
                        finding_id=None,  # Will be assigned by database
                        scan_id=current_scan_id,
                        success=True,
                        response_snippet=response
                    )
                    
                    findings.append({
                        'category': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'Reflected XSS in parameter "{param_name}"',
                        'evidence': f'Payload "{old_payload["payload_text"]}" appears unescaped',
                        'url': url,
                        'payload_used': old_payload['payload_text'],  # ← Track ini!
                        'payload_source': 'reused'
                    })
            
            # Try new payloads
            new_payloads = [
                '<img src=x onerror=alert("xss")>',
                '"><script>alert("xss")</script>',
                'javascript:alert("xss")'
            ]
            
            for new_payload in new_payloads:
                success, response = self.test_payload(url, param_name, new_payload)
                
                if success:
                    # Add ke database untuk future reuse
                    payload_id = self.payload_tracker.add_payload(
                        category='XSS',
                        payload_type='reflected',
                        payload_text=new_payload,
                        description=f'XSS payload for {param_name}',
                        source='custom'
                    )
                    
                    findings.append({
                        'category': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'Reflected XSS in parameter "{param_name}"',
                        'evidence': f'Payload "{new_payload}" appears unescaped',
                        'url': url,
                        'payload_used': new_payload,
                        'payload_source': 'new'
                    })
        
        return findings
```

---

## OPTION B: Implement ZAP Integration for Payload Extraction

### Enable ZAP Scanning Instead of Custom Scanner

```python
# File: MoodleSec/proxy/app.py (modified)

from ml.zap_integration.zap_integration_manager import ZAPIntegrationManager
from ml.zap_integration.zap_result_aggregator import ZAPResultAggregator
from database.payload_tracker import PayloadTracker

# Initialize ZAP Manager
zap_manager = ZAPIntegrationManager(
    host="localhost",
    port=8080,
    api_key="1qlbij76v3j9c6ail8d0locm24"
)

payload_tracker = PayloadTracker()

@app.post("/api/scan-native-auth-zap")
async def scan_with_zap(request: NativeAuthScanRequest) -> Dict[str, Any]:
    """
    Native authenticated scan menggunakan ZAP.
    """
    scan_id = f"zap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        # Step 1: Setup ZAP authentication
        print(f"[ZAP Scan] Configuring authentication...")
        zap_manager.configure_moodle_auth(
            context_id=1,
            moodle_url=MOODLE_URL,
            username=request.username,
            password=request.password
        )
        
        # Step 2: Spider dengan authenticated session
        print(f"[ZAP Scan] Starting spider...")
        spider_results = zap_manager.spider_manager.start_spider(
            url=MOODLE_URL,
            context_id=1,
            max_depth=request.max_depth
        )
        
        # Step 3: Active scan
        print(f"[ZAP Scan] Starting active scan...")
        scan_id_zap = zap_manager.ascan_manager.start_ascan(
            url=MOODLE_URL,
            context_id=1,
            policy="medium"
        )
        
        # Wait for scan to complete
        progress = zap_manager.ascan_manager.wait_for_completion(scan_id_zap)
        
        # Step 4: Get raw findings (dengan PAYLOADS dari ZAP)
        print(f"[ZAP Scan] Retrieving findings...")
        raw_findings = zap_manager.result_aggregator.get_raw_findings(scan_id_zap)
        
        # Step 5: Extract dan record payloads
        for finding in raw_findings:
            # Evidence dari ZAP berisi HTML snippet atau error message
            evidence = finding.get('evidence', '')
            
            # Try to extract payload dari evidence
            if evidence and len(evidence) > 5:
                # This IS the payload atau HTTP response yang menunjukkan payload
                payload_id = payload_tracker.add_payload(
                    category=finding.get('category', 'Unknown'),
                    payload_type='zap_extracted',
                    payload_text=evidence[:200],  # Payload atau snippet
                    description=f"Extracted from ZAP finding: {finding.get('description')}",
                    source='zap'
                )
                
                print(f"[ZAP Scan] Recorded payload #{payload_id} from finding")
        
        # Step 6: Filter findings dengan ML
        filtered_findings = zap_manager.result_aggregator.apply_filtering(raw_findings)
        
        # Step 7: Save ke database
        scan_data = {
            'scan_id': scan_id,
            'scan_type': 'native_authenticated_zap',
            'target_url': MOODLE_URL,
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(filtered_findings),
            'findings': filtered_findings
        }
        scan_history_db.save_scan(scan_data)
        
        return {
            'success': True,
            'scan_id': scan_id,
            'findings_count': len(filtered_findings),
            'payloads_recorded': len([f for f in raw_findings if f.get('evidence')])
        }
    
    except Exception as e:
        print(f"[ZAP Scan] ERROR: {e}")
        return {'success': False, 'error': str(e)}
```

---

## OPTION C: Manual Payload Migration from ZAP Report

### If ZAP scan dijalankan manual dari GUI:

```python
# File: MoodleSec/proxy/utils/import_zap_report.py

import json
import xml.etree.ElementTree as ET
from database.payload_tracker import PayloadTracker

class ZAPReportImporter:
    """Import payloads dari ZAP report (JSON/XML)."""
    
    def __init__(self):
        self.tracker = PayloadTracker()
    
    def import_json_report(self, report_path: str) -> int:
        """Import dari ZAP JSON report."""
        with open(report_path, 'r') as f:
            report = json.load(f)
        
        count = 0
        for site in report.get('site', []):
            for alert in site.get('alerts', []):
                # Extract payload dari evidence
                evidence = alert.get('evidence', '')
                if evidence:
                    self.tracker.add_payload(
                        category=alert.get('name', 'Unknown'),
                        payload_type=self._detect_payload_type(evidence),
                        payload_text=evidence[:500],  # Payload atau snippet
                        description=alert.get('description', ''),
                        source='zap_manual_import'
                    )
                    count += 1
        
        return count
    
    def import_xml_report(self, report_path: str) -> int:
        """Import dari ZAP XML report."""
        tree = ET.parse(report_path)
        root = tree.getroot()
        
        count = 0
        for alert in root.findall('.//alert'):
            evidence = alert.findtext('evidence', '')
            if evidence:
                self.tracker.add_payload(
                    category=alert.findtext('name', 'Unknown'),
                    payload_type=self._detect_payload_type(evidence),
                    payload_text=evidence[:500],
                    description=alert.findtext('description', ''),
                    source='zap_manual_import'
                )
                count += 1
        
        return count
    
    def _detect_payload_type(self, evidence: str) -> str:
        """Detect jenis payload dari evidence."""
        if '<' in evidence or '>' in evidence:
            return 'xss'
        elif 'SELECT' in evidence or 'UNION' in evidence:
            return 'sqli'
        elif 'csrf' in evidence.lower():
            return 'csrf'
        else:
            return 'other'

# Usage:
# importer = ZAPReportImporter()
# count = importer.import_json_report('/path/to/zap_report.json')
# print(f"Imported {count} payloads")
```

---

## 📊 Comparison Table

| Feature | Custom Scanner | ZAP Integration | Hybrid |
|---------|---|---|---|
| **Payload Tracking** | ✅ Easy to add | ✅ Via API | ✅ Both |
| **Payload Reuse** | ✅ Custom DB | ✅ Need recording | ✅ Yes |
| **Enterprise Payloads** | ❌ Limited | ✅ Extensive | ✅ Both |
| **Control** | ✅ Full | ⚠️ Depends on ZAP | ✅ Full |
| **Evidence Detail** | ⚠️ Text only | ✅ Rich | ✅ Both |
| **Performance** | ✅ Fast | ⚠️ Slower | ⚠️ Medium |
| **Maintenance** | ✅ Self | ⚠️ ZAP updates | ✅ Balanced |

---

## 🎯 RECOMMENDATION

**Untuk Anda:**

1. **Short term (Sekarang):**
   - Implementasi Option A: Payload Tracking
   - Tambah `payload_used` field ke findings
   - Track mana payload yang berhasil untuk reuse

2. **Medium term (2-3 bulan):**
   - Build payload repository dengan success rates
   - Create admin UI untuk manage payloads

3. **Long term (Later):**
   - Integrate ZAP untuk enterprise payloads
   - Use both: Custom scanner + ZAP payloads
   - Maintain centralized payload database

---

**STATUS: READY FOR IMPLEMENTATION**
