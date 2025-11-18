# Priority 2 Features - Reporting & Integrations

Advanced reporting, trend tracking, and external system integrations.

---

## 🎯 Overview

Priority 2 adds enterprise-grade features for security operations:

1. **Historical Tracking** - Trend analysis and regression detection
2. **PDF Reports** - Executive summaries and compliance reports
3. **Integrations** - SIEM, ticketing systems, and webhooks

---

## 📊 Feature 1: Historical Tracking & Trends

### **Purpose**
Track vulnerability trends over time, detect regressions, and monitor fix rates.

### **Capabilities**
- ✅ SQLite database for scan history
- ✅ Trend tracking (daily/weekly/monthly)
- ✅ Regression detection (new vulnerabilities)
- ✅ Fix rate monitoring
- ✅ Average time to fix calculation

### **Database Schema**

```sql
-- Scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    scan_id TEXT UNIQUE,
    scan_type TEXT,
    target_url TEXT,
    timestamp DATETIME,
    total_findings INTEGER,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    info_count INTEGER
);

-- Findings table
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    scan_id TEXT,
    finding_hash TEXT,
    severity TEXT,
    category TEXT,
    cvss_score REAL,
    risk_score REAL,
    first_seen DATETIME,
    last_seen DATETIME,
    status TEXT DEFAULT 'open'
);
```

### **API Endpoints**

#### Get Trends
```bash
GET /trends?days=30

Response:
{
  "period_days": 30,
  "start_date": "2025-10-18T00:00:00Z",
  "end_date": "2025-11-18T00:00:00Z",
  "data_points": [
    {
      "date": "2025-11-18",
      "critical": 0,
      "high": 2,
      "medium": 17,
      "low": 0,
      "info": 1,
      "total": 20
    }
  ]
}
```

#### Detect Regressions
```bash
GET /regressions?lookback_scans=5

Response:
{
  "regressions_count": 3,
  "regressions": [
    {
      "severity": "High",
      "category": "SQL Injection",
      "first_seen": "2025-11-18T12:00:00Z",
      "url": "http://localhost:8998/admin/users.php"
    }
  ]
}
```

#### Get Fix Rate
```bash
GET /fix-rate?days=30

Response:
{
  "period_days": 30,
  "total_findings": 50,
  "fixed": 30,
  "open": 20,
  "fix_rate_percent": 60.0,
  "avg_time_to_fix_days": 5.2
}
```

### **Usage Example**

```python
from database.scan_history import ScanHistoryDB

db = ScanHistoryDB()

# Save scan results
db.save_scan(scan_data)

# Get trends
trends = db.get_trend_data(days=30)

# Detect regressions
regressions = db.detect_regressions(lookback_scans=5)

# Get fix rate
fix_rate = db.get_fix_rate(days=30)
```

---

## 📄 Feature 2: PDF Report Generation

### **Purpose**
Generate professional PDF reports for stakeholders and compliance.

### **Report Types**

#### 1. Executive Summary
- High-level overview
- Vulnerability summary
- Top 10 risks
- Recommendations

#### 2. Compliance Report
- OWASP Top 10 mapping
- PCI-DSS compliance
- Control status
- Findings count per control

#### 3. Detailed Technical Report
- All findings with evidence
- CVSS scores
- Risk scores
- Remediation guidance

### **API Endpoints**

#### Executive Summary
```bash
GET /reports/executive-summary?scan_id=scan_20251118_001

Response: PDF file download
```

#### Compliance Report
```bash
GET /reports/compliance?scan_id=scan_20251118_001&framework=OWASP

Frameworks supported:
- OWASP (OWASP Top 10 2021)
- PCI-DSS (PCI-DSS v3.2.1)

Response: PDF file download
```

### **Report Contents**

**Executive Summary includes:**
- Scan information (ID, date, target)
- Vulnerability summary (Critical/High/Medium/Low/Info)
- Top 10 critical findings
- Risk-based recommendations
- Compliance status

**Compliance Report includes:**
- Framework control mapping
- Pass/Fail status per control
- Findings count per control
- Remediation priorities

### **Usage Example**

```python
from reporting.pdf_generator import PDFReportGenerator

generator = PDFReportGenerator()

# Generate executive summary
pdf_bytes = generator.generate_executive_summary(scan_data)

# Generate compliance report
pdf_bytes = generator.generate_compliance_report(scan_data, framework="OWASP")

# Save to file
with open('report.pdf', 'wb') as f:
    f.write(pdf_bytes)
```

---

## 🔗 Feature 3: External Integrations

### **Purpose**
Integrate with SIEM, ticketing systems, and communication platforms.

### **Supported Integrations**

#### SIEM Systems
- ✅ **Splunk** (HTTP Event Collector)
- ✅ **ELK Stack** (Elasticsearch)
- ✅ **IBM QRadar** (API)

#### Ticketing Systems
- ✅ **Jira** (Cloud/Server)
- ✅ **ServiceNow** (Incident Management)
- ✅ **GitHub Issues**

#### Webhooks
- ✅ **Slack**
- ✅ **Microsoft Teams**
- ✅ **Discord**
- ✅ **Custom Webhooks**

### **API Endpoints**

#### Send Webhook
```bash
POST /integrations/webhook

Body:
{
  "webhook_type": "slack",
  "message": {
    "title": "Critical Vulnerability Detected",
    "severity": "critical",
    "category": "SQL Injection",
    "description": "SQL injection found in login form"
  },
  "config": {
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  }
}

Response:
{
  "success": true
}
```

#### Create Ticket
```bash
POST /integrations/ticket

Body:
{
  "ticketing_type": "jira",
  "ticket_data": {
    "title": "Fix SQL Injection in Login",
    "description": "Critical SQL injection vulnerability detected",
    "priority": 1
  },
  "config": {
    "jira_url": "https://your-domain.atlassian.net",
    "email": "your-email@example.com",
    "api_token": "your-api-token",
    "project_key": "SEC"
  }
}

Response:
{
  "success": true,
  "ticket_id": "SEC-123"
}
```

### **Integration Examples**

#### Splunk HEC
```python
from integrations.integration_manager import IntegrationManager

manager = IntegrationManager()

config = {
    'hec_url': 'https://splunk.example.com:8088/services/collector',
    'hec_token': 'your-hec-token'
}

event_data = {
    'scan_id': 'scan_001',
    'severity': 'high',
    'findings_count': 5
}

await manager.send_to_siem('splunk', event_data, config)
```

#### Jira Ticket
```python
config = {
    'jira_url': 'https://your-domain.atlassian.net',
    'email': 'your-email@example.com',
    'api_token': 'your-api-token',
    'project_key': 'SEC'
}

ticket_data = {
    'title': 'Critical Security Finding',
    'description': 'SQL injection detected',
    'priority': 1
}

ticket_id = await manager.create_ticket('jira', ticket_data, config)
```

#### Slack Webhook
```python
config = {
    'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
}

message = {
    'title': '🚨 Critical Vulnerability Alert',
    'severity': 'critical',
    'category': 'SQL Injection',
    'description': 'Immediate action required'
}

await manager.send_webhook('slack', message, config)
```

---

## 🎨 Webhook Message Formats

### Slack
```json
{
  "text": "Security Alert",
  "attachments": [{
    "color": "#dc3545",
    "fields": [
      {"title": "Severity", "value": "Critical"},
      {"title": "Category", "value": "SQL Injection"}
    ]
  }]
}
```

### Microsoft Teams
```json
{
  "@type": "MessageCard",
  "summary": "Security Alert",
  "themeColor": "#dc3545",
  "title": "Critical Vulnerability",
  "sections": [{
    "facts": [
      {"name": "Severity", "value": "Critical"},
      {"name": "Category", "value": "SQL Injection"}
    ]
  }]
}
```

### Discord
```json
{
  "embeds": [{
    "title": "Security Alert",
    "description": "Critical vulnerability detected",
    "color": 14423100,
    "fields": [
      {"name": "Severity", "value": "Critical"},
      {"name": "Category", "value": "SQL Injection"}
    ]
  }]
}
```

---

## 📈 Compliance Mappings

### OWASP Top 10 2021

| Control ID | Description | Mapped Findings |
|------------|-------------|-----------------|
| A03:2021 | Injection | SQL Injection |
| A07:2021 | XSS | Cross-Site Scripting |
| A01:2021 | Broken Access Control | Access Control |
| A05:2021 | Security Misconfiguration | Configuration |
| A02:2021 | Cryptographic Failures | Encryption |

### PCI-DSS v3.2.1

| Requirement | Description | Mapped Findings |
|-------------|-------------|-----------------|
| 6.5.1 | Injection flaws | SQL Injection |
| 6.5.7 | Cross-site scripting | XSS |
| 6.5.9 | Improper access control | Access Control |
| 6.5.10 | Broken authentication | Authentication |

---

## 🚀 Deployment

### Install Dependencies

```bash
pip install reportlab
```

### Database Setup

Database is automatically created on first run at `data/scan_history.db`.

### Configuration

Add to `config.py`:

```python
# Database
DATABASE_PATH = "data/scan_history.db"

# Integrations
ENABLE_SIEM = True
ENABLE_TICKETING = True
ENABLE_WEBHOOKS = True
```

---

## 📊 Usage Workflow

### 1. Run Scan & Save to Database
```python
# Scan is automatically saved to database
scan_result = await full_site_scan()
```

### 2. View Trends
```python
# Get 30-day trends
trends = await get_trends(days=30)
```

### 3. Generate Reports
```python
# Generate executive summary
pdf = await generate_executive_summary(scan_id="scan_001")

# Generate compliance report
pdf = await generate_compliance_report(scan_id="scan_001", framework="OWASP")
```

### 4. Send Notifications
```python
# Send Slack notification for critical findings
if critical_count > 0:
    await send_webhook_notification(
        webhook_type="slack",
        message=alert_data,
        config=slack_config
    )
```

### 5. Create Tickets
```python
# Auto-create Jira tickets for high/critical findings
for finding in high_critical_findings:
    ticket_id = await create_ticket(
        ticketing_type="jira",
        ticket_data=finding,
        config=jira_config
    )
```

---

## ✅ Testing

### Test Trends
```bash
curl http://localhost:8999/trends?days=30
```

### Test Regressions
```bash
curl http://localhost:8999/regressions?lookback_scans=5
```

### Test PDF Generation
```bash
curl "http://localhost:8999/reports/executive-summary?scan_id=scan_001" \
  -o report.pdf
```

### Test Webhook
```bash
curl -X POST http://localhost:8999/integrations/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_type": "slack",
    "message": {"title": "Test Alert"},
    "config": {"webhook_url": "YOUR_WEBHOOK_URL"}
  }'
```

---

## 📝 Benefits

### For Security Teams
- ✅ Historical trend analysis
- ✅ Regression detection
- ✅ Automated reporting
- ✅ SIEM integration

### For Management
- ✅ Executive summaries
- ✅ Compliance reports
- ✅ Fix rate metrics
- ✅ Progress tracking

### For DevOps
- ✅ Jira integration
- ✅ Slack notifications
- ✅ Automated ticketing
- ✅ CI/CD integration

---

## 🎯 Summary

**Priority 2 Features:**
- ✅ Historical tracking (1,150 lines)
- ✅ PDF reports (650 lines)
- ✅ Integrations (750 lines)
- **Total: ~2,550 lines**

**Combined Total:**
- Phase 1: ~1,860 lines
- Priority 1: ~1,150 lines
- Priority 2: ~2,550 lines
- **Grand Total: ~5,560 lines!**

---

**Status**: ✅ Priority 2 Features Complete  
**Next**: Testing & Documentation
