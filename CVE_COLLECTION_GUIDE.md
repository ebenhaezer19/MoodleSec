# Moodle CVE Collection Guide
## Objective: Collect True Positive samples from documented Moodle vulnerabilities

---

## PHASE 1: CVE Research & Selection (2-3 hours)

### Step 1.1: Analyze CVE Database
**Source:** https://www.cvedetails.com/product/3590/Moodle-Moodle.html?vendor_id=2105

**Filter Criteria:**
1. **Severity:** High or Critical only
2. **Type:** Focus on OWASP Top 10:
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - CSRF (Cross-Site Request Forgery)
   - Authentication/Authorization bypass
   - Remote Code Execution (RCE)
   - File Upload vulnerabilities
   - Path Traversal
   - SSRF

3. **Moodle Version:** Focus on versions masih bisa diinstall:
   - Moodle 3.9.x (LTS, End of Life)
   - Moodle 3.11.x (LTS, recently EOL)
   - Moodle 4.0.x (easier to setup)

4. **Exploit Availability:** Prioritize CVE dengan:
   - PoC (Proof of Concept) available
   - Detailed advisory
   - Reproducible steps

---

### Step 1.2: Priority CVE List (Example Selection)

Based on CVE Details, here are high-priority targets:

#### **HIGH PRIORITY (Easy to reproduce):**

**1. SQL Injection CVEs:**
- CVE-2023-30943 (Moodle < 4.1.3) - SQL Injection in course reports
- CVE-2021-36393 (Moodle < 3.9.8) - SQL Injection in badges
- CVE-2020-14321 (Moodle < 3.9.1) - SQL Injection in forum

**2. XSS CVEs:**
- CVE-2023-28329 (Moodle < 4.1.2) - Stored XSS in calendar
- CVE-2022-35653 (Moodle < 3.11.8) - XSS in messaging
- CVE-2021-36394 (Moodle < 3.9.8) - XSS in user profile

**3. Authentication/Authorization:**
- CVE-2023-28328 (Moodle < 4.1.2) - Authentication bypass
- CVE-2022-35649 (Moodle < 3.11.8) - Privilege escalation
- CVE-2020-14318 (Moodle < 3.9.1) - CSRF protection bypass

**4. File Upload:**
- CVE-2023-30544 (Moodle < 4.1.3) - Unrestricted file upload
- CVE-2021-36392 (Moodle < 3.9.8) - File type validation bypass

**5. SSRF/RCE:**
- CVE-2022-35650 (Moodle < 3.11.8) - SSRF in external content
- CVE-2020-14322 (Moodle < 3.9.1) - Remote code execution

---

### Step 1.3: CVE Documentation Template

For each CVE, document:

```markdown
## CVE-XXXX-XXXXX

**Severity:** High/Critical
**Type:** SQL Injection / XSS / etc
**Affected Versions:** Moodle X.X.x - Y.Y.y
**Fixed in:** Moodle Z.Z.z

**Description:**
[Brief description of vulnerability]

**Attack Vector:**
[How to exploit - URL, payload, steps]

**Proof of Concept:**
```
[PoC code or curl command]
```

**Expected Finding:**
- Scanner should detect: [Expected alert name]
- Evidence: [What evidence scanner should capture]
- Label: TRUE POSITIVE ✅
```

---

## PHASE 2: Test Environment Setup (4-6 hours)

### Step 2.1: Choose Deployment Method

**Option A: Docker (RECOMMENDED - Fastest)**
```bash
# Pull vulnerable Moodle version
docker pull moodle/moodle:3.9.0
docker run -d --name moodle-vuln \
  -p 8080:80 \
  -e MOODLE_DATABASE_TYPE=mariadb \
  -e MOODLE_DATABASE_HOST=db \
  -e MOODLE_DATABASE_NAME=moodle \
  -e MOODLE_DATABASE_USER=moodle \
  -e MOODLE_DATABASE_PASSWORD=moodle \
  moodle/moodle:3.9.0
```

**Option B: Bitnami Moodle Stack**
- Download: https://bitnami.com/stack/moodle
- Choose Moodle 3.9.x version
- Easy installation wizard
- Self-contained (Apache + MySQL + PHP)

**Option C: Manual Install**
- Download Moodle source: https://download.moodle.org/releases/legacy/
- Setup XAMPP/WAMP
- Install Moodle 3.9.x manually

### Step 2.2: Post-Installation Setup

1. **Enable Developer Mode:**
   ```
   Admin → Development → Debugging → DEVELOPER level
   ```

2. **Disable Security Features (for testing only!):**
   ```
   Admin → Security → HTTP Security → Disable all
   ```

3. **Create Test Users:**
   - Admin account (for testing auth bypass)
   - Student account (for privilege escalation)
   - Teacher account (for testing RBAC)

4. **Populate Sample Data:**
   - Create courses
   - Add forums, quizzes, assignments
   - Upload files
   (This gives scanners more surface area)

---

## PHASE 3: CVE Reproduction (Per CVE: 30-60 mins)

### Step 3.1: Manual Exploitation Test

**Template Workflow:**

1. **Read CVE Advisory:**
   - Official Moodle advisory: https://moodle.org/security/
   - CVE Details: Full description + references

2. **Identify Attack Endpoint:**
   ```
   Example for SQL Injection in badges:
   URL: /badges/overview.php?id=[BADGE_ID]
   Parameter: id
   Payload: 1' OR '1'='1
   ```

3. **Test Manually:**
   ```bash
   # Use curl or browser
   curl "http://localhost:8080/badges/overview.php?id=1' OR '1'='1"
   
   # Check response for:
   - SQL error messages
   - Unexpected data disclosure
   - Different behavior
   ```

4. **Document Evidence:**
   - Screenshot of vulnerable response
   - HTTP request/response logs
   - Proof of exploitation success

---

## PHASE 4: Scanner Testing (Per CVE: 15-30 mins)

### Step 4.1: OWASP ZAP Scan

**Targeted Scan:**
```bash
# Focus scan on specific vulnerable endpoint
zap.sh -cmd \
  -quickurl http://localhost:8080/badges/overview.php \
  -quickprogress \
  -quickout /path/to/output.json
```

**Important:** Configure ZAP to be aggressive for known vulnerable endpoints.

### Step 4.2: Acunetix Scan

**Manual Scan Configuration:**
1. Create new scan target
2. Add vulnerable Moodle URL
3. Enable all vulnerability checks
4. Set crawl scope to include vulnerable modules
5. Run scan
6. Export JSON report

### Step 4.3: Verify Scanner Detection

**Expected Outcomes:**

✅ **BEST CASE: Scanner detects vulnerability**
- Category matches CVE type
- Severity appropriate
- Evidence includes exploit payload
- **Label as TRUE POSITIVE**

⚠️ **MODERATE: Scanner detects related issue**
- Category similar but not exact
- Still exploitable
- **Label as TRUE POSITIVE with notes**

❌ **WORST CASE: Scanner misses vulnerability**
- No alert generated
- **Document as scanner limitation**
- **Manually create finding for dataset**

---

## PHASE 5: Data Collection & Labeling (Per CVE: 10-15 mins)

### Step 5.1: Extract Scanner Finding

From scanner JSON, extract:
```json
{
  "category": "SQL Injection",
  "severity": "High",
  "url": "http://localhost:8080/badges/overview.php?id=1",
  "description": "[Scanner description]",
  "evidence": "[Exploit payload]",
  "cvss_score": 7.5
}
```

### Step 5.2: Manual Labeling

```json
{
  "finding": { ... },
  "label": 0,  // TRUE POSITIVE
  "label_name": "TRUE_POSITIVE",
  "label_source": "manual_review_cve",
  "label_confidence": 1.0,
  "cve_id": "CVE-2021-36393",
  "cve_verified": true,
  "exploit_confirmed": true,
  "notes": "Reproduced CVE-2021-36393 SQL Injection in badges module"
}
```

### Step 5.3: Add to Training Dataset

Append to `processed_findings_YYYYMMDD_HHMMSS.json`

---

## PHASE 6: Iteration & Validation (Ongoing)

### Step 6.1: Target Collection Goals

**Minimum Viable:**
- 20 CVE-based TP samples
- Coverage: SQL Injection (5), XSS (5), Auth (5), Other (5)
- Multiple Moodle versions

**Ideal:**
- 30-50 CVE-based TP samples
- Full OWASP Top 10 coverage
- Diverse attack vectors

### Step 6.2: Quality Checks

For each TP sample, verify:
- ✅ CVE is documented and confirmed
- ✅ Vulnerability reproduced successfully
- ✅ Scanner detected (or finding manually created)
- ✅ Labels accurate and confident
- ✅ Evidence sufficient for ML training

---

## TOOLS & RESOURCES

### Essential Tools:
- **OWASP ZAP**: https://www.zaproxy.org/
- **Acunetix** (if available)
- **Burp Suite Community**: For manual testing
- **Docker**: For quick environment setup
- **Postman/Insomnia**: For API testing

### Key Resources:
- **Moodle Security**: https://moodle.org/security/
- **CVE Details**: https://www.cvedetails.com/product/3590/
- **Exploit-DB**: https://www.exploit-db.com/ (search "moodle")
- **GitHub**: Search for "moodle exploit" or "moodle poc"
- **Moodle Tracker**: https://tracker.moodle.org/ (for detailed bug reports)

### Helper Scripts:
- `cve_collection_tracker.xlsx` - Track progress per CVE
- `reproduce_cve.py` - Automated exploitation scripts
- `label_cve_findings.py` - Batch labeling tool

---

## TIME ESTIMATES

**Per CVE (Full Cycle):**
- Research: 15 mins
- Reproduction: 30-60 mins
- Scanner test: 15-30 mins
- Documentation: 10-15 mins
- **Total: 70-120 mins per CVE**

**Target Collection:**
- 20 CVEs = 23-40 hours (3-5 days dedicated work)
- 30 CVEs = 35-60 hours (5-7 days dedicated work)

**Parallelization:**
- Setup 2-3 Moodle versions simultaneously
- Test multiple CVEs per version
- Can reduce timeline by 30-40%

---

## SUCCESS METRICS

**Dataset Quality:**
- ✅ All TP samples have confirmed CVE IDs
- ✅ 100% exploitation success rate
- ✅ Scanner detection rate: 70%+ (realistic target)
- ✅ Documentation complete for defense

**Model Improvement:**
- Before: 8 TP samples (29.75:1 imbalance)
- Target: 30+ TP samples (<10:1 imbalance)
- Expected: Better generalization, lower overfitting

**Defense Readiness:**
- Can cite specific CVEs tested
- Can demonstrate real vulnerability detection
- Can justify TP labels with evidence

---

## NEXT STEPS

1. **Start with 5 High-Priority CVEs** (SQL Injection + XSS)
2. **Setup 1 vulnerable Moodle instance** (3.9.x recommended)
3. **Reproduce & scan first batch** (1-2 days)
4. **Validate approach** before scaling to 30 CVEs
5. **Iterate and expand** based on results

Ready to begin? 🚀
