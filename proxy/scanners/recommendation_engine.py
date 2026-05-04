"""
Recommendation Engine — AI-Powered Security Remediation

Enriches security findings with:
  - PoC (Proof of Concept) structure
  - CVSS v3.1 scoring
  - GPT-powered dynamic recommendations (with fallback to static templates)
  - Moodle-specific config suggestions
  - L6 config hints + L7 verify-fix metadata

Architecture:
  Scanner finding → enrich_finding() → enriched finding (poc, cvss, recommendation, config_fix)
"""

import os
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 Base Score Map (category → score + vector)
# ─────────────────────────────────────────────────────────────────────────────
CVSS_MAP = {
    'SQL Injection': {
        'score': 9.8, 'severity': 'Critical',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'rationale': 'Network-accessible, no auth required, full C/I/A impact'
    },
    'XSS': {
        'score': 6.1, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'rationale': 'Requires user interaction, limited impact scope'
    },
    'Cross-Site Scripting': {
        'score': 6.1, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
        'rationale': 'Requires user interaction, limited impact scope'
    },
    'CSRF': {
        'score': 6.5, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
        'rationale': 'Requires user interaction, high integrity impact'
    },
    'Path Traversal': {
        'score': 7.5, 'severity': 'High',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'rationale': 'Network-accessible, no auth, high confidentiality impact'
    },
    'Information Disclosure': {
        'score': 5.3, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'rationale': 'Limited confidentiality disclosure'
    },
    'Missing Security Header': {
        'score': 4.3, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
        'rationale': 'Missing defensive control, limited direct impact'
    },
    'Clickjacking': {
        'score': 4.3, 'severity': 'Medium',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
        'rationale': 'Requires user interaction, UI-level attack'
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# STATIC RECOMMENDATION TEMPLATES (Fallback when GPT unavailable)
# ─────────────────────────────────────────────────────────────────────────────
STATIC_TEMPLATES = {
    'SQL Injection': {
        'summary': (
            "SQL Injection memungkinkan attacker memanipulasi query database "
            "untuk membaca, mengubah, atau menghapus data. Di Moodle, "
            "vulnerability ini sangat kritis karena database menyimpan data "
            "pengguna, nilai, dan konten kursus."
        ),
        'steps': [
            "Gunakan Moodle Database API (\\$DB->get_record_sql) dengan parameterized queries",
            "Validasi semua input menggunakan PARAM_* constants Moodle (PARAM_INT, PARAM_TEXT)",
            "Aktifkan Moodle's built-in SQL injection protection di config.php",
            "Audit semua custom SQL queries di plugin/theme yang diinstall",
            "Enable database query logging untuk monitoring",
        ],
        'code_fix': (
            "// SEBELUM (Vulnerable):\n"
            "$sql = \"SELECT * FROM mdl_user WHERE username = '$username'\";\n"
            "$result = $DB->get_records_sql($sql);\n\n"
            "// SESUDAH (Aman):\n"
            "$result = $DB->get_records_sql(\n"
            "    'SELECT * FROM {user} WHERE username = ?',\n"
            "    [$username]\n"
            ");"
        ),
        'config_fix': {
            'moodle': (
                "// config.php — Aktifkan debugging untuk monitor errors:\n"
                "$CFG->dbdebug = 0;  // Set 0 di production\n"
                "$CFG->debug = 0;    // Matikan error display di production"
            ),
            'description': "Pastikan debug mode dimatikan di production agar SQL errors tidak terekspos ke user"
        },
        'references': [
            'https://docs.moodle.org/dev/Data_manipulation_API',
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'CWE-89: Improper Neutralization of Special Elements in SQL Command'
        ],
        'verify_payload': "'"  # Payload untuk verify fix
    },

    'XSS': {
        'summary': (
            "Cross-Site Scripting (XSS) memungkinkan attacker menyisipkan "
            "script berbahaya ke halaman yang dilihat pengguna lain. "
            "Di Moodle, XSS dapat digunakan untuk mencuri session token "
            "admin atau redirect pengguna ke halaman phishing."
        ),
        'steps': [
            "Gunakan format_string() dan format_text() Moodle untuk semua output user",
            "Aktifkan Content Security Policy (CSP) header di web server",
            "Gunakan s() function Moodle untuk encoding HTML entities",
            "Audit semua tempat output user-generated content",
            "Aktifkan Moodle's XSS filtering di Site Administration",
        ],
        'code_fix': (
            "// SEBELUM (Vulnerable):\n"
            "echo $user_input;\n\n"
            "// SESUDAH (Aman):\n"
            "echo s($user_input);           // HTML encode\n"
            "// atau untuk rich text:\n"
            "echo format_text($user_input, FORMAT_HTML, ['noclean' => false]);"
        ),
        'config_fix': {
            'apache': (
                "# .htaccess atau httpd.conf:\n"
                'Header always set Content-Security-Policy "default-src \'self\'; '
                'script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'"'
            ),
            'nginx': (
                "# nginx.conf:\n"
                'add_header Content-Security-Policy "default-src \'self\'";'
            ),
            'moodle': (
                "// config.php:\n"
                "// Aktifkan security headers via Moodle:\n"
                "$CFG->custommenuitems = '';  // Batasi menu items"
            ),
            'description': "Tambahkan Content-Security-Policy header untuk mencegah eksekusi script tidak sah"
        },
        'references': [
            'https://docs.moodle.org/dev/Output_functions',
            'https://owasp.org/www-community/attacks/xss/',
            'CWE-79: Improper Neutralization of Input During Web Page Generation'
        ],
        'verify_payload': '<script>alert(1)</script>'
    },

    'CSRF': {
        'summary': (
            "Cross-Site Request Forgery (CSRF) memungkinkan attacker "
            "memaksa pengguna yang sudah login untuk melakukan aksi "
            "tanpa sepengetahuan mereka. Di Moodle, ini dapat digunakan "
            "untuk mengubah password, mendaftarkan user ke kursus, "
            "atau mengubah settings sistem."
        ),
        'steps': [
            "Pastikan semua form menggunakan require_sesskey() Moodle",
            "Verifikasi sesskey di setiap action yang mengubah data",
            "Gunakan SameSite=Strict untuk MoodleSession cookie",
            "Aktifkan CSRF protection di Moodle security settings",
            "Audit semua form custom di plugin yang diinstall",
        ],
        'code_fix': (
            "// SEBELUM (Vulnerable):\n"
            "if ($data = data_submitted()) {\n"
            "    process_data($data);\n"
            "}\n\n"
            "// SESUDAH (Aman):\n"
            "if ($data = data_submitted()) {\n"
            "    require_sesskey();  // Validasi CSRF token\n"
            "    process_data($data);\n"
            "}\n\n"
            "// Di form HTML, tambahkan:\n"
            "echo '<input type=\"hidden\" name=\"sesskey\" value=\"'.sesskey().'\">';"
        ),
        'config_fix': {
            'moodle': (
                "// Site Administration → Security → HTTP Security:\n"
                "// Aktifkan: 'Only accept sesskey from form fields'\n"
                "// Aktifkan: 'Protect usernames'"
            ),
            'description': "Aktifkan strict sesskey validation di Moodle Security settings"
        },
        'references': [
            'https://docs.moodle.org/dev/Security/CSRF',
            'https://owasp.org/www-community/attacks/csrf',
            'CWE-352: Cross-Site Request Forgery'
        ],
        'verify_payload': None
    },

    'Path Traversal': {
        'summary': (
            "Path Traversal memungkinkan attacker mengakses file di luar "
            "direktori yang diizinkan, seperti /etc/passwd atau file "
            "konfigurasi sistem. Di Moodle, ini dapat mengekspos "
            "config.php yang berisi kredensial database."
        ),
        'steps': [
            "Validasi semua file path input menggunakan realpath()",
            "Gunakan allowlist untuk direktori yang diizinkan",
            "Aktifkan open_basedir di php.ini",
            "Pastikan file permissions Moodle sudah benar (data dir)",
            "Sembunyikan path server di error messages",
        ],
        'code_fix': (
            "// SEBELUM (Vulnerable):\n"
            "$file = $_GET['file'];\n"
            "include($moodleroot . '/' . $file);\n\n"
            "// SESUDAH (Aman):\n"
            "$file = basename($_GET['file']);\n"
            "$allowed_dir = $CFG->dataroot . '/uploads/';\n"
            "$full_path = realpath($allowed_dir . $file);\n"
            "if (strpos($full_path, $allowed_dir) !== 0) {\n"
            "    die('Access denied');\n"
            "}"
        ),
        'config_fix': {
            'php': (
                "; php.ini:\n"
                "open_basedir = /var/www/moodle:/var/moodledata:/tmp\n"
                "disable_functions = exec,passthru,shell_exec,system"
            ),
            'description': "Batasi PHP file access dengan open_basedir"
        },
        'references': [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'CWE-22: Improper Limitation of a Pathname'
        ],
        'verify_payload': '../../../etc/passwd'
    },

    'Missing Security Header': {
        'summary': (
            "Security header yang hilang melemahkan pertahanan browser "
            "terhadap berbagai serangan. Meskipun tidak langsung exploitable, "
            "ini meningkatkan attack surface dan melanggar best practice keamanan."
        ),
        'steps': [
            "Tambahkan X-Frame-Options, X-Content-Type-Options, X-XSS-Protection",
            "Aktifkan Strict-Transport-Security (HSTS) jika menggunakan HTTPS",
            "Konfigurasi Content-Security-Policy sesuai kebutuhan Moodle",
            "Aktifkan Referrer-Policy untuk kontrol informasi referrer",
        ],
        'code_fix': None,
        'config_fix': {
            'apache': (
                "# httpd.conf atau .htaccess:\n"
                "Header always set X-Frame-Options SAMEORIGIN\n"
                "Header always set X-Content-Type-Options nosniff\n"
                "Header always set X-XSS-Protection '1; mode=block'\n"
                "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'\n"
                "Header always set Referrer-Policy 'strict-origin-when-cross-origin'"
            ),
            'nginx': (
                "# nginx.conf:\n"
                "add_header X-Frame-Options SAMEORIGIN;\n"
                "add_header X-Content-Type-Options nosniff;\n"
                "add_header X-XSS-Protection '1; mode=block';\n"
                "add_header Strict-Transport-Security 'max-age=31536000';\n"
                "add_header Referrer-Policy 'strict-origin-when-cross-origin';"
            ),
            'description': "Tambahkan HTTP security headers di konfigurasi web server"
        },
        'references': [
            'https://owasp.org/www-project-secure-headers/',
            'https://docs.moodle.org/en/Security_recommendations'
        ],
        'verify_payload': None
    },

    'default': {
        'summary': (
            "Vulnerability ini memerlukan perhatian segera. "
            "Lakukan review kode dan implementasikan security best practices "
            "sesuai panduan OWASP untuk kategori ini."
        ),
        'steps': [
            "Review kode yang berhubungan dengan vulnerability ini",
            "Implementasikan input validation dan output encoding",
            "Ikuti Moodle Security Guidelines",
            "Lakukan security testing setelah fix",
        ],
        'code_fix': None,
        'config_fix': {
            'description': "Ikuti Moodle Security Recommendations di dokumentasi resmi"
        },
        'references': [
            'https://docs.moodle.org/en/Security',
            'https://owasp.org/www-project-top-ten/'
        ],
        'verify_payload': None
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# GPT CLIENT (with fallback)
# ─────────────────────────────────────────────────────────────────────────────
class GPTRecommendationClient:
    """
    OpenAI GPT client for dynamic security recommendations.
    Falls back to static templates if API unavailable or quota exceeded.
    """

    def __init__(self):
        self.api_key = os.environ.get('OPENAI_API_KEY', '')
        self.enabled = bool(self.api_key)
        self.model = 'gpt-4o-mini'  # cost-efficient model
        self.max_tokens = 600
        self._cache: Dict[str, str] = {}  # Cache by finding hash

        if self.enabled:
            print("[Recommendation Engine] GPT mode AKTIF (OpenAI API key ditemukan)")
        else:
            print("[Recommendation Engine] GPT mode NONAKTIF — menggunakan static templates")

    def get_recommendation(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Get AI-powered recommendation for a finding.
        Returns None if GPT unavailable (will fall back to static template).
        """
        if not self.enabled:
            return None

        # Cache key based on category + severity
        cache_key = hashlib.md5(
            f"{finding.get('category')}:{finding.get('severity')}:{finding.get('url', '')[:50]}".encode()
        ).hexdigest()

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            import httpx
            import asyncio

            prompt = self._build_prompt(finding)

            # Synchronous call using httpx (avoids async complexity)
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    'https://api.openai.com/v1/chat/completions',
                    headers={
                        'Authorization': f'Bearer {self.api_key}',
                        'Content-Type': 'application/json'
                    },
                    json={
                        'model': self.model,
                        'messages': [
                            {
                                'role': 'system',
                                'content': (
                                    'Kamu adalah security expert yang ahli di Moodle LMS security. '
                                    'Berikan rekomendasi remediasi yang spesifik, actionable, dan dalam Bahasa Indonesia. '
                                    'Format: 3-4 kalimat ringkas yang langsung ke solusi.'
                                )
                            },
                            {'role': 'user', 'content': prompt}
                        ],
                        'max_tokens': self.max_tokens,
                        'temperature': 0.3
                    }
                )

            if response.status_code == 200:
                data = response.json()
                recommendation = data['choices'][0]['message']['content'].strip()
                self._cache[cache_key] = recommendation
                print(f"[Recommendation Engine] GPT recommendation generated for {finding.get('category')}")
                return recommendation
            else:
                print(f"[Recommendation Engine] GPT API error {response.status_code} — fallback ke static template")
                return None

        except Exception as e:
            print(f"[Recommendation Engine] GPT error: {e} — fallback ke static template")
            return None

    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        """Build a contextual GPT prompt from finding data."""
        category = finding.get('category', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        url = finding.get('url', 'N/A')
        parameter = finding.get('parameter', 'N/A')
        evidence = str(finding.get('evidence', ''))[:300]

        return (
            f"Vulnerability ditemukan di Moodle LMS:\n"
            f"- Kategori: {category}\n"
            f"- Severity: {severity}\n"
            f"- URL: {url}\n"
            f"- Parameter: {parameter}\n"
            f"- Evidence: {evidence}\n\n"
            f"Berikan rekomendasi remediasi spesifik untuk Moodle dalam 3-4 kalimat. "
            f"Fokus pada solusi teknis yang bisa langsung diimplementasikan oleh Moodle admin."
        )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RECOMMENDATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class RecommendationEngine:
    """
    Central engine that enriches security findings with:
    - CVSS scoring
    - PoC structure
    - AI/static recommendations
    - Moodle config suggestions
    - Verify-fix metadata
    """

    def __init__(self):
        self.gpt_client = GPTRecommendationClient()

        # Import RiskScorer (CVSS v3.1 context-aware)
        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from risk.risk_scorer import RiskScorer
            self.risk_scorer = RiskScorer()
            print("[Recommendation Engine] RiskScorer loaded (CVSS v3.1 context-aware)")
        except Exception as e:
            print(f"[Recommendation Engine] RiskScorer unavailable ({e}) - static CVSS fallback")
            self.risk_scorer = None

        # Import SeverityPredictor (ML severity refinement)
        try:
            from ml.severity_predictor import SeverityPredictor
            self.severity_predictor = SeverityPredictor()
            mode = 'ML model' if self.severity_predictor.is_trained else 'heuristic'
            print(f"[Recommendation Engine] SeverityPredictor loaded ({mode} mode)")
        except Exception as e:
            print(f"[Recommendation Engine] SeverityPredictor unavailable ({e})")
            self.severity_predictor = None

        print("[Recommendation Engine] Initialized (L2-L7 pipeline active)")

    def enrich_finding(
        self,
        finding: Dict[str, Any],
        payload_used: Optional[str] = None,
        parameter: Optional[str] = None,
        method: str = 'GET',
        response_snippet: Optional[str] = None,
        response_status: int = 200,
    ) -> Dict[str, Any]:
        """
        Enrich a finding with CVSS, PoC, recommendation, and config suggestion.

        Args:
            finding: Raw finding from scanner
            payload_used: The actual payload that triggered the finding
            parameter: Vulnerable parameter name
            method: HTTP method used
            response_snippet: First 300 chars of response
            response_status: HTTP response status code

        Returns:
            Enriched finding dict
        """
        enriched = dict(finding)
        category = finding.get('category', 'default')
        # Support both 'url' and legacy 'target' key from payload_injector
        url = finding.get('url') or finding.get('target', '')
        enriched['url'] = url

        # Use payload/parameter from finding dict if already set by scanner
        if not payload_used:
            payload_used = finding.get('payload') or None
        if not parameter:
            parameter = finding.get('parameter') or finding.get('param_name') or None

        # -- 1. CVSS + Risk Score (via RiskScorer - context-aware CVSS v3.1) --
        if self.risk_scorer:
            try:
                risk_info = self.risk_scorer.calculate_risk_score(enriched)
                enriched['cvss_score']    = risk_info['cvss_score']
                enriched['cvss_vector']   = risk_info['cvss_vector']
                enriched['risk_score']    = risk_info['risk_score']
                enriched['priority']      = risk_info['priority']
                enriched['cvss_severity'] = risk_info['cvss_severity']
            except Exception as e:
                print(f"[Recommendation Engine] RiskScorer error: {e}")
                cvss_data = self._get_cvss(category)
                enriched['cvss_score']  = cvss_data['score']
                enriched['cvss_vector'] = cvss_data['vector']
                enriched['risk_score']  = round(cvss_data['score'] * 10, 1)
        else:
            cvss_data = self._get_cvss(category)
            enriched['cvss_score']  = cvss_data['score']
            enriched['cvss_vector'] = cvss_data['vector']
            enriched['risk_score']  = round(cvss_data['score'] * 10, 1)

        # Override severity from scanner if CVSS says it should be higher
        if not enriched.get('severity') or enriched['severity'] in ('Info', 'Low'):
            cvss_sev = enriched.get('cvss_severity') or self._get_cvss(category).get('severity', 'Medium')
            enriched['severity'] = cvss_sev

        # -- 1b. Severity Refinement via SeverityPredictor (ML/heuristic) --
        if self.severity_predictor:
            try:
                predicted_sev, confidence, _ = self.severity_predictor.predict(enriched)
                sev_order   = ['info', 'low', 'medium', 'high', 'critical']
                scanner_sev = (enriched.get('severity') or 'info').lower()
                pred_idx    = sev_order.index(predicted_sev) if predicted_sev in sev_order else 2
                scan_idx    = sev_order.index(scanner_sev)   if scanner_sev  in sev_order else 2
                if confidence > 0.55 and pred_idx > scan_idx:
                    enriched['severity']            = predicted_sev.capitalize()
                    enriched['severity_predicted']  = True
                    enriched['severity_confidence'] = round(confidence, 3)
                else:
                    enriched['severity_predicted']  = False
                    enriched['severity_confidence'] = round(confidence, 3)
            except Exception as e:
                print(f"[Recommendation Engine] SeverityPredictor error: {e}")
                enriched['severity_predicted'] = False
        else:
            enriched['severity_predicted'] = False

        # ── 2. Parameter info ─────────────────────────────────────────────────
        if parameter:
            enriched['parameter'] = parameter

        # ── 3. PoC Structure ─────────────────────────────────────────────────
        enriched['poc'] = self._build_poc(
            finding=enriched,
            payload_used=payload_used,
            parameter=parameter,
            method=method,
            response_snippet=response_snippet,
            response_status=response_status,
        )

        # ── 4. Dynamic/Static Recommendation ─────────────────────────────────
        gpt_recommendation = self.gpt_client.get_recommendation(enriched)
        template = self._get_template(category)

        if gpt_recommendation:
            # GPT available — prepend GPT then static steps
            enriched['recommendation'] = gpt_recommendation
            enriched['recommendation_source'] = 'gpt'
        else:
            # Static fallback
            enriched['recommendation'] = template['summary']
            enriched['recommendation_source'] = 'static'

        enriched['remediation_steps'] = template['steps']
        enriched['code_fix'] = template.get('code_fix')
        enriched['references'] = template.get('references', [])

        # ── 5. Config Suggestion (L6) ─────────────────────────────────────────
        if template.get('config_fix'):
            enriched['config_fix'] = template['config_fix']

        # ── 6. Verify-Fix Metadata (L7) ───────────────────────────────────────
        verify_payload = template.get('verify_payload')
        if verify_payload and parameter and url:
            enriched['verify_fix'] = {
                'can_auto_verify': True,
                'verify_url': url,
                'verify_parameter': parameter,
                'verify_payload': verify_payload,
                'verify_method': method,
                'status': 'open',  # open | fixed | verified_fixed
                'last_verified': None,
            }
        else:
            enriched['verify_fix'] = {
                'can_auto_verify': False,
                'status': 'open',
                'manual_verify_note': 'Verifikasi manual diperlukan untuk kategori ini',
            }

        # ── 7. Timestamp ──────────────────────────────────────────────────────
        enriched['enriched_at'] = datetime.utcnow().isoformat() + 'Z'

        return enriched

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _get_cvss(self, category: str) -> Dict[str, Any]:
        """Get CVSS data for a vulnerability category."""
        for key, data in CVSS_MAP.items():
            if key.lower() in category.lower():
                return data
        return {'score': 3.0, 'severity': 'Low',
                'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'rationale': 'Default score - manual review required'}

    def _get_template(self, category: str) -> Dict[str, Any]:
        """Get static template for a vulnerability category."""
        for key, template in STATIC_TEMPLATES.items():
            if key == 'default':
                continue
            if key.lower() in category.lower():
                return template
        return STATIC_TEMPLATES['default']

    def _build_poc(
        self,
        finding: Dict[str, Any],
        payload_used: Optional[str],
        parameter: Optional[str],
        method: str,
        response_snippet: Optional[str],
        response_status: int,
    ) -> Dict[str, Any]:
        """Build structured Proof of Concept from finding data."""
        url = finding.get('url', 'N/A')
        category = finding.get('category', 'Unknown')
        evidence = str(finding.get('evidence', ''))[:300]
        template = self._get_template(category)

        poc: Dict[str, Any] = {}

        # Request info
        poc['request'] = {
            'url': url,
            'method': method,
            'parameter': parameter or 'N/A',
            'payload': payload_used or 'Pattern detected in response',
        }

        # Response info
        poc['response'] = {
            'status_code': response_status,
            'evidence_snippet': response_snippet or evidence,
        }

        # Reproduction steps
        steps = []
        if url and url != 'N/A':
            steps.append(f"1. Navigasi ke: {url}")
        if parameter and payload_used:
            steps.append(f"2. Inject payload ke parameter '{parameter}': {payload_used[:80]}")
            steps.append(f"3. Kirim request dengan method {method}")
            steps.append(f"4. Observasi response: {evidence[:100]}")
        else:
            steps.append(f"2. Observasi evidence: {evidence[:100]}")
        steps.append("5. Vulnerability dikonfirmasi jika response sesuai pattern yang dideteksi")

        poc['steps'] = steps

        # Fix code from template
        if template.get('code_fix'):
            poc['fix_code'] = template['code_fix']

        return poc

    def bulk_enrich(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple findings. Used by scanner_engine."""
        enriched = []
        for finding in findings:
            try:
                e = self.enrich_finding(finding)
                enriched.append(e)
            except Exception as ex:
                print(f"[Recommendation Engine] Warning: enrich failed for {finding.get('category')}: {ex}")
                enriched.append(finding)  # Return original if enrich fails
        return enriched
