"""
DATA PROVENANCE AUDIT — Phase 5 Training Data
Run from /proxy: python data_provenance_audit.py
Answers: where do 86 samples come from, column names, first 5 rows.
"""
import sys, os, csv, random
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
random.seed(42)
np.random.seed(42)

proxy_dir = os.path.dirname(os.path.abspath(__file__))
candidates = [
    os.path.join(proxy_dir, 'ml', 'training_data', 'phase3_balanced_dataset_FINAL.csv'),
    'ml/training_data/phase3_balanced_dataset_FINAL.csv',
    '../ml/training_data/phase3_balanced_dataset_FINAL.csv',
]
csv_path = next((p for p in candidates if os.path.exists(p)), None)
if not csv_path:
    print("[ERROR] phase3_balanced_dataset_FINAL.csv not found"); sys.exit(1)

rows = []
with open(csv_path) as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    for row in reader:
        rows.append(row)

attacks = [r for r in rows if float(r['label']) == 1.0]
normals = [r for r in rows if float(r['label']) == 0.0]

print("=" * 70)
print("DATA PROVENANCE AUDIT — Phase 5 Training Data")
print("=" * 70)

# ── Q1: Where do the 86 samples come from? ───────────────────────
print("""
QUESTION 1: Where do the 86 samples come from?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Source A: phase3_balanced_dataset_FINAL.csv  →  76 rows
  - Attack rows (label=1.0): rows from real HTTP Attack traffic captured in HAR
  - Normal rows (label=0.0): rows from real HTTP Normal traffic captured in HAR
  - Origin: HAR files captured during Moodle penetration test (Phase 3)
  - Format: REQUEST-LEVEL features (HTTP-level, not finding-level)
""")
print(f"  Loaded: {len(rows)} rows from CSV")
print(f"    Attack rows  : {len(attacks)}")
print(f"    Normal rows  : {len(normals)}")

print("""
Source B: Manual annotations  →  10 rows
  - 5 manually confirmed True Positives  (SQLi, XSS, CSRF)
  - 5 manually confirmed False Positives (headers, input fields, version)
  - Format: FINDING-LEVEL (scanner output format)
  - Origin: Actual scanner run output, human-verified

TOTAL: 76 (HAR) + 10 (manual) = 86 samples
""")

# ── Q2: Column names in the CSV ───────────────────────────────────
print("QUESTION 2: Actual column names in phase3_balanced_dataset_FINAL.csv")
print("━" * 70)
print(f"\n  CSV has {len(fieldnames)} columns:")
for i, col in enumerate(fieldnames, 1):
    sample_val = rows[0].get(col, 'N/A')
    print(f"  {i:2}. {col:<30} (example: {sample_val})")

print("""
  → These are REQUEST-LEVEL features (HTTP traffic level)
  → NOT the same as finding-level features used by the ML model
""")

# ── Q3: How are finding-level features generated? ─────────────────
print("QUESTION 3: How finding-level features are generated from HAR data")
print("━" * 70)
print("""
  PIPELINE (har_to_finding function in retrain_fp_reducer.py):

  HAR row (request-level)        →  Finding dict (finding-level)
  ─────────────────────────────────────────────────────────────
  row['label'] == 1.0            →  Template: TP_TEMPLATES (random.choice)
  row['label'] == 0.0            →  Template: FP_TEMPLATES (random.choice)
  
  row['response_status']         →  context['status_code']
  row['request_time_ms']         →  context['response_time']
  row['db_error_visible']        →  appended to evidence string
  row['payload_reflected']       →  appended to evidence string
  row['error_leaked']            →  appended to evidence string
  row['response_size']           →  appended to evidence string

  Template-derived (from random.choice of fixed lists):
    finding['severity']          →  e.g. 'Critical', 'High', 'Medium', 'Info'
    finding['category']          →  e.g. 'SQL Injection', 'XSS'
    finding['description']       →  e.g. 'SQL Injection detected in parameter'
    finding['evidence']          →  base + HAR-derived additions
    finding['url']               →  random.choice(MOODLE_ATTACK/NORMAL_URLS)
    finding['cvss_score']        →  0 (NEUTRALIZED — Phase 0 methodology)
    finding['risk_score']        →  0 (NEUTRALIZED — Phase 0 methodology)

  LABEL ASSIGNMENT:
    HAR attack row  (label=1.0)  →  ML label 0 (True Positive)
    HAR normal row  (label=0.0)  →  ML label 1 (False Positive)
    Note: Label inversion is intentional (FP Reducer: 0=TP, 1=FP)
""")

# ── Q4: First 5 rows of CSV ───────────────────────────────────────
print("QUESTION 4: First 5 rows of phase3_balanced_dataset_FINAL.csv")
print("━" * 70)
print("\n  [RAW CSV — REQUEST-LEVEL format]\n")

for i, row in enumerate(rows[:5], 1):
    print(f"  Row {i}:")
    for col in fieldnames:
        print(f"    {col:<30}: {row[col]}")
    print()

# ── Show what the model actually receives ─────────────────────────
print("  [TRANSFORMED — what extract_features() receives for Row 1]\n")
from ml.anomaly_false_positive_reducer import FalsePositiveReducer

reducer = FalsePositiveReducer()

# Simulate har_to_finding for row 0 (attack)
row = rows[0]
is_attack = float(row['label']) == 1.0

TP_TEMPLATES = [
    {'severity': 'Critical', 'category': 'SQL Injection',
     'desc': 'SQL Injection detected in parameter via payload injection',
     'evidence_base': 'SQL error pattern found after injecting payload. Error writing to database.'},
]
FP_TEMPLATES = [
    {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Found input field(s) - verify XSS protection on each field',
     'evidence_base': 'Input fields detected. Ensure proper output encoding.'},
]

status = int(float(row['response_status']))
time_ms = float(row['request_time_ms'])
db_err = float(row['db_error_visible'])
pay_ref = float(row['payload_reflected'])
err_leak = float(row['error_leaked'])
resp_sz = float(row['response_size'])

tmpl = TP_TEMPLATES[0] if is_attack else FP_TEMPLATES[0]
evidence = tmpl['evidence_base']
if db_err: evidence += ' Database error visible.'
if pay_ref: evidence += ' Payload reflected.'
if err_leak: evidence += f' Error leaked ({resp_sz:.0f} bytes).'

finding = {'severity': tmpl['severity'], 'category': tmpl['category'],
           'description': tmpl['desc'], 'evidence': evidence,
           'url': 'http://localhost:8999/login/index.php',
           'cvss_score': 0, 'risk_score': 0}
context = {'status_code': status, 'response_time': time_ms,
           'occurrence_count': 1, 'days_since_first_seen': 0}

feat_vec = reducer.extract_features(finding, context).flatten()

CLEAN_FEATURES = [
    'severity', 'category', 'evidence_length', 'description_length',
    'url_complexity', 'has_params', 'cvss_score', 'risk_score',
    'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio',
    'is_informational', 'status_code', 'response_time'
]

print(f"  HAR source: label={row['label']} → ML label={'TP(0)' if is_attack else 'FP(1)'}")
print(f"  Finding dict:")
for k, v in finding.items():
    print(f"    {k:<15}: {v}")
print(f"  Context: status={context['status_code']}, time={context['response_time']}ms")
print(f"\n  Feature vector ({len(feat_vec)} values):")
for name, val in zip(CLEAN_FEATURES, feat_vec):
    print(f"    {name:<25}: {val:.4f}")

# ── Summary for thesis ────────────────────────────────────────────
print("\n" + "=" * 70)
print("THESIS DATA PROVENANCE SUMMARY")
print("=" * 70)
print(f"""
Training Data Composition (Phase 5 Clean-14):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Source 1: HAR files (Phase 3 penetration test)
    File   : phase3_balanced_dataset_FINAL.csv
    Rows   : {len(rows)} (38 attack + 38 normal HTTP requests)
    Format : Request-level (HTTP traffic features)
    Origin : Moodle penetration test, HAR captured via browser proxy
    
  Source 2: Manual expert annotations
    Rows   : 10 (5 TP + 5 FP)
    Format : Finding-level (scanner output)
    Origin : Actual scanner run, human-verified by researcher

  TOTAL  : 86 samples (43 TP + 43 FP, balanced)

Feature Engineering:
━━━━━━━━━━━━━━━━━━━
  HAR rows are TRANSFORMED via har_to_finding():
  - Label (attack/normal) selects finding template (TP/FP class)
  - HAR HTTP features (response_time, status_code, db_error, etc.)
    are mapped to finding context
  - Finding text (description, evidence, category, severity) is
    generated from expert-written templates, enriched with HAR signals
  - This creates FINDING-LEVEL features matching production scanner output
  
  Key design decision: templates are intentionally varied (8 TP + 8 FP)
  with OVERLAPPING severity (borderline cases) to prevent severity-only
  shortcuts (Phase 5 shortcut analysis result: severity = 88.2% stump).

Feature Vector (14 features, Clean-14):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1-2  : severity, category (expert knowledge encoding)
  3-6  : evidence/desc length, url_complexity, has_params (text features)
  7-8  : cvss_score=0, risk_score=0 (neutralized, Phase 0 methodology)
  9-12 : keyword features (OWASP/SANS expert patterns)
  13-14: status_code, response_time (from HAR → context mapping)
  [REMOVED]: occurrence_count (95.3% single-feature → shortcut)
  [REMOVED]: days_since_first_seen (correlated, d=1.53)
""")
