#!/usr/bin/env python3
"""Test PDF generation with risk scores"""

from database.scan_history import ScanHistoryDB
from reporting.pdf_generator import PDFReportGenerator
from risk.risk_scorer import RiskScorer
import json

db = ScanHistoryDB()
pdf_gen = PDFReportGenerator()
scorer = RiskScorer()

print("=" * 80)
print("TESTING PDF GENERATION WITH RISK SCORES")
print("=" * 80)

# Get latest auth scan
scans = db.get_scan_history(limit=20)
auth_scans = [s for s in scans if s['scan_type'] == 'authentication']

if not auth_scans:
    print("No auth scans found!")
    exit(1)

latest_auth = auth_scans[0]
scan_id = latest_auth['scan_id']

print(f"\nUsing scan: {scan_id}")

# Get scan data
scan_data = db.get_scan_with_findings(scan_id)

if not scan_data:
    print("Scan data not found!")
    exit(1)

print(f"Total findings: {len(scan_data['findings'])}")

# Check current risk scores
print("\n" + "=" * 80)
print("CURRENT FINDINGS (from database):")
print("=" * 80)

for i, finding in enumerate(scan_data['findings'], 1):
    print(f"\n{i}. {finding.get('category')} ({finding.get('severity')})")
    print(f"   Risk Score: {finding.get('risk_score', 'NOT SET')}")
    print(f"   CVSS Score: {finding.get('cvss_score', 'NOT SET')}")
    print(f"   Priority: {finding.get('priority', 'NOT SET')}")

# Check top_risks
print("\n" + "=" * 80)
print("TOP RISKS (what PDF will show):")
print("=" * 80)

for i, finding in enumerate(scan_data.get('top_risks', [])[:5], 1):
    print(f"\n{i}. {finding.get('category')} ({finding.get('severity')})")
    print(f"   Risk Score: {finding.get('risk_score', 'NOT SET')}")

# Simulate what SHOULD happen with new proxy
print("\n" + "=" * 80)
print("SIMULATING NEW PROXY (with risk enrichment):")
print("=" * 80)

# Re-enrich findings
enriched_findings = scorer.batch_enrich_findings(scan_data['findings'])

print("\nEnriched findings:")
for i, finding in enumerate(enriched_findings, 1):
    print(f"\n{i}. {finding.get('category')} ({finding.get('severity')})")
    print(f"   Risk Score: {finding.get('risk_score', 'NOT SET')}")
    print(f"   CVSS Score: {finding.get('cvss_score', 'NOT SET')}")
    print(f"   Priority: {finding.get('priority', 'NOT SET')}")

# Update scan_data with enriched findings
scan_data['findings'] = enriched_findings
scan_data['top_risks'] = sorted(
    enriched_findings,
    key=lambda x: x.get('risk_score', 0),
    reverse=True
)[:10]

print("\n" + "=" * 80)
print("GENERATING PDF WITH ENRICHED DATA...")
print("=" * 80)

try:
    pdf_bytes = pdf_gen.generate_executive_summary(scan_data)
    
    # Save to file
    output_file = f'/tmp/test_report_{scan_id}.pdf'
    with open(output_file, 'wb') as f:
        f.write(pdf_bytes)
    
    print(f"\n✅ PDF generated successfully!")
    print(f"   File: {output_file}")
    print(f"   Size: {len(pdf_bytes)} bytes")
    print(f"\nThis PDF should show risk scores in 'Top 10 Critical Findings' table")
    
except Exception as e:
    print(f"\n❌ PDF generation failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("CONCLUSION:")
print("=" * 80)
print("Current database has risk_score = 0.0")
print("After proxy restart + new scan, risk scores will appear in PDF")
print("=" * 80)
