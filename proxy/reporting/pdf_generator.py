"""
PDF Report Generator for Security Scan Results

Generates professional PDF reports with charts and compliance mappings.
"""

from datetime import datetime
from typing import Dict, Any, List
from io import BytesIO
import json


class PDFReportGenerator:
    """Generate PDF reports from scan results."""
    
    def __init__(self):
        """Initialize PDF generator."""
        self.page_width = 595  # A4 width in points
        self.page_height = 842  # A4 height in points
        self.margin = 50
    
    def generate_executive_summary(self, scan_data: Dict[str, Any]) -> bytes:
        """
        Generate executive summary PDF.
        
        Args:
            scan_data: Scan results data
            
        Returns:
            PDF bytes
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.platypus import Image as RLImage
            from reportlab.graphics.shapes import Drawing
            from reportlab.graphics.charts.piecharts import Pie
        except ImportError:
            return self._generate_text_report(scan_data)
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=1  # Center
        )
        
        elements.append(Paragraph("Security Scan Executive Summary", title_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Scan Information
        info_data = [
            ['Scan ID:', scan_data.get('scan_id', 'N/A')],
            ['Scan Date:', scan_data.get('timestamp', 'N/A')],
            ['Target:', scan_data.get('target_url', 'N/A')],
            ['Endpoints Scanned:', str(scan_data.get('endpoints_scanned', 0))],
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Vulnerability Summary
        elements.append(Paragraph("Vulnerability Summary", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = scan_data.get('summary', {})
        summary_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(summary.get('critical', 0)), self._calc_percentage(summary.get('critical', 0), scan_data.get('total_findings', 1))],
            ['High', str(summary.get('high', 0)), self._calc_percentage(summary.get('high', 0), scan_data.get('total_findings', 1))],
            ['Medium', str(summary.get('medium', 0)), self._calc_percentage(summary.get('medium', 0), scan_data.get('total_findings', 1))],
            ['Low', str(summary.get('low', 0)), self._calc_percentage(summary.get('low', 0), scan_data.get('total_findings', 1))],
            ['Info', str(summary.get('info', 0)), self._calc_percentage(summary.get('info', 0), scan_data.get('total_findings', 1))],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90e2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Top Risks
        if scan_data.get('top_risks'):
            elements.append(Paragraph("Top 10 Critical Findings", styles['Heading2']))
            elements.append(Spacer(1, 0.2*inch))
            
            risk_data = [['Priority', 'Severity', 'Category', 'Risk Score']]
            
            for finding in scan_data['top_risks'][:10]:
                risk_data.append([
                    str(finding.get('priority', 'N/A')),
                    finding.get('severity', 'N/A'),
                    finding.get('category', 'N/A'),
                    str(finding.get('risk_score', 0))
                ])
            
            risk_table = Table(risk_data, colWidths=[1*inch, 1.5*inch, 2*inch, 1.5*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e74c3c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            
            elements.append(risk_table)
        
        # Detailed Findings with PoC
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("Detailed Findings", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        findings = scan_data.get('findings', [])
        for i, finding in enumerate(findings[:10], 1):  # Limit to top 10 for executive summary
            elements.append(Paragraph(f"Finding #{i}: {finding.get('category', 'Unknown')}", styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Basic finding info
            finding_details = [
                ['Severity:', finding.get('severity', 'N/A')],
                ['Description:', finding.get('description', 'N/A')],
                ['Evidence:', str(finding.get('evidence', 'N/A'))[:200] + '...'],
            ]
            if 'recommendation' in finding:
                finding_details.append(['Recommendation:', finding.get('recommendation', 'N/A')])
            
            detail_table = Table(finding_details, colWidths=[1.5*inch, 4.5*inch])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            elements.append(detail_table)
            elements.append(Spacer(1, 0.15*inch))
            
            # Add PoC if available
            if 'poc' in finding:
                poc_data = finding['poc']
                elements.append(Paragraph("<b>Proof of Concept (PoC)</b>", styles['Heading4']))
                elements.append(Spacer(1, 0.1*inch))
                
                # Request
                if poc_data.get('request'):
                    req = poc_data['request']
                    elements.append(Paragraph("<b>Request:</b>", styles['Normal']))
                    req_info = [
                        ['Method:', req.get('method', 'N/A')],
                        ['URL:', req.get('url', 'N/A')],
                    ]
                    req_table = Table(req_info, colWidths=[1*inch, 5*inch])
                    req_table.setStyle(TableStyle([
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('FONTNAME', (1, 0), (1, -1), 'Courier')
                    ]))
                    elements.append(req_table)
                    elements.append(Spacer(1, 0.1*inch))
                
                # Response
                if poc_data.get('response'):
                    resp = poc_data['response']
                    elements.append(Paragraph("<b>Response:</b>", styles['Normal']))
                    resp_info = [['Status:', str(resp.get('status_code', 'N/A'))]]
                    resp_table = Table(resp_info, colWidths=[1*inch, 5*inch])
                    resp_table.setStyle(TableStyle([
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                    ]))
                    elements.append(resp_table)
                    elements.append(Spacer(1, 0.1*inch))
                
                # Steps
                if poc_data.get('steps'):
                    elements.append(Paragraph("<b>Reproduction Steps:</b>", styles['Normal']))
                    for step_num, step in enumerate(poc_data['steps'], 1):
                        elements.append(Paragraph(f"{step_num}. {step}", styles['Normal']))
                    elements.append(Spacer(1, 0.1*inch))
                
                # Fix code
                if poc_data.get('fix_code'):
                    elements.append(Paragraph("<b>Fix:</b>", styles['Normal']))
                    elements.append(Paragraph(f"<font name='Courier' size='7'>{poc_data['fix_code'][:300]}</font>", styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("Recommendations", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        recommendations = self._generate_recommendations(scan_data)
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        # Build PDF
        doc.build(elements)
        
        return buffer.getvalue()
    
    def generate_compliance_report(self, scan_data: Dict[str, Any], 
                                   framework: str = "OWASP") -> bytes:
        """
        Generate compliance report mapped to security framework.
        
        Args:
            scan_data: Scan results
            framework: Compliance framework (OWASP, PCI-DSS, etc.)
            
        Returns:
            PDF bytes
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        except ImportError:
            return self._generate_text_report(scan_data)
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        elements.append(Paragraph(f"{framework} Compliance Report", styles['Title']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Compliance mapping
        mappings = self._get_compliance_mappings(scan_data, framework)
        
        elements.append(Paragraph("Compliance Status", styles['Heading2']))
        elements.append(Spacer(1, 0.2*inch))
        
        mapping_data = [['Control ID', 'Description', 'Status', 'Findings']]
        
        for mapping in mappings:
            mapping_data.append([
                mapping['control_id'],
                mapping['description'],
                mapping['status'],
                str(mapping['findings_count'])
            ])
        
        mapping_table = Table(mapping_data, colWidths=[1*inch, 3*inch, 1*inch, 1*inch])
        mapping_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        
        elements.append(mapping_table)
        
        doc.build(elements)
        return buffer.getvalue()
    
    def generate_detailed_report(self, scan_data: Dict[str, Any]) -> bytes:
        """
        Generate detailed technical report with all findings.
        
        Args:
            scan_data: Complete scan results
            
        Returns:
            PDF bytes
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        except ImportError:
            return self._generate_text_report(scan_data)
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        elements.append(Paragraph("Detailed Security Scan Report", styles['Title']))
        elements.append(Spacer(1, 0.3*inch))
        
        # All findings
        findings = scan_data.get('findings', [])
        
        for i, finding in enumerate(findings, 1):
            elements.append(Paragraph(f"Finding #{i}: {finding.get('category', 'Unknown')}", styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            finding_details = [
                ['Severity:', finding.get('severity', 'N/A')],
                ['CVSS Score:', str(finding.get('cvss_score', 0))],
                ['Risk Score:', str(finding.get('risk_score', 0))],
                ['Priority:', str(finding.get('priority', 'N/A'))],
                ['Description:', finding.get('description', 'N/A')],
                ['Evidence:', finding.get('evidence', 'N/A')[:200] + '...'],
                ['Recommendation:', finding.get('recommendation', 'N/A')],
            ]
            
            detail_table = Table(finding_details, colWidths=[1.5*inch, 4.5*inch])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            elements.append(detail_table)
            elements.append(Spacer(1, 0.15*inch))
            
            # Add Proof of Concept (PoC) section
            poc_data = finding.get('poc', {})
            if poc_data:
                elements.append(Paragraph("<b>Proof of Concept (PoC)</b>", styles['Heading4']))
                elements.append(Spacer(1, 0.1*inch))
                
                # Request details
                if poc_data.get('request'):
                    req = poc_data['request']
                    elements.append(Paragraph("<b>Request:</b>", styles['Normal']))
                    request_info = [
                        ['Method:', req.get('method', 'N/A')],
                        ['URL:', req.get('url', 'N/A')],
                        ['Headers:', self._format_dict(req.get('headers', {}))],
                    ]
                    if req.get('body'):
                        request_info.append(['Body:', str(req.get('body', ''))[:200] + '...'])
                    
                    req_table = Table(request_info, colWidths=[1*inch, 5*inch])
                    req_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.Color(0.95, 0.95, 0.95)),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (1, 0), (1, -1), 'Courier')
                    ]))
                    elements.append(req_table)
                    elements.append(Spacer(1, 0.1*inch))
                
                # Response details
                if poc_data.get('response'):
                    resp = poc_data['response']
                    elements.append(Paragraph("<b>Response:</b>", styles['Normal']))
                    response_info = [
                        ['Status Code:', str(resp.get('status_code', 'N/A'))],
                        ['Headers:', self._format_dict(resp.get('headers', {}))],
                    ]
                    if resp.get('body'):
                        response_info.append(['Body Snippet:', str(resp.get('body', ''))[:300] + '...'])
                    
                    resp_table = Table(response_info, colWidths=[1*inch, 5*inch])
                    resp_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.Color(0.95, 0.95, 0.95)),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('FONTNAME', (1, 0), (1, -1), 'Courier')
                    ]))
                    elements.append(resp_table)
                    elements.append(Spacer(1, 0.1*inch))
                
                # Reproduction steps
                if poc_data.get('steps'):
                    elements.append(Paragraph("<b>Reproduction Steps:</b>", styles['Normal']))
                    for step_num, step in enumerate(poc_data['steps'], 1):
                        elements.append(Paragraph(f"{step_num}. {step}", styles['Normal']))
                    elements.append(Spacer(1, 0.1*inch))
                
                # Fix code snippet
                if poc_data.get('fix_code'):
                    elements.append(Paragraph("<b>Recommended Fix:</b>", styles['Normal']))
                    fix_code = Paragraph(f"<font name='Courier' size='8'>{poc_data['fix_code']}</font>", styles['Code'])
                    elements.append(fix_code)
            
            elements.append(Spacer(1, 0.2*inch))
            
            if i % 5 == 0:  # Page break every 5 findings
                elements.append(PageBreak())
        
        doc.build(elements)
        return buffer.getvalue()
    
    def _generate_text_report(self, scan_data: Dict[str, Any]) -> bytes:
        """Generate simple text report if reportlab not available."""
        report = []
        report.append("=" * 80)
        report.append("SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"\nScan ID: {scan_data.get('scan_id', 'N/A')}")
        report.append(f"Timestamp: {scan_data.get('timestamp', 'N/A')}")
        report.append(f"Target: {scan_data.get('target_url', 'N/A')}")
        report.append(f"\nTotal Findings: {scan_data.get('total_findings', 0)}")
        
        summary = scan_data.get('summary', {})
        report.append(f"\nCritical: {summary.get('critical', 0)}")
        report.append(f"High: {summary.get('high', 0)}")
        report.append(f"Medium: {summary.get('medium', 0)}")
        report.append(f"Low: {summary.get('low', 0)}")
        report.append(f"Info: {summary.get('info', 0)}")
        
        report.append("\n" + "=" * 80)
        
        return '\n'.join(report).encode('utf-8')
    
    def _calc_percentage(self, count: int, total: int) -> str:
        """Calculate percentage."""
        if total == 0:
            return "0%"
        return f"{(count / total * 100):.1f}%"
    
    def _format_dict(self, data: Dict[str, Any]) -> str:
        """Format dictionary for display in PDF."""
        if not data:
            return "N/A"
        # Format as key: value pairs, limit to important headers
        formatted = []
        for key, value in list(data.items())[:5]:  # Limit to 5 items
            formatted.append(f"{key}: {value}")
        if len(data) > 5:
            formatted.append(f"... and {len(data) - 5} more")
        return "\n".join(formatted)
    
    def _generate_recommendations(self, scan_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        summary = scan_data.get('summary', {})
        
        if summary.get('critical', 0) > 0:
            recommendations.append("CRITICAL: Address critical vulnerabilities immediately within 24 hours")
        
        if summary.get('high', 0) > 0:
            recommendations.append("HIGH: Fix high-severity issues within 1 week")
        
        if summary.get('medium', 0) > 5:
            recommendations.append("MEDIUM: Plan remediation for medium-severity findings within 1 month")
        
        recommendations.append("Implement regular security scanning (weekly recommended)")
        recommendations.append("Enable automated vulnerability tracking and alerting")
        recommendations.append("Conduct security awareness training for development team")
        
        return recommendations
    
    def _get_compliance_mappings(self, scan_data: Dict[str, Any], 
                                 framework: str) -> List[Dict[str, Any]]:
        """Map findings to compliance framework controls."""
        if framework == "OWASP":
            return self._map_to_owasp(scan_data)
        elif framework == "PCI-DSS":
            return self._map_to_pci_dss(scan_data)
        else:
            return []
    
    def _map_to_owasp(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map to OWASP Top 10."""
        findings = scan_data.get('findings', [])
        
        mappings = [
            {
                'control_id': 'A03:2021',
                'description': 'Injection',
                'status': 'FAIL' if any(f.get('category') == 'SQL Injection' for f in findings) else 'PASS',
                'findings_count': sum(1 for f in findings if f.get('category') == 'SQL Injection')
            },
            {
                'control_id': 'A07:2021',
                'description': 'Cross-Site Scripting (XSS)',
                'status': 'FAIL' if any('XSS' in f.get('category', '') for f in findings) else 'PASS',
                'findings_count': sum(1 for f in findings if 'XSS' in f.get('category', ''))
            },
            {
                'control_id': 'A01:2021',
                'description': 'Broken Access Control',
                'status': 'FAIL' if any(f.get('category') == 'Access Control' for f in findings) else 'PASS',
                'findings_count': sum(1 for f in findings if f.get('category') == 'Access Control')
            },
        ]
        
        return mappings
    
    def _map_to_pci_dss(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map to PCI-DSS requirements."""
        findings = scan_data.get('findings', [])
        
        mappings = [
            {
                'control_id': '6.5.1',
                'description': 'Injection flaws',
                'status': 'FAIL' if any(f.get('category') == 'SQL Injection' for f in findings) else 'PASS',
                'findings_count': sum(1 for f in findings if f.get('category') == 'SQL Injection')
            },
            {
                'control_id': '6.5.7',
                'description': 'Cross-site scripting (XSS)',
                'status': 'FAIL' if any('XSS' in f.get('category', '') for f in findings) else 'PASS',
                'findings_count': sum(1 for f in findings if 'XSS' in f.get('category', ''))
            },
        ]
        
        return mappings


# Example usage
if __name__ == "__main__":
    generator = PDFReportGenerator()
    
    sample_data = {
        'scan_id': 'scan_20251118_001',
        'timestamp': datetime.utcnow().isoformat(),
        'target_url': 'http://localhost:8998',
        'endpoints_scanned': 20,
        'total_findings': 10,
        'summary': {
            'critical': 0,
            'high': 2,
            'medium': 5,
            'low': 2,
            'info': 1
        },
        'top_risks': [
            {
                'priority': 1,
                'severity': 'High',
                'category': 'SQL Injection',
                'risk_score': 9.5,
                'cvss_score': 8.0
            }
        ],
        'findings': []
    }
    
    # Generate executive summary
    pdf_bytes = generator.generate_executive_summary(sample_data)
    
    with open('executive_summary.pdf', 'wb') as f:
        f.write(pdf_bytes)
    
    print("PDF generated successfully!")
