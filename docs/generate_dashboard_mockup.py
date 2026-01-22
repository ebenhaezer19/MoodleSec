#!/usr/bin/env python3
"""
Generate Dashboard Mockup for MoodleSec
Creates professional PNG mockups for PowerPoint presentation
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Rectangle, Circle
import numpy as np
from datetime import datetime, timedelta

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Arial', 'DejaVu Sans']

def create_main_dashboard():
    """Create main monitoring dashboard mockup."""
    fig = plt.figure(figsize=(16, 10), dpi=150)
    fig.patch.set_facecolor('#f5f5f5')
    
    # Title bar
    ax_title = plt.subplot2grid((20, 3), (0, 0), colspan=3, rowspan=1)
    ax_title.axis('off')
    ax_title.add_patch(Rectangle((0, 0), 1, 1, facecolor='#2c3e50', transform=ax_title.transAxes))
    ax_title.text(0.02, 0.5, '🛡️ MoodleSec - Security Monitoring Dashboard', 
                  color='white', fontsize=20, fontweight='bold', 
                  transform=ax_title.transAxes, va='center')
    ax_title.text(0.98, 0.5, f'Last Update: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 
                  color='#ecf0f1', fontsize=10, 
                  transform=ax_title.transAxes, va='center', ha='right')
    
    # === ROW 1: Key Metrics Cards ===
    
    # Card 1: Total Scans
    ax1 = plt.subplot2grid((20, 3), (2, 0), rowspan=3)
    ax1.axis('off')
    card1 = FancyBboxPatch((0.05, 0.1), 0.9, 0.8, 
                           boxstyle="round,pad=0.05", 
                           facecolor='#3498db', edgecolor='#2980b9', linewidth=2,
                           transform=ax1.transAxes)
    ax1.add_patch(card1)
    ax1.text(0.5, 0.7, '1,247', color='white', fontsize=32, fontweight='bold',
             transform=ax1.transAxes, ha='center', va='center')
    ax1.text(0.5, 0.4, 'Total Scans', color='white', fontsize=14,
             transform=ax1.transAxes, ha='center', va='center')
    ax1.text(0.5, 0.2, '↑ 12.5% vs last week', color='#ecf0f1', fontsize=10,
             transform=ax1.transAxes, ha='center', va='center')
    
    # Card 2: Vulnerabilities Detected
    ax2 = plt.subplot2grid((20, 3), (2, 1), rowspan=3)
    ax2.axis('off')
    card2 = FancyBboxPatch((0.05, 0.1), 0.9, 0.8, 
                           boxstyle="round,pad=0.05", 
                           facecolor='#e74c3c', edgecolor='#c0392b', linewidth=2,
                           transform=ax2.transAxes)
    ax2.add_patch(card2)
    ax2.text(0.5, 0.7, '342', color='white', fontsize=32, fontweight='bold',
             transform=ax2.transAxes, ha='center', va='center')
    ax2.text(0.5, 0.4, 'Vulnerabilities Found', color='white', fontsize=14,
             transform=ax2.transAxes, ha='center', va='center')
    ax2.text(0.5, 0.2, '87% reduction (FP filtered)', color='#ecf0f1', fontsize=10,
             transform=ax2.transAxes, ha='center', va='center')
    
    # Card 3: ML Accuracy
    ax3 = plt.subplot2grid((20, 3), (2, 2), rowspan=3)
    ax3.axis('off')
    card3 = FancyBboxPatch((0.05, 0.1), 0.9, 0.8, 
                           boxstyle="round,pad=0.05", 
                           facecolor='#2ecc71', edgecolor='#27ae60', linewidth=2,
                           transform=ax3.transAxes)
    ax3.add_patch(card3)
    ax3.text(0.5, 0.7, '95.0%', color='white', fontsize=32, fontweight='bold',
             transform=ax3.transAxes, ha='center', va='center')
    ax3.text(0.5, 0.4, 'ML Model Accuracy', color='white', fontsize=14,
             transform=ax3.transAxes, ha='center', va='center')
    ax3.text(0.5, 0.2, 'False Positive Reducer', color='#ecf0f1', fontsize=10,
             transform=ax3.transAxes, ha='center', va='center')
    
    # === ROW 2: Scan Activity Chart ===
    ax4 = plt.subplot2grid((20, 3), (6, 0), colspan=2, rowspan=6)
    
    # Generate sample data for last 7 days
    dates = [datetime.now() - timedelta(days=i) for i in range(6, -1, -1)]
    date_labels = [d.strftime('%m-%d') for d in dates]
    
    scans = [145, 167, 189, 201, 198, 215, 232]
    vulnerabilities = [89, 98, 112, 95, 87, 102, 108]
    true_positives = [12, 15, 18, 13, 11, 14, 13]
    
    x = np.arange(len(date_labels))
    width = 0.25
    
    bars1 = ax4.bar(x - width, scans, width, label='Total Scans', color='#3498db', alpha=0.8)
    bars2 = ax4.bar(x, vulnerabilities, width, label='Findings (raw)', color='#e74c3c', alpha=0.8)
    bars3 = ax4.bar(x + width, true_positives, width, label='True Positives (ML filtered)', 
                    color='#2ecc71', alpha=0.8)
    
    ax4.set_xlabel('Date', fontsize=12, fontweight='bold')
    ax4.set_ylabel('Count', fontsize=12, fontweight='bold')
    ax4.set_title('Weekly Scan Activity & ML Filtering Results', fontsize=14, fontweight='bold', pad=15)
    ax4.set_xticks(x)
    ax4.set_xticklabels(date_labels)
    ax4.legend(loc='upper left', fontsize=10)
    ax4.grid(True, alpha=0.3)
    ax4.set_facecolor('#ffffff')
    
    # Add value labels on bars
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=8)
    
    # === ROW 2: Severity Distribution Pie Chart ===
    ax5 = plt.subplot2grid((20, 3), (6, 2), rowspan=6)
    
    severity_labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    severity_counts = [8, 18, 45, 82, 189]
    severity_colors = ['#c0392b', '#e74c3c', '#f39c12', '#f1c40f', '#3498db']
    
    wedges, texts, autotexts = ax5.pie(severity_counts, labels=severity_labels, 
                                        autopct='%1.1f%%',
                                        colors=severity_colors,
                                        startangle=90,
                                        textprops={'fontsize': 10, 'fontweight': 'bold'})
    
    # Make percentage text white
    for autotext in autotexts:
        autotext.set_color('white')
        autotext.set_fontsize(9)
    
    ax5.set_title('Severity Distribution\n(After ML Filtering)', fontsize=12, fontweight='bold', pad=15)
    
    # === ROW 3: Recent Alerts Table ===
    ax6 = plt.subplot2grid((20, 3), (13, 0), colspan=3, rowspan=6)
    ax6.axis('off')
    
    # Table header
    ax6.text(0.02, 0.95, 'Recent Critical Alerts', fontsize=14, fontweight='bold',
             transform=ax6.transAxes, va='top')
    
    # Table data
    alerts_data = [
        ['🔴', '2026-01-22 14:32', 'SQL Injection', 'Critical', '/admin/users.php', 'True Positive (95%)'],
        ['🔴', '2026-01-22 14:15', 'XSS Stored', 'High', '/mod/forum/post.php', 'True Positive (92%)'],
        ['🟡', '2026-01-22 13:58', 'CSRF Token Missing', 'Medium', '/enrol/ajax.php', 'Under Review'],
        ['🟢', '2026-01-22 13:45', 'Missing HSTS Header', 'Low', '/index.php', 'False Positive (89%)'],
        ['🟡', '2026-01-22 13:22', 'Path Traversal', 'High', '/pluginfile.php', 'True Positive (88%)'],
    ]
    
    # Table headers
    headers = ['Status', 'Timestamp', 'Type', 'Severity', 'Endpoint', 'ML Classification']
    col_widths = [0.06, 0.15, 0.18, 0.12, 0.25, 0.24]
    x_positions = [0.02]
    for w in col_widths[:-1]:
        x_positions.append(x_positions[-1] + w)
    
    y_start = 0.85
    row_height = 0.12
    
    # Draw header background
    header_bg = Rectangle((0.02, y_start - 0.01), 0.96, row_height, 
                          facecolor='#34495e', transform=ax6.transAxes)
    ax6.add_patch(header_bg)
    
    # Draw headers
    for i, (header, x_pos) in enumerate(zip(headers, x_positions)):
        ax6.text(x_pos + 0.01, y_start + row_height/2, header, 
                color='white', fontsize=10, fontweight='bold',
                transform=ax6.transAxes, va='center')
    
    # Draw table rows
    for idx, row in enumerate(alerts_data):
        y_pos = y_start - (idx + 1) * row_height
        
        # Alternating row colors
        if idx % 2 == 0:
            row_bg = Rectangle((0.02, y_pos - 0.01), 0.96, row_height,
                              facecolor='#ecf0f1', transform=ax6.transAxes)
            ax6.add_patch(row_bg)
        
        # Draw row data
        for col_idx, (value, x_pos) in enumerate(zip(row, x_positions)):
            color = '#2c3e50'
            if col_idx == 3:  # Severity column
                if value == 'Critical':
                    color = '#c0392b'
                elif value == 'High':
                    color = '#e74c3c'
                elif value == 'Medium':
                    color = '#f39c12'
            
            ax6.text(x_pos + 0.01, y_pos + row_height/2, value,
                    color=color, fontsize=9,
                    transform=ax6.transAxes, va='center')
    
    plt.tight_layout()
    return fig

def create_ml_performance_dashboard():
    """Create ML model performance dashboard."""
    fig = plt.figure(figsize=(16, 10), dpi=150)
    fig.patch.set_facecolor('#f5f5f5')
    
    # Title bar
    ax_title = plt.subplot2grid((20, 3), (0, 0), colspan=3, rowspan=1)
    ax_title.axis('off')
    ax_title.add_patch(Rectangle((0, 0), 1, 1, facecolor='#8e44ad', transform=ax_title.transAxes))
    ax_title.text(0.02, 0.5, '🤖 Machine Learning Models - Performance Dashboard', 
                  color='white', fontsize=20, fontweight='bold', 
                  transform=ax_title.transAxes, va='center')
    
    # === Model Cards ===
    models = [
        {'name': 'False Positive\nReducer', 'accuracy': 95.0, 'status': 'Active', 'color': '#2ecc71'},
        {'name': 'Severity\nPredictor', 'accuracy': 85.0, 'status': 'Active', 'color': '#3498db'},
        {'name': 'Anomaly\nDetector', 'accuracy': 89.0, 'status': 'Baseline', 'color': '#f39c12'},
        {'name': 'Rate\nLimiter', 'accuracy': 72.0, 'status': 'Baseline', 'color': '#9b59b6'},
    ]
    
    for idx, model in enumerate(models):
        ax = plt.subplot2grid((20, 4), (2, idx), rowspan=3)
        ax.axis('off')
        
        card = FancyBboxPatch((0.05, 0.1), 0.9, 0.8, 
                             boxstyle="round,pad=0.05", 
                             facecolor=model['color'], edgecolor='#2c3e50', linewidth=2,
                             transform=ax.transAxes)
        ax.add_patch(card)
        
        ax.text(0.5, 0.75, model['name'], color='white', fontsize=11, fontweight='bold',
               transform=ax.transAxes, ha='center', va='center')
        ax.text(0.5, 0.5, f"{model['accuracy']}%", color='white', fontsize=24, fontweight='bold',
               transform=ax.transAxes, ha='center', va='center')
        ax.text(0.5, 0.25, model['status'], color='#ecf0f1', fontsize=10,
               transform=ax.transAxes, ha='center', va='center')
    
    # === Confusion Matrix ===
    ax_cm = plt.subplot2grid((20, 4), (6, 0), colspan=2, rowspan=7)
    
    confusion_matrix = np.array([[108, 5], [4, 63]])
    
    im = ax_cm.imshow(confusion_matrix, cmap='Blues', aspect='auto')
    
    ax_cm.set_xticks([0, 1])
    ax_cm.set_yticks([0, 1])
    ax_cm.set_xticklabels(['Predicted TP', 'Predicted FP'], fontsize=11, fontweight='bold')
    ax_cm.set_yticklabels(['Actual TP', 'Actual FP'], fontsize=11, fontweight='bold')
    
    # Add text annotations
    for i in range(2):
        for j in range(2):
            text_color = 'white' if confusion_matrix[i, j] > 50 else 'black'
            ax_cm.text(j, i, str(confusion_matrix[i, j]),
                      ha="center", va="center", color=text_color, 
                      fontsize=32, fontweight='bold')
    
    ax_cm.set_title('False Positive Reducer - Confusion Matrix', 
                   fontsize=14, fontweight='bold', pad=15)
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax_cm, fraction=0.046, pad=0.04)
    cbar.set_label('Count', fontsize=10)
    
    # === Feature Importance ===
    ax_fi = plt.subplot2grid((20, 4), (6, 2), colspan=2, rowspan=7)
    
    features = ['keyword_ratio', 'cvss_score', 'tp_keyword_count', 
                'severity', 'evidence_length', 'risk_score', 'category']
    importance = [18.42, 15.23, 13.98, 12.05, 9.87, 8.54, 7.23]
    
    colors_fi = ['#e74c3c' if imp > 15 else '#3498db' if imp > 10 else '#95a5a6' 
                 for imp in importance]
    
    bars = ax_fi.barh(features, importance, color=colors_fi, alpha=0.8)
    
    ax_fi.set_xlabel('Importance (%)', fontsize=12, fontweight='bold')
    ax_fi.set_title('Feature Importance - FP Reducer Model', 
                   fontsize=14, fontweight='bold', pad=15)
    ax_fi.grid(True, axis='x', alpha=0.3)
    ax_fi.set_facecolor('#ffffff')
    
    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, importance)):
        ax_fi.text(val + 0.5, i, f'{val:.1f}%', 
                  va='center', fontsize=10, fontweight='bold')
    
    # === Training History ===
    ax_hist = plt.subplot2grid((20, 4), (14, 0), colspan=4, rowspan=5)
    
    epochs = np.arange(1, 11)
    train_acc = [0.78, 0.85, 0.89, 0.91, 0.93, 0.94, 0.95, 0.96, 0.97, 0.975]
    test_acc = [0.76, 0.83, 0.87, 0.89, 0.91, 0.92, 0.93, 0.94, 0.95, 0.95]
    
    ax_hist.plot(epochs, train_acc, marker='o', linewidth=2, 
                label='Training Accuracy', color='#3498db')
    ax_hist.plot(epochs, test_acc, marker='s', linewidth=2, 
                label='Test Accuracy', color='#2ecc71')
    
    ax_hist.set_xlabel('Training Iteration', fontsize=12, fontweight='bold')
    ax_hist.set_ylabel('Accuracy', fontsize=12, fontweight='bold')
    ax_hist.set_title('Model Training Progress (False Positive Reducer)', 
                     fontsize=14, fontweight='bold', pad=15)
    ax_hist.legend(loc='lower right', fontsize=11)
    ax_hist.grid(True, alpha=0.3)
    ax_hist.set_facecolor('#ffffff')
    ax_hist.set_ylim([0.7, 1.0])
    
    # Add final accuracy annotation
    ax_hist.annotate(f'Final: {test_acc[-1]:.1%}', 
                    xy=(epochs[-1], test_acc[-1]), 
                    xytext=(epochs[-1]-2, test_acc[-1]-0.05),
                    arrowprops=dict(arrowstyle='->', color='#2ecc71', lw=2),
                    fontsize=12, fontweight='bold', color='#2ecc71')
    
    plt.tight_layout()
    return fig

def create_security_overview_dashboard():
    """Create security overview dashboard."""
    fig = plt.figure(figsize=(16, 10), dpi=150)
    fig.patch.set_facecolor('#f5f5f5')
    
    # Title bar
    ax_title = plt.subplot2grid((20, 3), (0, 0), colspan=3, rowspan=1)
    ax_title.axis('off')
    ax_title.add_patch(Rectangle((0, 0), 1, 1, facecolor='#c0392b', transform=ax_title.transAxes))
    ax_title.text(0.02, 0.5, '⚠️ Security Overview - Vulnerability Assessment', 
                  color='white', fontsize=20, fontweight='bold', 
                  transform=ax_title.transAxes, va='center')
    
    # === OWASP Top 10 Detection ===
    ax_owasp = plt.subplot2grid((20, 3), (2, 0), colspan=2, rowspan=8)
    
    owasp_categories = ['A01: Broken\nAccess Control', 'A02: Crypto\nFailures', 
                        'A03: Injection', 'A05: Security\nMisconfig',
                        'A06: Vulnerable\nComponents', 'A07: Auth\nFailures',
                        'A08: Data\nIntegrity', 'A09: Security\nLogging']
    
    detected = [23, 8, 45, 67, 12, 18, 5, 34]
    filtered_fp = [2, 1, 5, 58, 3, 2, 1, 28]
    true_positive = [21, 7, 40, 9, 9, 16, 4, 6]
    
    x = np.arange(len(owasp_categories))
    width = 0.25
    
    bars1 = ax_owasp.bar(x - width, detected, width, label='Raw Findings', 
                        color='#e74c3c', alpha=0.7)
    bars2 = ax_owasp.bar(x, filtered_fp, width, label='Filtered (False Positive)', 
                        color='#95a5a6', alpha=0.7)
    bars3 = ax_owasp.bar(x + width, true_positive, width, label='Confirmed (True Positive)', 
                        color='#c0392b', alpha=0.9)
    
    ax_owasp.set_xlabel('OWASP Top 10 Category', fontsize=12, fontweight='bold')
    ax_owasp.set_ylabel('Count', fontsize=12, fontweight='bold')
    ax_owasp.set_title('OWASP Top 10 Detection & ML Filtering', 
                      fontsize=14, fontweight='bold', pad=15)
    ax_owasp.set_xticks(x)
    ax_owasp.set_xticklabels(owasp_categories, fontsize=9, rotation=15, ha='right')
    ax_owasp.legend(loc='upper left', fontsize=10)
    ax_owasp.grid(True, axis='y', alpha=0.3)
    ax_owasp.set_facecolor('#ffffff')
    
    # === Risk Score Distribution ===
    ax_risk = plt.subplot2grid((20, 3), (2, 2), rowspan=8)
    
    risk_ranges = ['0-2\n(Low)', '2-4\n(Med)', '4-6\n(Med-High)', 
                   '6-8\n(High)', '8-10\n(Critical)']
    risk_counts = [145, 89, 56, 34, 18]
    risk_colors = ['#3498db', '#f1c40f', '#f39c12', '#e74c3c', '#c0392b']
    
    bars_risk = ax_risk.barh(risk_ranges, risk_counts, color=risk_colors, alpha=0.8)
    
    ax_risk.set_xlabel('Count', fontsize=12, fontweight='bold')
    ax_risk.set_title('CVSS Risk Score\nDistribution', 
                     fontsize=14, fontweight='bold', pad=15)
    ax_risk.grid(True, axis='x', alpha=0.3)
    ax_risk.set_facecolor('#ffffff')
    
    # Add value labels
    for bar, val in zip(bars_risk, risk_counts):
        ax_risk.text(val + 2, bar.get_y() + bar.get_height()/2, 
                    f'{val}', va='center', fontsize=11, fontweight='bold')
    
    # === Scanner Comparison ===
    ax_scanner = plt.subplot2grid((20, 3), (11, 0), colspan=3, rowspan=8)
    
    scanners = ['OWASP ZAP', 'Acunetix', 'Custom SQL\nInjection', 
                'Custom XSS', 'Custom CSRF', 'Path Traversal']
    
    findings_count = [234, 189, 67, 45, 23, 34]
    tp_rate = [15, 18, 95, 92, 88, 85]  # percentage
    
    x_scan = np.arange(len(scanners))
    
    # Create two y-axes
    ax_scanner_twin = ax_scanner.twinx()
    
    bars_scan = ax_scanner.bar(x_scan, findings_count, color='#3498db', alpha=0.7, 
                               label='Total Findings')
    line_scan = ax_scanner_twin.plot(x_scan, tp_rate, marker='o', color='#2ecc71', 
                                     linewidth=3, markersize=10, label='True Positive Rate')
    
    ax_scanner.set_xlabel('Scanner / Module', fontsize=12, fontweight='bold')
    ax_scanner.set_ylabel('Total Findings', fontsize=12, fontweight='bold', color='#3498db')
    ax_scanner_twin.set_ylabel('True Positive Rate (%)', fontsize=12, fontweight='bold', 
                               color='#2ecc71')
    
    ax_scanner.set_title('Scanner Performance Comparison (ML-Enhanced)', 
                        fontsize=14, fontweight='bold', pad=15)
    ax_scanner.set_xticks(x_scan)
    ax_scanner.set_xticklabels(scanners, fontsize=10, rotation=20, ha='right')
    ax_scanner.tick_params(axis='y', labelcolor='#3498db')
    ax_scanner_twin.tick_params(axis='y', labelcolor='#2ecc71')
    ax_scanner.grid(True, alpha=0.3)
    ax_scanner.set_facecolor('#ffffff')
    
    # Add value labels
    for bar, val in zip(bars_scan, findings_count):
        ax_scanner.text(bar.get_x() + bar.get_width()/2, val + 5, 
                       f'{val}', ha='center', fontsize=9, fontweight='bold')
    
    for x_val, y_val in zip(x_scan, tp_rate):
        ax_scanner_twin.text(x_val, y_val + 2, f'{y_val}%', 
                            ha='center', fontsize=9, fontweight='bold', color='#2ecc71')
    
    # Combined legend
    lines1, labels1 = ax_scanner.get_legend_handles_labels()
    lines2, labels2 = ax_scanner_twin.get_legend_handles_labels()
    ax_scanner.legend(lines1 + lines2, labels1 + labels2, loc='upper left', fontsize=10)
    
    plt.tight_layout()
    return fig

# Generate all dashboards
if __name__ == "__main__":
    import os
    
    output_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("Generating MoodleSec Dashboard Mockups...")
    print("=" * 60)
    
    # Dashboard 1: Main Monitoring
    print("\n[1/3] Creating Main Monitoring Dashboard...")
    fig1 = create_main_dashboard()
    output1 = os.path.join(output_dir, "Dashboard_1_Main_Monitoring.png")
    fig1.savefig(output1, dpi=150, bbox_inches='tight', facecolor='#f5f5f5')
    print(f"✅ Saved: {output1}")
    plt.close(fig1)
    
    # Dashboard 2: ML Performance
    print("\n[2/3] Creating ML Performance Dashboard...")
    fig2 = create_ml_performance_dashboard()
    output2 = os.path.join(output_dir, "Dashboard_2_ML_Performance.png")
    fig2.savefig(output2, dpi=150, bbox_inches='tight', facecolor='#f5f5f5')
    print(f"✅ Saved: {output2}")
    plt.close(fig2)
    
    # Dashboard 3: Security Overview
    print("\n[3/3] Creating Security Overview Dashboard...")
    fig3 = create_security_overview_dashboard()
    output3 = os.path.join(output_dir, "Dashboard_3_Security_Overview.png")
    fig3.savefig(output3, dpi=150, bbox_inches='tight', facecolor='#f5f5f5')
    print(f"✅ Saved: {output3}")
    plt.close(fig3)
    
    print("\n" + "=" * 60)
    print("✅ All dashboard mockups generated successfully!")
    print("\nGenerated files:")
    print(f"  1. Dashboard_1_Main_Monitoring.png")
    print(f"  2. Dashboard_2_ML_Performance.png")
    print(f"  3. Dashboard_3_Security_Overview.png")
    print("\nReady for PowerPoint presentation! 🎉")
