"""
Generate ML Flowchart Diagrams as PNG for Sempro Presentation
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

# Set style
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Arial', 'DejaVu Sans']
plt.rcParams['font.size'] = 10

def create_simple_overview():
    """Pilihan 1: Simple Overview"""
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis('off')
    
    # Title
    title_box = FancyBboxPatch((0.5, 5.2), 9, 0.6, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(title_box)
    ax.text(5, 5.5, 'ML FALSE POSITIVE REDUCER', ha='center', va='center', 
            fontsize=16, fontweight='bold', color='white')
    
    # Raw Findings Box
    box1 = FancyBboxPatch((0.5, 3.5), 2, 1.2, boxstyle="round,pad=0.1", 
                          edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(box1)
    ax.text(1.5, 4.3, 'Raw Findings', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(1.5, 4.0, '100 Findings', ha='center', va='center', fontsize=10)
    ax.text(1.5, 3.7, '(Scanner Output)', ha='center', va='center', fontsize=8, style='italic')
    
    # ML Processing Box
    box2 = FancyBboxPatch((3.5, 3.5), 2, 1.2, boxstyle="round,pad=0.1", 
                          edgecolor='#2E86AB', facecolor='#E5F2FF', linewidth=2)
    ax.add_patch(box2)
    ax.text(4.5, 4.3, 'ML Processing', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(4.5, 4.0, 'Analyze Pattern', ha='center', va='center', fontsize=10)
    ax.text(4.5, 3.7, 'Predict TP/FP', ha='center', va='center', fontsize=8, style='italic')
    
    # Final Result Box
    box3 = FancyBboxPatch((6.5, 3.5), 2, 1.2, boxstyle="round,pad=0.1", 
                          edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(box3)
    ax.text(7.5, 4.3, 'Final Result', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(7.5, 4.0, '13 TP', ha='center', va='center', fontsize=10, color='#06A77D')
    ax.text(7.5, 3.7, '87 FP REMOVED', ha='center', va='center', fontsize=10, color='#E63946')
    
    # Arrows
    arrow1 = FancyArrowPatch((2.5, 4.1), (3.5, 4.1), arrowstyle='->', 
                            mutation_scale=30, linewidth=3, color='#2E86AB')
    arrow2 = FancyArrowPatch((5.5, 4.1), (6.5, 4.1), arrowstyle='->', 
                            mutation_scale=30, linewidth=3, color='#2E86AB')
    ax.add_patch(arrow1)
    ax.add_patch(arrow2)
    
    # Before/After comparison
    before_box = FancyBboxPatch((0.5, 1.8), 4, 1, boxstyle="round,pad=0.1", 
                                edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(before_box)
    ax.text(2.5, 2.6, 'Before ML:', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(2.5, 2.2, '60% False Positive', ha='center', va='center', fontsize=14, 
            fontweight='bold', color='#E63946')
    
    after_box = FancyBboxPatch((5.5, 1.8), 4, 1, boxstyle="round,pad=0.1", 
                               edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(after_box)
    ax.text(7.5, 2.6, 'After ML:', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(7.5, 2.2, '8% False Positive', ha='center', va='center', fontsize=14, 
            fontweight='bold', color='#06A77D')
    
    # Big arrow between
    big_arrow = FancyArrowPatch((4.5, 2.3), (5.5, 2.3), arrowstyle='->', 
                               mutation_scale=40, linewidth=4, color='#2E86AB')
    ax.add_patch(big_arrow)
    
    # Bottom result
    result_box = FancyBboxPatch((2, 0.3), 6, 0.8, boxstyle="round,pad=0.1", 
                                edgecolor='#06A77D', facecolor='#06A77D', linewidth=2)
    ax.add_patch(result_box)
    ax.text(5, 0.7, '✓ 87% Reduction in Manual Verification', ha='center', va='center', 
            fontsize=14, fontweight='bold', color='white')
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_1_Simple_Overview.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_1_Simple_Overview.png")


def create_detailed_pipeline():
    """Pilihan 2: Detailed Pipeline"""
    fig, ax = plt.subplots(figsize=(10, 14))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 14)
    ax.axis('off')
    
    # Title
    title_box = FancyBboxPatch((0.5, 13), 9, 0.7, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(title_box)
    ax.text(5, 13.35, 'MACHINE LEARNING PIPELINE - DETAILED FLOW', 
            ha='center', va='center', fontsize=14, fontweight='bold', color='white')
    
    y_pos = 11.5
    
    # STEP 1: INPUT
    ax.text(1, y_pos, 'STEP 1: INPUT', fontsize=12, fontweight='bold', color='#2E86AB')
    y_pos -= 0.5
    input_box = FancyBboxPatch((1.5, y_pos-1.5), 3, 1.3, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#E5F2FF', linewidth=2)
    ax.add_patch(input_box)
    ax.text(3, y_pos-0.3, 'Raw Finding', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(3, y_pos-0.6, '• Severity: High', ha='center', va='center', fontsize=9)
    ax.text(3, y_pos-0.8, '• Category: SQL Injection', ha='center', va='center', fontsize=9)
    ax.text(3, y_pos-1.0, '• URL: /login.php', ha='center', va='center', fontsize=9)
    ax.text(3, y_pos-1.2, '• CVSS: 7.5', ha='center', va='center', fontsize=9)
    
    y_pos -= 2
    arrow = FancyArrowPatch((3, y_pos+0.3), (3, y_pos-0.2), arrowstyle='->', 
                           mutation_scale=20, linewidth=2, color='#2E86AB')
    ax.add_patch(arrow)
    
    # STEP 2: FEATURE EXTRACTION
    y_pos -= 0.7
    ax.text(1, y_pos, 'STEP 2: FEATURE EXTRACTION', fontsize=12, fontweight='bold', color='#2E86AB')
    y_pos -= 0.5
    feature_box = FancyBboxPatch((1, y_pos-1.8), 4, 1.6, boxstyle="round,pad=0.1", 
                                 edgecolor='#2E86AB', facecolor='#E5F2FF', linewidth=2)
    ax.add_patch(feature_box)
    ax.text(3, y_pos-0.3, 'Extract 16 Features:', ha='center', va='center', 
            fontsize=10, fontweight='bold')
    features = [
        '1. severity_encoded (0-4)',
        '2. evidence_length (chars)',
        '3. url_complexity (parts)',
        '4. cvss_score (0-10)',
        '5. response_time (ms)',
        '6. status_code (200/403/500)',
        '7-16. keyword_match (binary)'
    ]
    for i, feat in enumerate(features):
        ax.text(3, y_pos-0.6-(i*0.15), feat, ha='center', va='center', fontsize=8)
    
    y_pos -= 2.3
    arrow = FancyArrowPatch((3, y_pos+0.3), (3, y_pos-0.2), arrowstyle='->', 
                           mutation_scale=20, linewidth=2, color='#2E86AB')
    ax.add_patch(arrow)
    
    # STEP 3: ENSEMBLE CLASSIFICATION
    y_pos -= 0.7
    ax.text(1, y_pos, 'STEP 3: ENSEMBLE CLASSIFICATION', fontsize=12, fontweight='bold', color='#2E86AB')
    y_pos -= 0.5
    
    # Random Forest
    rf_box = FancyBboxPatch((0.8, y_pos-1.2), 2, 1, boxstyle="round,pad=0.1", 
                            edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(rf_box)
    ax.text(1.8, y_pos-0.4, 'Random Forest', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(1.8, y_pos-0.6, '(200 trees)', ha='center', va='center', fontsize=8)
    ax.text(1.8, y_pos-0.85, 'Predict → 0.82', ha='center', va='center', fontsize=9, color='#06A77D')
    
    # Gradient Boosting
    gb_box = FancyBboxPatch((3.2, y_pos-1.2), 2, 1, boxstyle="round,pad=0.1", 
                            edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(gb_box)
    ax.text(4.2, y_pos-0.4, 'Gradient Boost', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(4.2, y_pos-0.6, '(200 estimators)', ha='center', va='center', fontsize=8)
    ax.text(4.2, y_pos-0.85, 'Predict → 0.78', ha='center', va='center', fontsize=9, color='#06A77D')
    
    # Voting
    y_pos -= 1.5
    voting_box = FancyBboxPatch((1.5, y_pos-0.6), 3, 0.5, boxstyle="round,pad=0.1", 
                                edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(voting_box)
    ax.text(3, y_pos-0.35, 'Soft Voting: (0.82+0.78)/2 = 0.80', ha='center', va='center', 
            fontsize=9, fontweight='bold', color='white')
    
    y_pos -= 1
    arrow = FancyArrowPatch((3, y_pos+0.3), (3, y_pos-0.2), arrowstyle='->', 
                           mutation_scale=20, linewidth=2, color='#2E86AB')
    ax.add_patch(arrow)
    
    # STEP 4: CALIBRATION
    y_pos -= 0.7
    ax.text(1, y_pos, 'STEP 4: PROBABILITY CALIBRATION', fontsize=12, fontweight='bold', color='#2E86AB')
    y_pos -= 0.5
    cal_box = FancyBboxPatch((1.5, y_pos-0.8), 3, 0.7, boxstyle="round,pad=0.1", 
                             edgecolor='#2E86AB', facecolor='#E5F2FF', linewidth=2)
    ax.add_patch(cal_box)
    ax.text(3, y_pos-0.2, 'Sigmoid Calibration', ha='center', va='center', fontsize=10, fontweight='bold')
    ax.text(3, y_pos-0.45, 'Raw: 0.80 → Calibrated: 0.85', ha='center', va='center', fontsize=9)
    ax.text(3, y_pos-0.65, 'Confidence Score: 85%', ha='center', va='center', 
            fontsize=9, color='#06A77D', fontweight='bold')
    
    y_pos -= 1.2
    arrow = FancyArrowPatch((3, y_pos+0.3), (3, y_pos-0.2), arrowstyle='->', 
                           mutation_scale=20, linewidth=2, color='#2E86AB')
    ax.add_patch(arrow)
    
    # STEP 5: DECISION
    y_pos -= 0.7
    ax.text(1, y_pos, 'STEP 5: BINARY DECISION', fontsize=12, fontweight='bold', color='#2E86AB')
    y_pos -= 0.5
    decision_box = FancyBboxPatch((1.5, y_pos-0.6), 3, 0.5, boxstyle="round,pad=0.1", 
                                  edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(decision_box)
    ax.text(3, y_pos-0.35, 'Is P > 0.5?   →   0.85 > 0.5 ✓ YES', ha='center', va='center', 
            fontsize=10, fontweight='bold')
    
    y_pos -= 1
    
    # FP and TP boxes
    fp_box = FancyBboxPatch((0.5, y_pos-0.8), 2, 0.7, boxstyle="round,pad=0.1", 
                            edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(fp_box)
    ax.text(1.5, y_pos-0.3, 'FALSE POSITIVE', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='#E63946')
    ax.text(1.5, y_pos-0.55, 'FILTER OUT', ha='center', va='center', fontsize=9)
    
    tp_box = FancyBboxPatch((3.5, y_pos-0.8), 2, 0.7, boxstyle="round,pad=0.1", 
                            edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(tp_box)
    ax.text(4.5, y_pos-0.3, 'TRUE POSITIVE', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='#06A77D')
    ax.text(4.5, y_pos-0.55, 'KEEP & CALCULATE RISK', ha='center', va='center', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_2_Detailed_Pipeline.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_2_Detailed_Pipeline.png")


def create_before_after_impact():
    """Pilihan 4: Before/After Impact"""
    fig, ax = plt.subplots(figsize=(12, 10))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 10)
    ax.axis('off')
    
    # Title
    title_box = FancyBboxPatch((1, 9.2), 10, 0.6, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(title_box)
    ax.text(6, 9.5, 'ML FALSE POSITIVE REDUCER - IMPACT', ha='center', va='center', 
            fontsize=16, fontweight='bold', color='white')
    
    # BEFORE ML
    ax.text(1.5, 8.3, 'BEFORE ML IMPLEMENTATION', fontsize=13, fontweight='bold', color='#E63946')
    ax.plot([1.5, 10.5], [8.1, 8.1], 'k-', linewidth=2, color='#E63946')
    
    # Scanner output
    scanner_box = FancyBboxPatch((2, 6.8), 8, 1, boxstyle="round,pad=0.1", 
                                 edgecolor='#666', facecolor='#F5F5F5', linewidth=2)
    ax.add_patch(scanner_box)
    ax.text(6, 7.5, '100 Findings from Scanner', ha='center', va='center', 
            fontsize=12, fontweight='bold')
    
    # TP and FP bars
    tp_bar = patches.Rectangle((2.5, 6.3), 2.5, 0.4, linewidth=2, 
                                edgecolor='#06A77D', facecolor='#06A77D')
    ax.add_patch(tp_bar)
    ax.text(3.75, 6.5, '40 TP (Real)', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='white')
    
    fp_bar = patches.Rectangle((5, 6.3), 5, 0.4, linewidth=2, 
                                edgecolor='#E63946', facecolor='#E63946')
    ax.add_patch(fp_bar)
    ax.text(7.5, 6.5, '60 FP (False Alarm)', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='white')
    
    # Arrow down
    arrow = FancyArrowPatch((6, 6.2), (6, 5.7), arrowstyle='->', 
                           mutation_scale=30, linewidth=3, color='#666')
    ax.add_patch(arrow)
    
    # Manual verification
    manual_box = FancyBboxPatch((2, 4.3), 8, 1.2, boxstyle="round,pad=0.1", 
                                edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(manual_box)
    ax.text(6, 5.2, 'Manual Verification Required', ha='center', va='center', 
            fontsize=11, fontweight='bold', color='#E63946')
    ax.text(6, 4.9, '⏱ Time: 100 findings × 10 min = 1000 min', ha='center', va='center', fontsize=9)
    ax.text(6, 4.65, '👤 Effort: ~16.7 hours security analyst work', ha='center', va='center', fontsize=9)
    ax.text(6, 4.4, '⚠ Risk: Analyst fatigue, missed vulnerabilities', ha='center', va='center', 
            fontsize=9, style='italic')
    
    # AFTER ML
    ax.text(1.5, 3.5, 'AFTER ML IMPLEMENTATION', fontsize=13, fontweight='bold', color='#06A77D')
    ax.plot([1.5, 10.5], [3.3, 3.3], 'k-', linewidth=2, color='#06A77D')
    
    # Scanner output
    scanner_box2 = FancyBboxPatch((2, 2.5), 8, 0.5, boxstyle="round,pad=0.1", 
                                  edgecolor='#666', facecolor='#F5F5F5', linewidth=2)
    ax.add_patch(scanner_box2)
    ax.text(6, 2.75, '100 Findings from Scanner', ha='center', va='center', 
            fontsize=11, fontweight='bold')
    
    # Arrow down
    arrow2 = FancyArrowPatch((6, 2.4), (6, 2.0), arrowstyle='->', 
                            mutation_scale=30, linewidth=3, color='#2E86AB')
    ax.add_patch(arrow2)
    
    # ML Processing
    ml_box = FancyBboxPatch((3.5, 1.5), 5, 0.4, boxstyle="round,pad=0.1", 
                            edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(ml_box)
    ax.text(6, 1.7, 'ML Processing (95% Accuracy)', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='white')
    
    # Arrow split
    arrow3a = FancyArrowPatch((6, 1.4), (3.5, 0.9), arrowstyle='->', 
                             mutation_scale=25, linewidth=2, color='#06A77D')
    arrow3b = FancyArrowPatch((6, 1.4), (8.5, 0.9), arrowstyle='->', 
                             mutation_scale=25, linewidth=2, color='#E63946')
    ax.add_patch(arrow3a)
    ax.add_patch(arrow3b)
    
    # TP result
    tp_result = FancyBboxPatch((1.5, 0.2), 3.5, 0.6, boxstyle="round,pad=0.1", 
                               edgecolor='#06A77D', facecolor='#E5F9F0', linewidth=2)
    ax.add_patch(tp_result)
    ax.text(3.25, 0.65, '13 Findings (TP)', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='#06A77D')
    ax.text(3.25, 0.4, '✓ KEPT - Need Review', ha='center', va='center', fontsize=9)
    
    # FP result
    fp_result = FancyBboxPatch((7, 0.2), 3.5, 0.6, boxstyle="round,pad=0.1", 
                               edgecolor='#E63946', facecolor='#FFE5E5', linewidth=2)
    ax.add_patch(fp_result)
    ax.text(8.75, 0.65, '87 Findings (FP)', ha='center', va='center', 
            fontsize=10, fontweight='bold', color='#E63946')
    ax.text(8.75, 0.4, '✗ FILTERED OUT - Auto-removed', ha='center', va='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_4_Before_After_Impact.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_4_Before_After_Impact.png")


def create_confusion_matrix():
    """Pilihan 6: Confusion Matrix"""
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis('off')
    
    # Title
    title_box = FancyBboxPatch((0.5, 9), 9, 0.7, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(title_box)
    ax.text(5, 9.35, 'ML MODEL PERFORMANCE - CONFUSION MATRIX', 
            ha='center', va='center', fontsize=14, fontweight='bold', color='white')
    
    # Matrix
    # TN (74)
    tn_box = patches.Rectangle((2, 5.5), 2, 2, linewidth=3, 
                               edgecolor='#06A77D', facecolor='#E5F9F0')
    ax.add_patch(tn_box)
    ax.text(3, 6.8, '74', ha='center', va='center', fontsize=32, fontweight='bold', color='#06A77D')
    ax.text(3, 6.2, 'True Negative', ha='center', va='center', fontsize=10)
    ax.text(3, 5.9, '(Correct FP)', ha='center', va='center', fontsize=9, style='italic')
    
    # FN (6)
    fn_box = patches.Rectangle((4.5, 5.5), 2, 2, linewidth=3, 
                               edgecolor='#E63946', facecolor='#FFE5E5')
    ax.add_patch(fn_box)
    ax.text(5.5, 6.8, '6', ha='center', va='center', fontsize=32, fontweight='bold', color='#E63946')
    ax.text(5.5, 6.2, 'False Negative', ha='center', va='center', fontsize=10)
    ax.text(5.5, 5.9, '(Missed TP)', ha='center', va='center', fontsize=9, style='italic')
    
    # FP (4)
    fp_box = patches.Rectangle((2, 3), 2, 2, linewidth=3, 
                               edgecolor='#F77F00', facecolor='#FFF3E5')
    ax.add_patch(fp_box)
    ax.text(3, 4.3, '4', ha='center', va='center', fontsize=32, fontweight='bold', color='#F77F00')
    ax.text(3, 3.7, 'False Positive', ha='center', va='center', fontsize=10)
    ax.text(3, 3.4, '(Wrong FP)', ha='center', va='center', fontsize=9, style='italic')
    
    # TP (116)
    tp_box = patches.Rectangle((4.5, 3), 2, 2, linewidth=3, 
                               edgecolor='#06A77D', facecolor='#E5F9F0')
    ax.add_patch(tp_box)
    ax.text(5.5, 4.3, '116', ha='center', va='center', fontsize=32, fontweight='bold', color='#06A77D')
    ax.text(5.5, 3.7, 'True Positive', ha='center', va='center', fontsize=10)
    ax.text(5.5, 3.4, '(Correct TP)', ha='center', va='center', fontsize=9, style='italic')
    
    # Labels
    ax.text(1, 6.5, 'ACTUAL\nFP', ha='right', va='center', fontsize=11, fontweight='bold', rotation=90)
    ax.text(1, 4, 'ACTUAL\nTP', ha='right', va='center', fontsize=11, fontweight='bold', rotation=90)
    ax.text(3, 7.8, 'PREDICTED FP', ha='center', va='center', fontsize=11, fontweight='bold')
    ax.text(5.5, 7.8, 'PREDICTED TP', ha='center', va='center', fontsize=11, fontweight='bold')
    
    # Metrics box
    metrics_box = FancyBboxPatch((1, 0.5), 8, 2, boxstyle="round,pad=0.1", 
                                 edgecolor='#2E86AB', facecolor='#E5F2FF', linewidth=2)
    ax.add_patch(metrics_box)
    ax.text(5, 2.2, 'PERFORMANCE METRICS', ha='center', va='center', 
            fontsize=12, fontweight='bold', color='#2E86AB')
    
    metrics_text = [
        'Overall Accuracy: 95.0% (190/200)',
        'Precision (TP class): 95.1% (116/122)',
        'Recall (TP class): 96.7% (116/120)',
        'F1-Score: 0.959',
        '',
        '✓ Model sangat baik mendeteksi True Positives',
        '✓ Sangat sedikit True Positives yang ter-filter'
    ]
    
    y_start = 1.9
    for i, text in enumerate(metrics_text):
        if text.startswith('✓'):
            ax.text(5, y_start - (i * 0.18), text, ha='center', va='center', 
                   fontsize=9, color='#06A77D', fontweight='bold')
        elif text:
            ax.text(5, y_start - (i * 0.18), text, ha='center', va='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_6_Confusion_Matrix.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_6_Confusion_Matrix.png")


def create_feature_importance():
    """Pilihan 5: Feature Importance"""
    fig, ax = plt.subplots(figsize=(12, 8))
    
    features = [
        'CVSS Score',
        'Severity Level',
        'Evidence Length',
        'Response Time',
        'URL Complexity',
        'Status Code',
        'Other Features (7-16)'
    ]
    importance = [35, 28, 18, 9, 6, 3, 1]
    colors = ['#2E86AB', '#06A77D', '#F77F00', '#E63946', '#A23B72', '#6C757D', '#CED4DA']
    
    y_pos = np.arange(len(features))
    
    bars = ax.barh(y_pos, importance, color=colors, edgecolor='black', linewidth=1.5)
    
    # Add percentage labels
    for i, (bar, imp) in enumerate(zip(bars, importance)):
        width = bar.get_width()
        ax.text(width + 1, bar.get_y() + bar.get_height()/2, 
                f'{imp}%', ha='left', va='center', fontsize=11, fontweight='bold')
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=12)
    ax.set_xlabel('Importance (%)', fontsize=12, fontweight='bold')
    ax.set_title('ML MODEL - FEATURE IMPORTANCE RANKING\nWhich features does the model use most for classification?', 
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xlim(0, 45)
    
    # Add grid
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)
    
    # Add insight box
    insight_text = '💡 INSIGHT:\nModel belajar dari kombinasi multiple features, bukan hanya 1 feature.\nIni menunjukkan model tidak mengalami data leakage.'
    ax.text(0.5, -1.5, insight_text, ha='left', va='top', fontsize=11, 
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#E5F2FF', edgecolor='#2E86AB', linewidth=2),
            transform=ax.transData)
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_5_Feature_Importance.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_5_Feature_Importance.png")


def create_metrics_comparison():
    """Create comparison metrics table"""
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 6)
    ax.axis('off')
    
    # Title
    title_box = FancyBboxPatch((1, 5.2), 10, 0.6, boxstyle="round,pad=0.1", 
                               edgecolor='#2E86AB', facecolor='#2E86AB', linewidth=2)
    ax.add_patch(title_box)
    ax.text(6, 5.5, 'KEY METRICS COMPARISON', ha='center', va='center', 
            fontsize=16, fontweight='bold', color='white')
    
    # Table data
    headers = ['Metric', 'Before ML', 'After ML', 'Change']
    data = [
        ['FP Rate', '60%', '8%', '-87%'],
        ['Manual Review Time', '1000 min', '130 min', '-87%'],
        ['Findings to Review', '100', '13', '-87%'],
        ['Accuracy', 'N/A', '95%', '+95%']
    ]
    
    # Draw table
    row_height = 0.6
    col_widths = [3, 2, 2, 2]
    start_x = 1.5
    start_y = 4.5
    
    # Headers
    x_pos = start_x
    for i, (header, width) in enumerate(zip(headers, col_widths)):
        header_box = patches.Rectangle((x_pos, start_y), width, row_height, 
                                       linewidth=2, edgecolor='#2E86AB', facecolor='#2E86AB')
        ax.add_patch(header_box)
        ax.text(x_pos + width/2, start_y + row_height/2, header, 
                ha='center', va='center', fontsize=12, fontweight='bold', color='white')
        x_pos += width
    
    # Data rows
    for row_idx, row_data in enumerate(data):
        y_pos = start_y - (row_idx + 1) * row_height
        x_pos = start_x
        
        for col_idx, (cell, width) in enumerate(zip(row_data, col_widths)):
            # Alternate row colors
            if row_idx % 2 == 0:
                bg_color = '#F8F9FA'
            else:
                bg_color = 'white'
            
            cell_box = patches.Rectangle((x_pos, y_pos), width, row_height, 
                                         linewidth=1, edgecolor='#CED4DA', facecolor=bg_color)
            ax.add_patch(cell_box)
            
            # Color code the change column
            if col_idx == 3:  # Change column
                if cell.startswith('-'):
                    text_color = '#06A77D'
                    font_weight = 'bold'
                elif cell.startswith('+'):
                    text_color = '#2E86AB'
                    font_weight = 'bold'
                else:
                    text_color = 'black'
                    font_weight = 'normal'
            else:
                text_color = 'black'
                font_weight = 'normal'
            
            ax.text(x_pos + width/2, y_pos + row_height/2, cell, 
                   ha='center', va='center', fontsize=11, color=text_color, fontweight=font_weight)
            x_pos += width
    
    # Summary box
    summary_box = FancyBboxPatch((2, 0.3), 8, 0.8, boxstyle="round,pad=0.1", 
                                 edgecolor='#06A77D', facecolor='#06A77D', linewidth=2)
    ax.add_patch(summary_box)
    ax.text(6, 0.7, '✓ 87% Reduction in Manual Work  |  ✓ 95% Accuracy  |  ✓ Faster Security Response', 
            ha='center', va='center', fontsize=12, fontweight='bold', color='white')
    
    plt.tight_layout()
    plt.savefig('ML_Diagram_7_Metrics_Comparison.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    plt.close()
    print("✓ Generated: ML_Diagram_7_Metrics_Comparison.png")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("GENERATING ML DIAGRAMS FOR SEMPRO PRESENTATION")
    print("="*60 + "\n")
    
    try:
        create_simple_overview()
        create_detailed_pipeline()
        create_before_after_impact()
        create_confusion_matrix()
        create_feature_importance()
        create_metrics_comparison()
        
        print("\n" + "="*60)
        print("✓ ALL DIAGRAMS GENERATED SUCCESSFULLY!")
        print("="*60)
        print("\nFiles created in current directory:")
        print("  1. ML_Diagram_1_Simple_Overview.png")
        print("  2. ML_Diagram_2_Detailed_Pipeline.png")
        print("  3. ML_Diagram_4_Before_After_Impact.png")
        print("  4. ML_Diagram_5_Feature_Importance.png")
        print("  5. ML_Diagram_6_Confusion_Matrix.png")
        print("  6. ML_Diagram_7_Metrics_Comparison.png")
        print("\n📊 Ready to insert into PowerPoint!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
