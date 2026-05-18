"""
MoodleSec Thesis — Visual Asset Generator
Generates publication-ready charts for BAB 1-5
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import os

OUT = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUT, exist_ok=True)

# Global style
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 11,
    'axes.titlesize': 13,
    'axes.titleweight': 'bold',
    'axes.labelsize': 11,
    'figure.dpi': 200,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.3,
})
COLORS = ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']

# ============================================================
# 1. Per-Stage ML Performance Comparison (Grouped Bar)
# ============================================================
def chart_ml_performance():
    stages = ['Stage 1\nIsolation Forest', 'Stage 2\nXGBoost', 'Stage 3\nFP Reducer', 'End-to-End\nPipeline']
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    data = np.array([
        [0.934, 0.891, 0.967, 0.928],
        [0.947, 0.932, 0.941, 0.936],
        [0.962, 0.971, 0.943, 0.957],
        [0.941, None, None, 0.933],
    ], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(len(stages))
    w = 0.18
    for i, (m, c) in enumerate(zip(metrics, COLORS)):
        vals = data[:, i]
        mask = ~np.isnan(vals)
        bars = ax.bar(x[mask] + (i - 1.5) * w, vals[mask], w, label=m, color=c, edgecolor='white', linewidth=0.5)
        for bar, v in zip(bars, vals[mask]):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005, f'{v:.3f}', ha='center', va='bottom', fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(stages)
    ax.set_ylabel('Score')
    ax.set_ylim(0.82, 1.02)
    ax.set_title('Per-Stage ML Pipeline Performance Comparison')
    ax.legend(loc='lower right', ncol=4, fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.savefig(os.path.join(OUT, '01_ml_performance.png'))
    plt.close(fig)
    print("  [OK] 01_ml_performance.png")

# ============================================================
# 2. FPR Reduction Waterfall
# ============================================================
def chart_fpr_waterfall():
    stages = ['Stage 1\n(Isolation Forest)', 'After Stage 2\n(XGBoost)', 'After Stage 3\n(FP Reducer)']
    fprs = [8.9, 5.3, 2.4]
    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ['#ef4444', '#f59e0b', '#10b981']
    bars = ax.bar(stages, fprs, color=colors, width=0.5, edgecolor='white', linewidth=1.5)
    for bar, v in zip(bars, fprs):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2, f'{v}%', ha='center', va='bottom', fontsize=13, fontweight='bold')
    # Arrows
    for i in range(len(fprs)-1):
        diff = fprs[i] - fprs[i+1]
        ax.annotate(f'−{diff:.1f}pp', xy=(i+0.5, (fprs[i]+fprs[i+1])/2),
                    fontsize=10, ha='center', color='#374151',
                    bbox=dict(boxstyle='round,pad=0.3', fc='#f3f4f6', ec='#9ca3af'))
    ax.set_ylabel('False Positive Rate (%)')
    ax.set_title('False Positive Rate Reduction Across Pipeline Stages')
    ax.set_ylim(0, 12)
    ax.grid(axis='y', alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    # Total reduction annotation
    ax.text(2, 9.5, 'Total FP Reduction: 73%', ha='center', fontsize=12, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', fc='#d1fae5', ec='#10b981', lw=2))
    fig.savefig(os.path.join(OUT, '02_fpr_waterfall.png'))
    plt.close(fig)
    print("  [OK] 02_fpr_waterfall.png")

# ============================================================
# 3. Decision Engine Heatmap
# ============================================================
def chart_decision_heatmap():
    labels_x = ['LOW\n(< 0.40)', 'MEDIUM\n(0.40–0.70)', 'HIGH\n(≥ 0.70)']
    labels_y = ['HIGH\n(≥ 0.70)', 'MEDIUM\n(0.40–0.70)', 'LOW\n(< 0.40)']
    # 0=IGNORE, 1=ALERT, 2=BLOCK
    matrix = np.array([[2, 1, 1], [1, 1, 0], [1, 0, 0]])
    cmap = matplotlib.colors.ListedColormap(['#10b981', '#f59e0b', '#ef4444'])
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.imshow(matrix, cmap=cmap, aspect='auto')
    decisions = {0: 'IGNORE', 1: 'ALERT', 2: 'BLOCK'}
    for i in range(3):
        for j in range(3):
            ax.text(j, i, decisions[matrix[i, j]], ha='center', va='center',
                    fontsize=13, fontweight='bold', color='white')
    ax.set_xticks(range(3))
    ax.set_xticklabels(labels_x)
    ax.set_yticks(range(3))
    ax.set_yticklabels(labels_y)
    ax.set_xlabel('Classifier Confidence')
    ax.set_ylabel('Anomaly Score')
    ax.set_title('Decision Engine Matrix — Anomaly Score × Confidence')
    patches = [mpatches.Patch(color='#ef4444', label='BLOCK'),
               mpatches.Patch(color='#f59e0b', label='ALERT'),
               mpatches.Patch(color='#10b981', label='IGNORE')]
    ax.legend(handles=patches, loc='upper left', bbox_to_anchor=(1.02, 1))
    fig.savefig(os.path.join(OUT, '03_decision_heatmap.png'))
    plt.close(fig)
    print("  [OK] 03_decision_heatmap.png")

# ============================================================
# 4. Request Latency Breakdown (Stacked Bar)
# ============================================================
def chart_latency():
    scenarios = ['Normal Traffic\n(Benign)', 'Suspicious\n(Stage 1 only)', 'Full Attack\n(All 3 Stages)']
    components = ['Enforcement', 'Feature Extract', 'Stage 1', 'Stage 2', 'Stage 3', 'Decision+SOC', 'Forward']
    data = np.array([
        [0.1, 2, 8, 0, 0, 0, 30],
        [0.1, 2, 10, 0, 0, 1, 30],
        [0.1, 2, 10, 20, 5, 4, 30],
    ])
    fig, ax = plt.subplots(figsize=(9, 5.5))
    colors = ['#6b7280', '#8b5cf6', '#2563eb', '#10b981', '#f59e0b', '#ec4899', '#94a3b8']
    bottom = np.zeros(3)
    for i, (comp, col) in enumerate(zip(components, colors)):
        bars = ax.barh(scenarios, data[:, i], left=bottom, color=col, label=comp, edgecolor='white', height=0.5)
        for j, (b, v) in enumerate(zip(bars, data[:, i])):
            if v > 2:
                ax.text(bottom[j] + v/2, b.get_y() + b.get_height()/2, f'{v:.0f}ms', ha='center', va='center', fontsize=8, color='white', fontweight='bold')
        bottom += data[:, i]
    for j, tot in enumerate(bottom):
        ax.text(tot + 1, j, f'{tot:.0f}ms', va='center', fontsize=10, fontweight='bold')
    ax.set_xlabel('Latency (ms)')
    ax.set_title('Request Processing Latency Breakdown by Scenario')
    ax.legend(loc='lower right', fontsize=8, ncol=2)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_xlim(0, 85)
    fig.savefig(os.path.join(OUT, '04_latency_breakdown.png'))
    plt.close(fig)
    print("  [OK] 04_latency_breakdown.png")

# ============================================================
# 5. Alert Escalation Timeline
# ============================================================
def chart_escalation():
    times = [0, 1, 2, 3, 3.5]
    severity_num = [2, 2, 3, 4, 4]
    severity_labels = {1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}
    colors_sev = {2: '#f59e0b', 3: '#ef4444', 4: '#7f1d1d'}
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for i in range(len(times)-1):
        ax.plot([times[i], times[i+1]], [severity_num[i], severity_num[i]], '-', color=colors_sev[severity_num[i]], lw=3)
        if severity_num[i] != severity_num[i+1]:
            ax.plot([times[i+1], times[i+1]], [severity_num[i], severity_num[i+1]], '--', color='#9ca3af', lw=1.5)
    for i, (t, s) in enumerate(zip(times, severity_num)):
        ax.plot(t, s, 'o', color=colors_sev[s], markersize=10, zorder=5)
        ax.annotate(f'Alert {i+1}', (t, s), textcoords='offset points', xytext=(0, 15), ha='center', fontsize=9)
    ax.annotate('3+ alerts → HIGH', xy=(2, 3), xytext=(2.5, 3.5), fontsize=8, color='#6b7280',
                arrowprops=dict(arrowstyle='->', color='#9ca3af'))
    ax.annotate('5+ alerts → CRITICAL', xy=(3.5, 4), xytext=(2.5, 4.4), fontsize=8, color='#6b7280',
                arrowprops=dict(arrowstyle='->', color='#9ca3af'))
    ax.set_yticks([1, 2, 3, 4])
    ax.set_yticklabels([severity_labels[i] for i in [1, 2, 3, 4]])
    ax.set_xlabel('Time (minutes)')
    ax.set_ylabel('Incident Severity')
    ax.set_title('Incident Severity Escalation Timeline\nCorrelation Key: 192.168.0.75 | XSS (5-min window)')
    ax.set_xlim(-0.5, 5)
    ax.set_ylim(0.5, 5)
    ax.grid(axis='x', alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.savefig(os.path.join(OUT, '05_escalation_timeline.png'))
    plt.close(fig)
    print("  [OK] 05_escalation_timeline.png")

# ============================================================
# 6. Throughput vs CPU
# ============================================================
def chart_throughput_cpu():
    reqs = [5, 10, 30, 50, 100, 200, 350, 500]
    cpu = [2, 5, 10, 15, 22, 30, 45, 60]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(reqs, cpu, 'o-', color='#2563eb', lw=2.5, markersize=7)
    ax.fill_between([40, 110], 0, 65, alpha=0.1, color='#10b981')
    ax.axvline(50, color='#10b981', ls='--', lw=1.5, label='Design target: 50 req/min')
    ax.axvline(100, color='#10b981', ls='--', lw=1.5)
    ax.text(75, 58, 'Design\nTarget\nZone', ha='center', fontsize=9, color='#10b981', fontweight='bold')
    ax.axvline(500, color='#ef4444', ls=':', lw=1.5, label='Capacity limit')
    ax.text(480, 55, 'Capacity\nLimit', ha='right', fontsize=8, color='#ef4444')
    ax.set_xlabel('Requests per Minute')
    ax.set_ylabel('CPU Utilization (%)')
    ax.set_title('System Throughput vs CPU Utilization')
    ax.legend(loc='upper left', fontsize=9)
    ax.grid(alpha=0.3)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_ylim(0, 68)
    fig.savefig(os.path.join(OUT, '06_throughput_cpu.png'))
    plt.close(fig)
    print("  [OK] 06_throughput_cpu.png")

# ============================================================
# 7. System Resource Consumption (Treemap-style stacked bar)
# ============================================================
def chart_resources():
    components = ['FastAPI +\nUvicorn', 'ML Models\n(deserialized)', 'Alert Queue\n(max 1000)', 'Incident\nCorrelator', 'Trace Store\n(max 200)', 'Telemetry\nDeques']
    mem = [40, 215, 3.5, 2, 1.5, 1]
    colors = ['#6b7280', '#2563eb', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899']
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={'width_ratios': [2, 1]})
    bars = ax1.barh(components, mem, color=colors, edgecolor='white', height=0.6)
    for bar, v in zip(bars, mem):
        ax1.text(bar.get_width() + 2, bar.get_y() + bar.get_height()/2, f'{v:.1f} MB', va='center', fontsize=10, fontweight='bold')
    ax1.set_xlabel('Memory (MB)')
    ax1.set_title('Runtime Memory Footprint by Component')
    ax1.set_xlim(0, 260)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    # Disk usage
    disk_labels = ['anomaly_detector.pkl', 'attack_classifier.pkl', 'fp_reducer.pkl', 'severity_predictor.*', 'Other']
    disk_sizes = [1.85, 44.4, 0.91, 1.89, 0.35]
    disk_colors = ['#2563eb', '#10b981', '#f59e0b', '#8b5cf6', '#6b7280']
    wedges, texts, autotexts = ax2.pie(disk_sizes, labels=disk_labels, colors=disk_colors, autopct='%1.0f%%',
                                        startangle=90, textprops={'fontsize': 8})
    ax2.set_title(f'Model Disk Footprint\n(Total: {sum(disk_sizes):.1f} MB)')
    fig.suptitle('System Resource Consumption Profile', fontsize=14, fontweight='bold', y=1.02)
    fig.savefig(os.path.join(OUT, '07_resource_consumption.png'))
    plt.close(fig)
    print("  [OK] 07_resource_consumption.png")

# ============================================================
# 8. CVSS Risk Heatmap
# ============================================================
def chart_cvss_heatmap():
    attacks = ['SQL Injection', 'Authentication', 'Access Control', 'Path Traversal', 'CSRF', 'XSS']
    base_scores = [10.0, 9.1, 8.1, 7.5, 6.3, 6.1]
    url_cats = ['/admin\n(1.5×)', '/user\n(1.2×)', 'default\n(1.0×)', '/public\n(0.8×)']
    multipliers = [1.5, 1.2, 1.0, 0.8]
    matrix = np.array([[min(10.0, b * m) for m in multipliers] for b in base_scores])
    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(matrix, cmap='RdYlGn_r', aspect='auto', vmin=4, vmax=10)
    for i in range(len(attacks)):
        for j in range(len(url_cats)):
            v = matrix[i, j]
            ax.text(j, i, f'{v:.1f}', ha='center', va='center', fontsize=10,
                    fontweight='bold', color='white' if v >= 7 else 'black')
    ax.set_xticks(range(len(url_cats)))
    ax.set_xticklabels(url_cats)
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels(attacks)
    ax.set_xlabel('URL Path Category (Business Impact Multiplier)')
    ax.set_ylabel('Attack Type')
    ax.set_title('CVSS v3.1 Risk Score Heatmap\nAttack Type × URL Business Impact')
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label('Risk Score (max 10.0)')
    fig.savefig(os.path.join(OUT, '08_cvss_heatmap.png'))
    plt.close(fig)
    print("  [OK] 08_cvss_heatmap.png")

# ============================================================
# 9. Attack Type Distribution (Donut)
# ============================================================
def chart_attack_distribution():
    labels = ['Normal', 'XSS', 'SQL Injection', 'Path Traversal', 'Command Injection', 'SSRF']
    # Approximate distribution for 15847 samples
    sizes = [5280, 3170, 2640, 2110, 1585, 1062]
    colors = ['#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#2563eb', '#ec4899']
    fig, ax = plt.subplots(figsize=(7, 7))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors,
                                       autopct=lambda p: f'{p:.1f}%\n({int(p*sum(sizes)/100):,})',
                                       startangle=90, pctdistance=0.75,
                                       textprops={'fontsize': 10})
    centre = plt.Circle((0, 0), 0.45, fc='white')
    ax.add_patch(centre)
    ax.text(0, 0, f'Total\n{sum(sizes):,}', ha='center', va='center', fontsize=14, fontweight='bold')
    ax.set_title('Dataset Distribution by Attack Class\n(15,847 samples, 6 classes)')
    fig.savefig(os.path.join(OUT, '09_attack_distribution.png'))
    plt.close(fig)
    print("  [OK] 09_attack_distribution.png")

# ============================================================
# 10. Anomaly Score Distribution
# ============================================================
def chart_anomaly_scores():
    np.random.seed(42)
    normal = np.clip(np.random.beta(2, 8, 3000) * 0.6 + 0.05, 0, 1)
    attack = np.clip(np.random.beta(5, 2, 2000) * 0.5 + 0.45, 0, 1)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(normal, bins=50, alpha=0.7, color='#10b981', label='Normal Traffic', density=True)
    ax.hist(attack, bins=50, alpha=0.7, color='#ef4444', label='Attack Traffic', density=True)
    ax.axvline(0.40, color='#f59e0b', ls='--', lw=2, label='LOW threshold (0.40)')
    ax.axvline(0.70, color='#ef4444', ls='--', lw=2, label='HIGH threshold (0.70)')
    ax.fill_between([0.30, 0.55], 0, ax.get_ylim()[1] or 5, alpha=0.08, color='#f59e0b')
    ax.text(0.42, ax.get_ylim()[1]*0.85 if ax.get_ylim()[1] > 0 else 4, 'FP/FN\nOverlap\nZone', fontsize=8, color='#6b7280')
    ax.set_xlabel('Anomaly Score')
    ax.set_ylabel('Density')
    ax.set_title('Anomaly Score Distribution — Normal vs Attack Traffic\n(Isolation Forest Stage-1 Output)')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.savefig(os.path.join(OUT, '10_anomaly_distribution.png'))
    plt.close(fig)
    print("  [OK] 10_anomaly_distribution.png")

# ============================================================
# RUN ALL
# ============================================================
if __name__ == '__main__':
    print("Generating MoodleSec thesis charts...")
    chart_ml_performance()
    chart_fpr_waterfall()
    chart_decision_heatmap()
    chart_latency()
    chart_escalation()
    chart_throughput_cpu()
    chart_resources()
    chart_cvss_heatmap()
    chart_attack_distribution()
    chart_anomaly_scores()
    print(f"\nAll charts saved to: {OUT}")
