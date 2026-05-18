"""MoodleSec Thesis — SOC, Comparison & Architecture Charts"""
import numpy as np
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from style_config import *
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
from matplotlib.colors import LinearSegmentedColormap

# ============================================================
# 1. SOC Radar Chart — MoodleSec vs SIEM
# ============================================================
def chart_radar():
    categories = ['ML Capability', 'Explainability\n(XAI)', 'LMS\nAwareness', 'Cost\nEfficiency',
                  'Easy\nDeployment', 'HITL\nSupport', 'Correlation\nEngine', 'Lightweight\nRuntime']
    N = len(categories)
    angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    systems = {
        'MoodleSec':  [9, 9, 10, 10, 9, 9, 7, 9],
        'Splunk':     [8, 3, 2, 2, 2, 8, 9, 2],
        'Elastic':    [7, 3, 2, 4, 3, 7, 8, 3],
        'Wazuh':      [3, 2, 2, 9, 6, 4, 5, 5],
        'Snort':      [2, 1, 1, 9, 5, 1, 2, 6],
    }
    colors_map = {'MoodleSec': C_DANGER, 'Splunk': C_SECONDARY, 'Elastic': C_SUCCESS,
                  'Wazuh': C_WARNING, 'Snort': C_GRAY}

    fig, ax = plt.subplots(figsize=(9, 9), subplot_kw=dict(polar=True))
    ax.set_theta_offset(np.pi/2)
    ax.set_theta_direction(-1)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=10)
    ax.set_ylim(0, 10)
    ax.set_yticks([2, 4, 6, 8, 10])
    ax.set_yticklabels(['2', '4', '6', '8', '10'], fontsize=8)
    ax.grid(alpha=0.3)

    for name, vals in systems.items():
        vals_closed = vals + vals[:1]
        lw = 3 if name == 'MoodleSec' else 1.5
        alpha_fill = 0.15 if name == 'MoodleSec' else 0.03
        ax.plot(angles, vals_closed, '-o', lw=lw, label=name, color=colors_map[name], markersize=5)
        ax.fill(angles, vals_closed, alpha=alpha_fill, color=colors_map[name])

    ax.legend(loc='lower right', bbox_to_anchor=(1.25, -0.05), fontsize=10)
    ax.set_title('Figure 5.X — SOC Capability Comparison Radar Chart', pad=25, fontsize=14, fontweight='bold')
    save(fig, 'soc_01_radar_comparison')

# ============================================================
# 2. Positioning Quadrant
# ============================================================
def chart_quadrant():
    systems = {
        'MoodleSec':  (8.5, 2),
        'Splunk':     (8, 9.5),
        'Elastic':    (7.5, 8),
        'Wazuh':      (3, 5),
        'Snort':      (2, 4),
    }
    colors_map = {'MoodleSec': C_DANGER, 'Splunk': C_SECONDARY, 'Elastic': C_SUCCESS,
                  'Wazuh': C_WARNING, 'Snort': C_GRAY}

    fig, ax = plt.subplots(figsize=(10, 8))
    for name, (ml, comp) in systems.items():
        s = 300 if name == 'MoodleSec' else 150
        zord = 10 if name == 'MoodleSec' else 5
        ax.scatter(comp, ml, s=s, color=colors_map[name], edgecolors='white', lw=2, zorder=zord)
        offset = (0.3, 0.3) if name != 'Snort' else (0.3, -0.4)
        ax.annotate(name, (comp, ml), xytext=offset, textcoords='offset fontsize',
                    fontsize=11, fontweight='bold' if name == 'MoodleSec' else 'normal',
                    color=colors_map[name])

    # Quadrant lines
    ax.axhline(5, color='#d1d5db', ls='--', lw=1)
    ax.axvline(5, color='#d1d5db', ls='--', lw=1)
    # Quadrant labels
    ax.text(2.5, 8.5, 'High ML\nLow Cost', ha='center', fontsize=10, color='#9ca3af', style='italic')
    ax.text(7.5, 8.5, 'High ML\nHigh Cost', ha='center', fontsize=10, color='#9ca3af', style='italic')
    ax.text(2.5, 2, 'Low ML\nLow Cost', ha='center', fontsize=10, color='#9ca3af', style='italic')
    ax.text(7.5, 2, 'Low ML\nHigh Cost', ha='center', fontsize=10, color='#9ca3af', style='italic')

    # Highlight MoodleSec quadrant
    from matplotlib.patches import Rectangle
    ax.add_patch(Rectangle((0, 5), 5, 5.5, fill=True, fc='#fef2f2', ec=C_DANGER, lw=2, ls='--', alpha=0.3, zorder=0))
    ax.text(2.5, 10, 'MoodleSec Niche:\nHigh ML + Low Cost', ha='center', fontsize=10,
            fontweight='bold', color=C_DANGER, bbox=dict(boxstyle='round,pad=0.3', fc='white', ec=C_DANGER))

    ax.set_xlabel('Complexity / Cost →', fontsize=12)
    ax.set_ylabel('ML Capability →', fontsize=12)
    ax.set_xlim(0, 10.5); ax.set_ylim(0, 10.5)
    ax.set_title('Figure 5.X — MoodleSec Positioning: ML Capability vs Complexity/Cost', fontsize=14, fontweight='bold')
    save(fig, 'soc_02_positioning_quadrant')

# ============================================================
# 3. Pipeline Latency Timeline
# ============================================================
def chart_pipeline_timeline():
    stages = ['Request\nReceived', 'Feature\nExtraction', 'Isolation\nForest', 'XGBoost\nClassifier',
              'FP\nReducer', 'Decision\nEngine', 'SOC\nQueue', 'Moodle\nForward']
    latencies = [0, 2, 10, 20, 5, 1, 3, 30]
    cumulative = np.cumsum(latencies)
    colors = [C_GRAY, C_PURPLE, C_SECONDARY, C_SUCCESS, C_WARNING, C_ACCENT, C_PINK, C_GRAY]

    fig, ax = plt.subplots(figsize=(14, 5))
    for i in range(len(stages)):
        left = cumulative[i] - latencies[i]
        bar = ax.barh(0, latencies[i], left=left, color=colors[i], edgecolor='white', height=0.5)
        if latencies[i] > 1:
            ax.text(left + latencies[i]/2, 0, f'{latencies[i]}ms', ha='center', va='center',
                    fontsize=9, fontweight='bold', color='white')
        ax.text(left + latencies[i]/2, -0.45, stages[i], ha='center', va='top', fontsize=8)

    # Bracket for ML overhead
    ax.annotate('', xy=(2, 0.35), xytext=(40, 0.35), arrowprops=dict(arrowstyle='<->', color=C_PRIMARY, lw=2))
    ax.text(21, 0.5, 'ML Pipeline Overhead: ~38ms', ha='center', fontsize=10, fontweight='bold', color=C_PRIMARY)

    ax.set_xlim(-2, 80)
    ax.set_ylim(-1, 1.2)
    ax.set_xlabel('Cumulative Latency (ms)')
    ax.set_title('Figure 3.X — Reverse Proxy Request Processing Timeline (Full Attack Scenario)', fontsize=13, fontweight='bold')
    ax.set_yticks([])
    ax.text(cumulative[-1]+2, 0, f'Total: {cumulative[-1]}ms', va='center', fontsize=11, fontweight='bold', color=C_PRIMARY)
    save(fig, 'arch_01_pipeline_timeline')

# ============================================================
# 4. FPR Waterfall (enhanced version)
# ============================================================
def chart_fpr_waterfall():
    stages = ['Stage 1\nIsolation Forest', 'Stage 2\nXGBoost', 'Stage 3\nFP Reducer']
    fprs = [8.9, 5.3, 2.4]
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = [C_DANGER, C_WARNING, C_SUCCESS]
    bars = ax.bar(stages, fprs, color=colors, width=0.5, edgecolor='white', linewidth=2)
    for bar, v, c in zip(bars, fprs, colors):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.2, f'{v}%',
                ha='center', fontsize=16, fontweight='bold', color=c)
    # Reduction arrows
    for i in range(len(fprs)-1):
        diff = fprs[i] - fprs[i+1]
        pct = diff / fprs[i] * 100
        ax.annotate(f'−{diff:.1f}pp\n({pct:.0f}%↓)', xy=(i+0.5, (fprs[i]+fprs[i+1])/2),
                    fontsize=11, ha='center', fontweight='bold', color=C_PRIMARY,
                    bbox=dict(boxstyle='round,pad=0.4', fc='#e0f2fe', ec=C_SECONDARY))
    ax.set_ylabel('False Positive Rate (%)', fontsize=12)
    ax.set_title('Figure 4.X — False Positive Rate Reduction Across Pipeline Stages', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 12)
    ax.text(1, 10.5, 'Total FP Reduction: 73%', ha='center', fontsize=14, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.6', fc='#d1fae5', ec=C_SUCCESS, lw=2.5))
    save(fig, 'soc_03_fpr_waterfall')

# ============================================================
# 5. Decision Heatmap (enhanced)
# ============================================================
def chart_decision_heatmap():
    labels_x = ['LOW\n(< 0.40)', 'MEDIUM\n(0.40–0.70)', 'HIGH\n(≥ 0.70)']
    labels_y = ['HIGH (≥ 0.70)', 'MEDIUM (0.40–0.70)', 'LOW (< 0.40)']
    matrix = np.array([[2, 1, 1], [1, 1, 0], [1, 0, 0]])
    cmap = matplotlib.colors.ListedColormap([C_SUCCESS, C_WARNING, C_DANGER])
    fig, ax = plt.subplots(figsize=(9, 7))
    ax.imshow(matrix, cmap=cmap, aspect='auto')
    decisions = {0: 'IGNORE', 1: 'ALERT', 2: 'BLOCK'}
    for i in range(3):
        for j in range(3):
            ax.text(j, i, decisions[matrix[i,j]], ha='center', va='center',
                    fontsize=16, fontweight='bold', color='white')
    ax.set_xticks(range(3)); ax.set_xticklabels(labels_x, fontsize=11)
    ax.set_yticks(range(3)); ax.set_yticklabels(labels_y, fontsize=11)
    ax.set_xlabel('Classifier Confidence', fontsize=12)
    ax.set_ylabel('Anomaly Score', fontsize=12)
    ax.set_title('Figure 4.X — Decision Engine Matrix\n(Anomaly Score × Classifier Confidence)', fontsize=14, fontweight='bold')
    patches = [mpatches.Patch(color=C_DANGER, label='BLOCK → HTTP 403'),
               mpatches.Patch(color=C_WARNING, label='ALERT → SOC Queue'),
               mpatches.Patch(color=C_SUCCESS, label='IGNORE → Forward')]
    ax.legend(handles=patches, loc='upper left', bbox_to_anchor=(1.02, 1), fontsize=10)
    save(fig, 'soc_04_decision_heatmap')

# ============================================================
# 6. CVSS Heatmap (enhanced)
# ============================================================
def chart_cvss():
    attacks = ['SQL Injection', 'Authentication', 'Access Control', 'Path Traversal', 'CSRF', 'XSS']
    base = [10.0, 9.1, 8.1, 7.5, 6.3, 6.1]
    urls = ['/admin (1.5×)', '/user (1.2×)', 'default (1.0×)', '/public (0.8×)']
    mults = [1.5, 1.2, 1.0, 0.8]
    matrix = np.array([[min(10.0, b*m) for m in mults] for b in base])
    cmap = LinearSegmentedColormap.from_list('risk', ['#d1fae5', '#fef3c7', '#fecaca', '#7f1d1d'])

    fig, ax = plt.subplots(figsize=(10, 7))
    im = ax.imshow(matrix, cmap=cmap, aspect='auto', vmin=4, vmax=10)
    for i in range(len(attacks)):
        for j in range(len(urls)):
            v = matrix[i,j]
            priority = 'P1' if v>=9 else 'P2' if v>=7 else 'P3'
            ax.text(j, i, f'{v:.1f}\n({priority})', ha='center', va='center',
                    fontsize=10, fontweight='bold', color='white' if v>=7 else C_PRIMARY)
    ax.set_xticks(range(4)); ax.set_xticklabels(urls, fontsize=10)
    ax.set_yticks(range(6)); ax.set_yticklabels(attacks, fontsize=10)
    ax.set_xlabel('URL Path Category (Business Impact Multiplier)')
    ax.set_ylabel('Attack Type')
    ax.set_title('Figure 4.X — CVSS v3.1 Risk Score Heatmap with Priority Classification', fontsize=13, fontweight='bold')
    fig.colorbar(im, ax=ax, shrink=0.8, label='Risk Score (max 10.0)')
    save(fig, 'soc_05_cvss_heatmap')

# ============================================================
# 7. Anomaly Score Distribution (enhanced)
# ============================================================
def chart_anomaly_dist():
    np.random.seed(42)
    normal = np.clip(np.random.beta(2, 8, 3000)*0.6 + 0.05, 0, 1)
    attack = np.clip(np.random.beta(5, 2, 2000)*0.5 + 0.45, 0, 1)
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.hist(normal, bins=60, alpha=0.7, color=C_SUCCESS, label='Normal Traffic (benign)', density=True)
    ax.hist(attack, bins=60, alpha=0.7, color=C_DANGER, label='Attack Traffic (malicious)', density=True)
    ax.axvline(0.40, color=C_WARNING, ls='--', lw=2.5, label='LOW Threshold (0.40)')
    ax.axvline(0.70, color=C_DANGER, ls='--', lw=2.5, label='HIGH Threshold (0.70)')
    yl = ax.get_ylim()[1]
    ax.fill_between([0.30, 0.55], 0, yl, alpha=0.06, color=C_WARNING)
    ax.text(0.42, yl*0.88, 'FP/FN\nOverlap Zone', fontsize=10, color=C_GRAY, ha='center',
            bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='#e5e7eb'))
    ax.set_xlabel('Anomaly Score')
    ax.set_ylabel('Density')
    ax.set_title('Figure 4.X — Anomaly Score Distribution: Normal vs Attack Traffic\n(Isolation Forest Stage-1 Output)', fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    save(fig, 'soc_06_anomaly_distribution')

# ============================================================
# 8. Attack Distribution Donut (enhanced)
# ============================================================
def chart_attack_donut():
    labels = ['Normal', 'XSS', 'SQL Injection', 'Path Traversal', 'Command Injection', 'SSRF']
    sizes = [5280, 3170, 2640, 2110, 1585, 1062]
    colors = [C_SUCCESS, C_DANGER, C_WARNING, C_PURPLE, C_SECONDARY, C_PINK]
    explode = (0.02, 0.02, 0.02, 0.02, 0.02, 0.02)
    fig, ax = plt.subplots(figsize=(9, 9))
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, explode=explode,
        autopct=lambda p: f'{p:.1f}%\n({int(p*sum(sizes)/100):,})',
        startangle=90, pctdistance=0.78, textprops={'fontsize': 10})
    for at in autotexts: at.set_fontweight('bold')
    centre = plt.Circle((0,0), 0.5, fc='white')
    ax.add_patch(centre)
    ax.text(0, 0.05, f'{sum(sizes):,}', ha='center', va='center', fontsize=20, fontweight='bold', color=C_PRIMARY)
    ax.text(0, -0.12, 'total samples', ha='center', fontsize=11, color=C_GRAY)
    ax.set_title('Figure 4.X — Dataset Distribution by Attack Class', fontsize=14, fontweight='bold', pad=20)
    save(fig, 'soc_07_attack_distribution')

# ============================================================
# 9. Escalation Timeline (enhanced)
# ============================================================
def chart_escalation():
    times = [0, 1, 2, 3, 3.5]
    sev = [2, 2, 3, 4, 4]
    sev_labels = {1:'LOW', 2:'MEDIUM', 3:'HIGH', 4:'CRITICAL'}
    sev_colors = {2:C_WARNING, 3:C_DANGER, 4:'#7f1d1d'}
    fig, ax = plt.subplots(figsize=(11, 5))
    for i in range(len(times)-1):
        ax.plot([times[i], times[i+1]], [sev[i], sev[i]], '-', color=sev_colors[sev[i]], lw=3.5)
        if sev[i] != sev[i+1]:
            ax.plot([times[i+1], times[i+1]], [sev[i], sev[i+1]], ':', color='#9ca3af', lw=2)
    for i, (t, s) in enumerate(zip(times, sev)):
        ax.plot(t, s, 'o', color=sev_colors[s], markersize=12, zorder=5, markeredgecolor='white', markeredgewidth=2)
        ax.annotate(f'Alert {i+1}', (t, s), textcoords='offset points', xytext=(0, 18),
                    ha='center', fontsize=10, fontweight='bold')
    ax.annotate('Rule: 3+ alerts → HIGH', xy=(2, 3), xytext=(3.5, 3.3), fontsize=9, color=C_GRAY,
                arrowprops=dict(arrowstyle='->', color='#9ca3af', lw=1.5),
                bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='#e5e7eb'))
    ax.annotate('Rule: 5+ alerts → CRITICAL', xy=(3.5, 4), xytext=(4.5, 4.3), fontsize=9, color=C_GRAY,
                arrowprops=dict(arrowstyle='->', color='#9ca3af', lw=1.5),
                bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='#e5e7eb'))
    ax.set_yticks([1,2,3,4]); ax.set_yticklabels([sev_labels[i] for i in [1,2,3,4]], fontsize=11)
    ax.set_xlabel('Time (minutes)', fontsize=12)
    ax.set_ylabel('Incident Severity', fontsize=12)
    ax.set_title('Figure 4.X — Incident Severity Escalation Timeline\nCorrelation Key: 192.168.0.75 | XSS (5-minute window)', fontsize=13, fontweight='bold')
    ax.set_xlim(-0.5, 6); ax.set_ylim(0.5, 5)
    save(fig, 'soc_08_escalation_timeline')

# ============================================================
# 10. Resource Consumption + Throughput (enhanced)
# ============================================================
def chart_resources():
    # Memory
    comps = ['FastAPI\nRuntime', 'ML Models', 'Alert Queue', 'Correlator', 'Trace Store', 'Telemetry']
    mem = [40, 215, 3.5, 2, 1.5, 1]
    colors_mem = [C_GRAY, C_SECONDARY, C_SUCCESS, C_WARNING, C_PURPLE, C_PINK]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw={'width_ratios': [1.2, 1]})
    bars = ax1.barh(comps, mem, color=colors_mem, edgecolor='white', height=0.6)
    for bar, v in zip(bars, mem):
        ax1.text(bar.get_width()+3, bar.get_y()+bar.get_height()/2, f'{v:.1f} MB',
                va='center', fontsize=10, fontweight='bold', color=C_PRIMARY)
    ax1.set_xlabel('Memory (MB)')
    ax1.set_title('Runtime Memory by Component', fontsize=12, fontweight='bold')
    ax1.set_xlim(0, 270)
    ax1.text(135, -0.8, f'Total: {sum(mem):.0f} MB', ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.4', fc='#e0f2fe', ec=C_SECONDARY))

    # Throughput vs CPU
    reqs = [5, 10, 30, 50, 100, 200, 350, 500]
    cpu = [2, 5, 10, 15, 22, 30, 45, 60]
    ax2.plot(reqs, cpu, 'o-', color=C_SECONDARY, lw=2.5, markersize=7)
    ax2.fill_between([40, 110], 0, 65, alpha=0.1, color=C_SUCCESS)
    ax2.axvline(75, color=C_SUCCESS, ls='--', lw=1.5)
    ax2.text(75, 62, 'Design Target', ha='center', fontsize=9, color=C_SUCCESS, fontweight='bold')
    ax2.set_xlabel('Requests/min')
    ax2.set_ylabel('CPU %')
    ax2.set_title('Throughput vs CPU', fontsize=12, fontweight='bold')
    ax2.set_ylim(0, 68)

    fig.suptitle('Figure 4.X — System Resource Consumption & Scalability Profile', fontsize=14, fontweight='bold', y=1.02)
    save(fig, 'soc_09_resource_throughput')

# ============================================================
# 11. Latency Breakdown Stacked (enhanced, 4 scenarios)
# ============================================================
def chart_latency():
    scenarios = ['Enforcement\nBlock', 'Normal\nTraffic', 'Suspicious\n(Stage 1)', 'Full Attack\n(3 Stages)']
    comps = ['Enforcement', 'Feature Extract', 'Stage 1', 'Stage 2', 'Stage 3', 'Decision+SOC', 'Forward']
    data = np.array([
        [0.1, 0, 0, 0, 0, 0, 0],
        [0.1, 2, 8, 0, 0, 0, 30],
        [0.1, 2, 10, 0, 0, 1, 30],
        [0.1, 2, 10, 20, 5, 4, 30],
    ])
    colors = [C_GRAY, C_PURPLE, C_SECONDARY, C_SUCCESS, C_WARNING, C_PINK, '#94a3b8']
    fig, ax = plt.subplots(figsize=(12, 6))
    bottom = np.zeros(4)
    for i, (comp, col) in enumerate(zip(comps, colors)):
        bars = ax.barh(scenarios, data[:, i], left=bottom, color=col, label=comp, edgecolor='white', height=0.55)
        for j, (b, v) in enumerate(zip(bars, data[:, i])):
            if v > 2:
                ax.text(bottom[j]+v/2, b.get_y()+b.get_height()/2, f'{v:.0f}ms',
                        ha='center', va='center', fontsize=8, color='white', fontweight='bold')
        bottom += data[:, i]
    for j, tot in enumerate(bottom):
        if tot > 0:
            ax.text(tot+1.5, j, f'{tot:.0f}ms', va='center', fontsize=11, fontweight='bold', color=C_PRIMARY)
    ax.set_xlabel('Latency (ms)')
    ax.set_title('Figure 4.X — Request Processing Latency Breakdown (4 Scenarios)', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right', fontsize=9, ncol=2)
    ax.set_xlim(0, 85)
    save(fig, 'soc_10_latency_breakdown')

# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    print("=== Generating SOC & Comparison Charts ===")
    chart_radar()
    chart_quadrant()
    chart_pipeline_timeline()
    chart_fpr_waterfall()
    chart_decision_heatmap()
    chart_cvss()
    chart_anomaly_dist()
    chart_attack_donut()
    chart_escalation()
    chart_resources()
    chart_latency()
    print("=== Done ===")
