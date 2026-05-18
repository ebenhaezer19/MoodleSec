# MoodleSec Thesis Visual Assets

## Quick Start

```bash
# Generate all charts (PNG 300 DPI + SVG)
python docs/thesis-visuals/scripts/generate_all.py

# Or run individually
python docs/thesis-visuals/scripts/generate_eval_charts.py
python docs/thesis-visuals/scripts/generate_soc_charts.py
```

## Dependencies

```
matplotlib numpy
```

## Structure

```
docs/thesis-visuals/
├── output/
│   ├── png/          ← 17 PNG charts (300 DPI)
│   └── svg/          ← 17 SVG vector versions
├── mermaid/          ← 8 Mermaid diagram sources (.mmd)
├── scripts/
│   ├── generate_all.py
│   ├── generate_eval_charts.py
│   ├── generate_soc_charts.py
│   └── style_config.py
└── README.md
```

## Chart Inventory

### ML Evaluation (BAB 4)
| File | Description |
|---|---|
| eval_01_roc_curve | ROC Curve — 3 stages + baseline |
| eval_02_pr_curve | Precision-Recall Curve |
| eval_03_confusion_matrix | 6-class Confusion Matrix |
| eval_04_threshold_tradeoff | TPR vs FPR Threshold Analysis |
| eval_05_feature_importance | XGBoost Feature Importance |
| eval_06_model_comparison | All Models × All Metrics |

### SOC & Architecture (BAB 3-5)
| File | Description |
|---|---|
| soc_01_radar_comparison | Radar: MoodleSec vs 4 SIEMs |
| soc_02_positioning_quadrant | ML Capability vs Cost quadrant |
| arch_01_pipeline_timeline | Request processing timeline |
| soc_03_fpr_waterfall | FPR reduction 8.9%→2.4% |
| soc_04_decision_heatmap | Decision Engine matrix |
| soc_05_cvss_heatmap | CVSS risk scores by attack×URL |
| soc_06_anomaly_distribution | Normal vs Attack score dist |
| soc_07_attack_distribution | Dataset class distribution |
| soc_08_escalation_timeline | Severity escalation timeline |
| soc_09_resource_throughput | RAM + CPU profile |
| soc_10_latency_breakdown | 4-scenario latency stacked bar |

### Mermaid Diagrams (BAB 3-4)
| File | Description |
|---|---|
| 01_system_architecture.mmd | End-to-end architecture |
| 02_alert_state_machine.mmd | SOC Alert Queue states |
| 03_hitl_workflow.mmd | Human-in-the-Loop sequence |
| 04_incident_correlation.mmd | Correlation algorithm flow |
| 05_pipeline_trace_xai.mmd | XAI trace architecture |
| 06_reverse_proxy_flow.mmd | Request processing flow |
| 07_sqli_attack_flow.mmd | SQLi attack detection |
| 08_decision_logic_tree.mmd | Decision Engine XAI tree |

## Rendering Mermaid

Paste `.mmd` files into [mermaid.live](https://mermaid.live) → export PNG/SVG.
