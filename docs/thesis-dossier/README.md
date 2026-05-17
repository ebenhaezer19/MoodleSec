# MoodleSec Technical Dossier — Perplexity AI Reference

> Feed these 3 files into Perplexity AI **in order** to synthesize BAB 1–5.

## Files

| # | File | Sections | Content |
|---|---|---|---|
| 1 | `PART1_ARCHITECTURE.md` | §1–5 | Project identity, system topology, dependency stack, operational modes, middleware, reverse proxy |
| 2 | `PART2_ML_PIPELINE.md` | §6–11 | Two-stage ML pipeline, Isolation Forest, XGBoost, FP Reducer, Decision Engine, evaluation metrics |
| 3 | `PART3_SOC_INTEGRATION.md` | §12–20 | Alert Queue state machine, Incident Correlator, Pipeline Traces (XAI), CVSS Risk Scorer, SOC Dashboard, Moodle Plugin, API inventory, thesis chapter mapping |

## Quick Reference — Key Metrics

| Metric | Value |
|---|---|
| End-to-End Accuracy | **0.941** |
| End-to-End F1 | **0.933** |
| FPR (before FP Reducer) | 8.9% |
| FPR (after FP Reducer) | **2.4%** |
| FP Reduction | **73%** |
| Dataset Size | 15,847 samples |
| ML Models | 3 (Isolation Forest + XGBoost + Random Forest) |
| Attack Classes | 6 (XSS, SQLi, Path Traversal, Cmd Injection, SSRF, Normal) |
| SOC Dashboard Pages | 9 |
| Total API Endpoints | 20+ |
| Codebase | ~3,255 lines (proxy) + 46 files (plugin) |

## Perplexity Prompt Template

```
Using the attached technical dossier (Parts 1-3), write BAB [X] of an
undergraduate Capstone thesis (Tugas Akhir) for the MoodleSec project.

Requirements:
- Write in Bahasa Indonesia (formal academic style)
- Ground ALL technical claims in the implementation evidence from the dossier
- Cite specific metrics, algorithms, and architectural decisions
- Follow standard Indonesian university thesis format
- Include relevant diagrams described in the dossier
```
