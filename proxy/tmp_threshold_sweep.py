import os
import sys
import random
import numpy as np

sys.path.insert(0, os.getcwd())
sys.path.insert(0, os.path.join(os.getcwd(),'ml'))

from retrain_anomaly_detector_csic import load_csic_samples, _sample_for_eval
from anomaly_detector import AnomalyDetector


def eval_detector(detector, normal_eval, anomalous_eval, use_meta=True):
    tp=fp=tn=fn=0
    for s in normal_eval:
        is_anom, _, _ = detector.detect(s, use_meta=use_meta)
        if is_anom:
            fp += 1
        else:
            tn += 1
    for s in anomalous_eval:
        is_anom, _, _ = detector.detect(s, use_meta=use_meta)
        if is_anom:
            tp += 1
        else:
            fn += 1
    return tp, fp, tn, fn

normal, anomalous, _ = load_csic_samples('ml/training_data/archive/csic_database.csv', 0)
rng = random.Random(42)
rng.shuffle(normal)
rng.shuffle(anomalous)

split_idx = int(len(normal) * 0.8)
split_idx = min(max(split_idx, 20), len(normal) - 1)
train_normals = normal[:split_idx]
holdout_normals = normal[split_idx:]

meta_anomaly_count = int(len(anomalous) * 0.6)
meta_anomaly_count = max(30, meta_anomaly_count)
meta_anomaly_count = min(meta_anomaly_count, len(anomalous))
eval_anomaly_pool = anomalous[meta_anomaly_count:] if meta_anomaly_count < len(anomalous) else anomalous

normal_eval, anomaly_eval = _sample_for_eval(holdout_normals, eval_anomaly_pool, 15000, 42)

model = AnomalyDetector(model_path='ml/models/anomaly_detector.pkl')
base = eval_detector(model, normal_eval, anomaly_eval, use_meta=False)
print('BASELINE TP FP TN FN:', base)

orig_thr = model.meta_threshold
best = None
for t in np.linspace(0.30, 0.90, 61):
    model.meta_threshold = float(t)
    tp, fp, tn, fn = eval_detector(model, normal_eval, anomaly_eval, use_meta=True)
    if fp <= base[1] and fn <= base[3]:
        print(f'BOTH-LEQ threshold={t:.3f} -> TP={tp} FP={fp} TN={tn} FN={fn}')
    objective = (fp/(fp+tn) if (fp+tn) else 0) + (fn/(fn+tp) if (fn+tp) else 0)
    if best is None or objective < best[0]:
        best = (objective, t, tp, fp, tn, fn)

model.meta_threshold = orig_thr
print(f'BEST-OBJECTIVE threshold={best[1]:.3f} -> TP={best[2]} FP={best[3]} TN={best[4]} FN={best[5]} obj={best[0]:.4f}')
