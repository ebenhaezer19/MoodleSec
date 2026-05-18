#!/usr/bin/env python3
"""
Comprehensive Model Retraining with Data Balance & SMOTE

Implements P0-P4 improvements:
P0: Generate pseudo TP data
P1: Rebalance to 50:50
P2: Implement SMOTE
P3: Enhance features
P4: Retrain models
"""

import json
import sys
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import generators and models
from ml.generate_pseudo_tp_data import PseudoTPDataGenerator
from ml.anomaly_false_positive_reducer import FalsePositiveReducer
from ml.severity_predictor import SeverityPredictor
from ml.anomaly_detector import AnomalyDetector
from ml.rate_limiter import MLRateLimiter

# Try to import SMOTE, install if needed
try:
    from imblearn.over_sampling import SMOTE
    from imblearn.pipeline import Pipeline as ImbPipeline
    from imblearn.combine import SMOTETomek
    SMOTE_AVAILABLE = True
except ImportError:
    SMOTE_AVAILABLE = False
    print("⚠️  imblearn not installed. Run: pip install imbalanced-learn")

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    roc_auc_score, confusion_matrix, classification_report
)


class ComprehensiveRetrainer:
    """Comprehensive model retraining with data balancing."""
    
    def __init__(self):
        """Initialize retrainer."""
        self.pseudo_tp_generator = PseudoTPDataGenerator()
        self.results = {}
        
    def step_1_generate_pseudo_tp(self, num_tp: int = 100) -> List[Dict]:
        """
        P0: Generate pseudo TP data for balancing.
        
        Args:
            num_tp: Number of pseudo TP samples to generate
            
        Returns:
            List of TP findings
        """
        print("\n" + "="*80)
        print("STEP 1: GENERATE PSEUDO TRUE POSITIVE DATA (P0)")
        print("="*80)
        
        print(f"\nGenerating {num_tp} pseudo TP findings...")
        pseudo_tp_data = self.pseudo_tp_generator.generate_with_context(num_tp)
        
        print(f"✅ Generated {len(pseudo_tp_data)} pseudo TP samples")
        print(f"   Categories: SQL Injection, XSS, RCE, CSRF, Auth Bypass, etc.")
        print(f"   All marked as label=0 (True Positive)")
        
        return pseudo_tp_data
    
    def step_2_load_existing_data(self, filepath: str = None) -> Tuple[List[Dict], List[int]]:
        """
        Load existing training data from file.
        
        Args:
            filepath: Path to training data JSON
            
        Returns:
            Tuple of (data, labels)
        """
        print("\n" + "="*80)
        print("STEP 2: LOAD EXISTING DATA")
        print("="*80)
        
        if filepath is None:
            # Try to find latest training data
            candidates = list(Path("ml/training_data").glob("*.json"))
            if not candidates:
                print("⚠️  No existing training data found")
                return [], []
            
            filepath = max(candidates, key=lambda p: p.stat().st_mtime)
        
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"⚠️  File not found: {filepath}")
            return [], []
        
        print(f"\nLoading from: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        training_data = []
        labels = []
        
        for item in data:
            # Handle different formats
            if 'finding' in item:
                finding = item['finding']
            else:
                finding = item
            
            if not finding.get('category') or not finding.get('severity'):
                continue
            
            label = item.get('label', -1)
            if label == -1:
                continue
            
            training_data.append(finding)
            labels.append(label)
        
        print(f"✅ Loaded {len(training_data)} existing findings")
        print(f"   True Positives: {labels.count(0)} ({labels.count(0)/len(labels)*100:.1f}%)")
        print(f"   False Positives: {labels.count(1)} ({labels.count(1)/len(labels)*100:.1f}%)")
        print(f"   Imbalance ratio: {labels.count(1)/max(labels.count(0),1):.1f}:1")
        
        return training_data, labels
    
    def step_3_merge_and_balance(
        self, 
        existing_data: List[Dict], 
        existing_labels: List[int],
        pseudo_tp_data: List[Dict]
    ) -> Tuple[List[Dict], List[int]]:
        """
        P1: Merge pseudo TP with existing data and rebalance to 50:50.
        
        Args:
            existing_data: Existing findings
            existing_labels: Existing labels
            pseudo_tp_data: Generated pseudo TP data
            
        Returns:
            Balanced (data, labels)
        """
        print("\n" + "="*80)
        print("STEP 3: MERGE AND REBALANCE DATASET (P1)")
        print("="*80)
        
        merged_data = list(existing_data)
        merged_labels = list(existing_labels)
        
        # Add pseudo TP data
        print(f"\nAdding {len(pseudo_tp_data)} pseudo TP findings...")
        for item in pseudo_tp_data:
            merged_data.append(item['finding'])
            merged_labels.append(0)  # TP label
        
        # Count before balancing
        tp_count = merged_labels.count(0)
        fp_count = merged_labels.count(1)
        total = len(merged_labels)
        
        print(f"\nBefore rebalancing:")
        print(f"   True Positives: {tp_count} ({tp_count/total*100:.1f}%)")
        print(f"   False Positives: {fp_count} ({fp_count/total*100:.1f}%)")
        print(f"   Imbalance ratio: {fp_count/max(tp_count,1):.1f}:1")
        
        # Rebalance to 50:50
        if tp_count > fp_count:
            # Too many TP, downsample TP
            target_size = fp_count
            tp_indices = [i for i, label in enumerate(merged_labels) if label == 0]
            downsampled_indices = np.random.choice(tp_indices, target_size, replace=False)
            
            # Keep all FP + downsampled TP
            keep_indices = set(downsampled_indices) | set(
                [i for i, label in enumerate(merged_labels) if label == 1]
            )
        else:
            # Too many FP (more common), keep all TP
            target_size = tp_count
            fp_indices = [i for i, label in enumerate(merged_labels) if label == 1]
            downsampled_indices = np.random.choice(fp_indices, target_size, replace=False)
            
            keep_indices = set([i for i, label in enumerate(merged_labels) if label == 0]) | set(downsampled_indices)
        
        keep_indices = sorted(list(keep_indices))
        balanced_data = [merged_data[i] for i in keep_indices]
        balanced_labels = [merged_labels[i] for i in keep_indices]
        
        # Shuffle
        combined = list(zip(balanced_data, balanced_labels))
        np.random.shuffle(combined)
        balanced_data, balanced_labels = zip(*combined)
        balanced_data = list(balanced_data)
        balanced_labels = list(balanced_labels)
        
        tp_balanced = balanced_labels.count(0)
        fp_balanced = balanced_labels.count(1)
        
        print(f"\nAfter rebalancing to target 50:50:")
        print(f"   True Positives: {tp_balanced} ({tp_balanced/len(balanced_labels)*100:.1f}%)")
        print(f"   False Positives: {fp_balanced} ({fp_balanced/len(balanced_labels)*100:.1f}%)")
        print(f"   Total samples: {len(balanced_labels)}")
        print(f"   Imbalance ratio: {fp_balanced/max(tp_balanced,1):.2f}:1")
        print(f"\n✅ Dataset rebalanced successfully!")
        
        return balanced_data, balanced_labels
    
    def step_4_implement_smote(
        self, 
        data: List[Dict], 
        labels: List[int],
        reducer: FalsePositiveReducer
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        P2/P4: Extract features and implement SMOTE if available.
        
        Args:
            data: Training data
            labels: Labels
            reducer: FP reducer model for feature extraction
            
        Returns:
            Processed (X, y) arrays
        """
        print("\n" + "="*80)
        print("STEP 4: FEATURE EXTRACTION & SMOTE SAMPLING (P2/P4)")
        print("="*80)
        
        print("\nExtracting features...")
        X = []
        for finding in data:
            features = reducer.extract_features(finding, {})
            X.append(features.flatten())
        
        X = np.array(X)
        y = np.array(labels)
        
        print(f"✅ Extracted features: {X.shape}")
        print(f"   Samples: {X.shape[0]}")
        print(f"   Features: {X.shape[1]}")
        
        # Apply SMOTE if available
        if SMOTE_AVAILABLE and len(np.unique(y)) > 1:
            print("\n🔄 Applying SMOTE (Synthetic Minority Oversampling)...")
            
            try:
                smote = SMOTETomek(sampling_strategy=0.8, random_state=42)
                X_resampled, y_resampled = smote.fit_resample(X, y)
                
                print(f"✅ SMOTE applied successfully!")
                print(f"   Before: {X.shape[0]} samples")
                print(f"   After: {X_resampled.shape[0]} samples")
                print(f"   Synthetic samples generated: {X_resampled.shape[0] - X.shape[0]}")
                
                tp_count = (y_resampled == 0).sum()
                fp_count = (y_resampled == 1).sum()
                print(f"   TP ratio: {tp_count/len(y_resampled)*100:.1f}%")
                print(f"   FP ratio: {fp_count/len(y_resampled)*100:.1f}%")
                
                return X_resampled, y_resampled
            except Exception as e:
                print(f"⚠️  SMOTE failed ({e}), using original data")
                return X, y
        else:
            print("⚠️  SMOTE not available, using standard resampling")
            return X, y
    
    def step_5_retrain_fp_reducer(
        self, 
        X: np.ndarray, 
        y: np.ndarray
    ) -> Dict:
        """
        Train FP Reducer with enhanced regularization.
        
        Args:
            X: Feature matrix
            y: Labels
            
        Returns:
            Results dictionary
        """
        print("\n" + "="*80)
        print("STEP 5A: RETRAIN FALSE POSITIVE REDUCER (P3)")
        print("="*80)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, stratify=y, random_state=42
        )
        
        print(f"\nTraining set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train with regularization
        print("\nTraining model with regularization...")
        model = RandomForestClassifier(
            n_estimators=100,        # Reduced from 150
            max_depth=8,             # Reduced from 12
            min_samples_split=6,     # Increased from 4
            min_samples_leaf=3,      # Increased from 2
            max_features='sqrt',     # Feature subsampling
            random_state=42,
            class_weight='balanced', # Handle imbalance
            n_jobs=-1
        )
        
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        train_pred = model.predict(X_train_scaled)
        test_pred = model.predict(X_test_scaled)
        
        train_acc = accuracy_score(y_train, train_pred)
        test_acc = accuracy_score(y_test, test_pred)
        test_precision = precision_score(y_test, test_pred, average='weighted')
        test_recall = recall_score(y_test, test_pred, average='weighted')
        test_f1 = f1_score(y_test, test_pred, average='weighted')
        
        # Cross-validation
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
        
        results = {
            'model': 'FP Reducer',
            'train_accuracy': float(train_acc),
            'test_accuracy': float(test_acc),
            'precision': float(test_precision),
            'recall': float(test_recall),
            'f1_score': float(test_f1),
            'cv_mean': float(cv_scores.mean()),
            'cv_std': float(cv_scores.std()),
            'train_test_gap': float(train_acc - test_acc),
            'confusion_matrix': confusion_matrix(y_test, test_pred).tolist()
        }
        
        print(f"\n📊 Results:")
        print(f"   Train Accuracy: {train_acc:.2%}")
        print(f"   Test Accuracy:  {test_acc:.2%}")
        print(f"   Precision:      {test_precision:.2%}")
        print(f"   Recall:         {test_recall:.2%}")
        print(f"   F1-Score:       {test_f1:.2%}")
        print(f"   CV Mean ± Std:  {cv_scores.mean():.2%} ± {cv_scores.std():.2%}")
        print(f"   Train/Test Gap: {train_acc - test_acc:.2%}")
        
        gap = train_acc - test_acc
        if gap > 0.15:
            print(f"   ⚠️  Large gap ({gap:.1%}) - still overfitting")
        elif gap > 0.05:
            print(f"   🟡 Slight gap ({gap:.1%}) - acceptable")
        else:
            print(f"   ✅ Good generalization ({gap:.1%})")
        
        self.results['fp_reducer'] = results
        return results
    
    def step_6_retrain_severity_predictor(
        self,
        X: np.ndarray,
        y: np.ndarray,
        original_data: List[Dict]
    ) -> Dict:
        """Retrain Severity Predictor."""
        print("\n" + "="*80)
        print("STEP 5B: RETRAIN SEVERITY PREDICTOR (P3)")
        print("="*80)
        
        # Extract severity labels from original data
        severity_labels = []
        for finding in original_data:
            severity_labels.append(finding.get('severity', 'medium').lower())
        
        # Map to numeric
        severity_map = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        y_severity = np.array([severity_map.get(s, 2) for s in severity_labels])
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_severity, test_size=0.25, stratify=y_severity, random_state=42
        )
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        print("\nTraining model...")
        model = GradientBoostingClassifier(
            n_estimators=75,
            max_depth=4,
            learning_rate=0.05,
            min_samples_split=6,
            min_samples_leaf=3,
            subsample=0.8,
            random_state=42
        )
        
        model.fit(X_train_scaled, y_train)
        
        train_acc = model.score(X_train_scaled, y_train)
        test_acc = model.score(X_test_scaled, y_test)
        
        results = {
            'model': 'Severity Predictor',
            'train_accuracy': float(train_acc),
            'test_accuracy': float(test_acc),
            'train_test_gap': float(train_acc - test_acc)
        }
        
        print(f"   Train Accuracy: {train_acc:.2%}")
        print(f"   Test Accuracy:  {test_acc:.2%}")
        
        self.results['severity_predictor'] = results
        return results
    
    def run_full_retraining(self, existing_data_file: str = None, num_pseudo_tp: int = 100):
        """
        Execute full retraining pipeline P0-P4.
        
        Args:
            existing_data_file: Path to existing training data
            num_pseudo_tp: Number of pseudo TP samples to generate
        """
        print("\n" + "█"*80)
        print("█" + " "*78 + "█")
        print("█" + "  COMPREHENSIVE MODEL RETRAINING PIPELINE (P0-P4)".center(78) + "█")
        print("█" + " "*78 + "█")
        print("█"*80 + "\n")
        
        try:
            # P0: Generate pseudo TP
            pseudo_tp = self.step_1_generate_pseudo_tp(num_pseudo_tp)
            
            # Load existing data
            existing_data, existing_labels = self.step_2_load_existing_data(existing_data_file)
            
            if not existing_data:
                print("⚠️  Using only pseudo TP data")
                balanced_data = [item['finding'] for item in pseudo_tp]
                balanced_labels = [0] * len(balanced_data)
            else:
                # P1: Merge and rebalance
                balanced_data, balanced_labels = self.step_3_merge_and_balance(
                    existing_data, existing_labels, pseudo_tp
                )
            
            # P2/P4: Feature extraction and SMOTE
            reducer = FalsePositiveReducer()
            X, y = self.step_4_implement_smote(balanced_data, balanced_labels, reducer)
            
            # Retrain models
            self.step_5_retrain_fp_reducer(X, y)
            self.step_6_retrain_severity_predictor(X, y, balanced_data)
            
            # Print summary
            self._print_summary()
            
        except Exception as e:
            print(f"\n❌ Error during retraining: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        return True
    
    def _print_summary(self):
        """Print retraining summary."""
        print("\n" + "="*80)
        print("RETRAINING SUMMARY")
        print("="*80)
        
        for model_name, results in self.results.items():
            print(f"\n{model_name.upper()}:")
            for key, value in results.items():
                if key != 'confusion_matrix':
                    print(f"  {key}: {value}")


def main():
    """Main execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Comprehensive model retraining with data balance')
    parser.add_argument('--data', type=str, help='Path to existing training data')
    parser.add_argument('--pseudo-tp', type=int, default=100, help='Number of pseudo TP samples')
    args = parser.parse_args()
    
    retrainer = ComprehensiveRetrainer()
    success = retrainer.run_full_retraining(args.data, args.pseudo_tp)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
