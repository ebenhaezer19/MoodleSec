#!/usr/bin/env python3
"""
Train ML Models - Wrapper Script

Easy-to-run script for training all ML models.
Run from proxy directory: python3 train_models.py
"""

import sys
import os

# Ensure we're in the right directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.model_trainer import ModelTrainer


def main():
    """Main training function."""
    print("="*80)
    print("ML MODEL TRAINING - MOODLESEC")
    print("="*80)
    print()
    
    # Initialize trainer
    trainer = ModelTrainer(data_dir="ml/data")
    
    # Train all models
    print("Starting training pipeline...")
    print()
    results = trainer.train_all_models(use_existing_data=False)
    
    # Validate models
    print()
    validation = trainer.validate_models()
    
    # Print summary
    print()
    trainer.print_summary()
    
    print()
    print("="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print()
    print("📁 Models saved to: ml/models/")
    print("📊 Training data: ml/data/")
    print("📝 Report: ml/data/training_report.json")
    print()
    print("Next steps:")
    print("  1. Test models: python3 test_ml_modules.py")
    print("  2. Check status: curl http://localhost:8999/ml/status")
    print("  3. Start proxy: python3 app.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
