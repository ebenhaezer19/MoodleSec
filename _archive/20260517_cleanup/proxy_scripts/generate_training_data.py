#!/usr/bin/env python3
"""
Generate Training Data - Wrapper Script

Easy-to-run script for generating training data.
Run from proxy directory: python3 generate_training_data.py
"""

import sys
import os

# Ensure we're in the right directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.training_data_generator import TrainingDataGenerator


def main():
    """Main data generation function."""
    print("="*80)
    print("TRAINING DATA GENERATOR - MOODLESEC")
    print("="*80)
    print()
    
    # Initialize generator
    generator = TrainingDataGenerator()
    
    # Generate and export data
    print("Generating synthetic training data...")
    print()
    datasets = generator.export_training_data(output_dir="ml/data")
    
    # Print summary
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    
    for name, dataset in datasets.items():
        print(f"\n{name.upper().replace('_', ' ')}:")
        print(f"  Samples: {len(dataset['data'])}")
        print(f"  Description: {dataset['description']}")
    
    print()
    print("="*80)
    print("✅ Training data generated successfully!")
    print("="*80)
    print()
    print("📁 Location: ml/data/")
    print()
    print("Files created:")
    print("  - false_positive_training.json (200 samples)")
    print("  - severity_training.json (200 samples)")
    print("  - anomaly_training.json (300 samples)")
    print("  - rate_limiter_training.json (200 samples)")
    print("  - metadata.json")
    print()
    print("Next step:")
    print("  Train models: python3 train_models.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Generation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
