import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(CURRENT_DIR, "proxy", "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from attack_classifier import AttackClassifier


def main():
    classifier = AttackClassifier()
    result = classifier.train_from_csv("moodle_attack_dataset.csv")
    print("=== TRAINING RESULT ===")
    print(result)


if __name__ == "__main__":
    main()
