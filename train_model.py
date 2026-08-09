"""
train_model.py - Model Training Script for QR Shield ML Classifier (13-Feature Version)
Trains a RandomForestClassifier (n_estimators=200, max_depth=10, random_state=42) on 10,000 dataset samples and exports model.pkl
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def train_and_evaluate():
    print("=" * 70)
    print("[TRAIN] QR Shield Upgraded ML Model Training Routine (10,000 Samples)")
    print("=" * 70)

    # 1. Load Dataset
    df = pd.read_csv('dataset.csv')
    print(f"[DATA] Dataset Loaded: {len(df)} samples")
    print(f"   - Safe URLs (0): {len(df[df['label'] == 0])}")
    print(f"   - Malicious URLs (1): {len(df[df['label'] == 1])}")

    # 2. 13 Advanced Feature Columns
    feature_cols = [
        'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdomains',
        'has_at_symbol', 'has_hyphen_in_domain', 'has_login_keyword', 'url_entropy',
        'tld_risk_score', 'domain_length', 'is_shortened', 'is_whitelisted'
    ]
    X = df[feature_cols]
    y = df['label']

    # 3. Train / Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[SPLIT] Data Split: {len(X_train)} training samples, {len(X_test)} test samples")

    # 4. Initialize & Train Random Forest Classifier with requested hyper-parameters
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        criterion='gini'
    )
    rf_model.fit(X_train, y_train)

    # 5. Evaluate Predictions
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "-" * 70)
    print(f"[ACCURACY] Model Accuracy Score: {accuracy * 100:.2f}%")
    print("-" * 70)
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe (0)', 'Malicious (1)']))
    print("Confusion Matrix:")
    print(cm)
    print("-" * 70)

    # Feature Importance Breakdown
    print("Feature Importances:")
    for feature, importance in zip(feature_cols, rf_model.feature_importances_):
        print(f"   - {feature:22s}: {importance * 100:.2f}%")

    # 6. Save Model using pickle as 'model.pkl'
    model_filename = 'model.pkl'
    with open(model_filename, 'wb') as f:
        pickle.dump(rf_model, f)

    print("\n[SUCCESS] Saved retrained 13-Feature Random Forest model to 'model.pkl'!")
    return accuracy

if __name__ == '__main__':
    train_and_evaluate()
