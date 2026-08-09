"""
train_model.py - Model Training Script for QR Shield ML Classifier (13-Feature Version)
Trains a RandomForestClassifier (n_estimators=200, max_depth=10, random_state=42) on 10,000 dataset samples and exports model.pkl
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from xgboost import XGBClassifier
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

    # 4. Initialize & Train XGBoost Classifier with GridSearchCV
    xgb_base = XGBClassifier(
        random_state=42,
        eval_metric='logloss'
    )
    
    # Define hyperparameter grid to tune and prevent overfitting
    param_grid = {
        'max_depth': [3, 5, 7],
        'learning_rate': [0.01, 0.1, 0.2],
        'n_estimators': [100, 200]
    }
    
    print("[TRAIN] Starting 5-fold Cross-Validation with GridSearchCV...")
    grid_search = GridSearchCV(
        estimator=xgb_base,
        param_grid=param_grid,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        verbose=1
    )
    grid_search.fit(X_train, y_train)
    
    best_xgb_model = grid_search.best_estimator_
    print(f"[TRAIN] Best Hyperparameters: {grid_search.best_params_}")

    # 5. Evaluate Predictions
    y_pred = best_xgb_model.predict(X_test)
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
    for feature, importance in zip(feature_cols, best_xgb_model.feature_importances_):
        print(f"   - {feature:22s}: {importance * 100:.2f}%")

    # 6. Save Model using pickle as 'model.pkl'
    model_filename = 'model.pkl'
    with open(model_filename, 'wb') as f:
        pickle.dump(best_xgb_model, f)

    print("\n[SUCCESS] Saved retrained 13-Feature XGBoost model to 'model.pkl'!")
    return accuracy

if __name__ == '__main__':
    train_and_evaluate()
