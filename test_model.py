"""
test_model.py - Simple Verification Script for QR Shield ML Classifier (13 Features)
Loads model.pkl and tests real-world URLs:
- https://google.com
- https://wikipedia.org
- http://bit.ly/test
- http://fake-login-bank.com
"""

import pickle
import pandas as pd
from generate_dataset import extract_advanced_13_features

def test_ml_model():
    print("=" * 75)
    print("[TEST] 13-Feature Upgraded ML Model Verification (model.pkl)")
    print("=" * 75)

    # 1. Load trained Random Forest model
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)

    # 2. Test Real-World URLs requested by User
    test_urls = [
        "https://google.com",
        "https://wikipedia.org",
        "http://bit.ly/test",
        "http://fake-login-bank.com"
    ]

    feature_cols = [
        'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdomains',
        'has_at_symbol', 'has_hyphen_in_domain', 'has_login_keyword', 'url_entropy',
        'tld_risk_score', 'domain_length', 'is_shortened', 'is_whitelisted'
    ]

    # 3. Predict and Display Results for Each URL
    for url in test_urls:
        feats_dict = extract_advanced_13_features(url)
        df_input = pd.DataFrame([feats_dict])[feature_cols]

        pred_class = model.predict(df_input)[0]
        probs = model.predict_proba(df_input)[0]
        confidence = probs[pred_class] * 100

        pred_label = "Safe" if pred_class == 0 else "Malicious"

        print(f"\nURL: {url}")
        print(f"Extracted 13 Features: {feats_dict}")
        print(f"Prediction: {pred_label}")
        print(f"Confidence Score: {confidence:.2f}%")

    # 4. Evaluate Overall Accuracy on Dataset
    df = pd.read_csv('dataset.csv')
    X_test = df[feature_cols]
    y_test = df['label']
    acc = model.score(X_test, y_test)

    print("\n" + "=" * 75)
    print(f"Model Score Accuracy (10,000 Samples): {acc * 100:.2f}%")
    print("=" * 75)

if __name__ == '__main__':
    test_ml_model()
