"""
test_model.py - Simple ML Model Verification Script
Verifies model.pkl predictions, feature extraction, and model score on test dataset.
"""

import pickle
import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.model_selection import train_test_split

# 1. Load trained model using pickle
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

# Shortener domains & Login keywords for feature extraction
SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'shorturl.at', 'cutt.ly']
LOGIN_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'banking', 'auth', 'credential', 'signin', 'password']

# 2. Feature Extraction Function
def extract_features(url):
    url_str = str(url).strip()
    url_lower = url_str.lower()
    
    try:
        parsed = urlparse(url_lower)
        hostname = parsed.hostname or url_lower
    except Exception:
        hostname = url_lower

    url_length = len(url_str)
    has_https = 1 if url_lower.startswith('https://') or (parsed.scheme == 'https') else 0
    num_dots = url_str.count('.')
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) or re.search(r'0x[0-9a-f]+', hostname) else 0
    has_login_keyword = 1 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0
    is_shortened = 1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0

    return {
        'url_length': url_length,
        'has_https': has_https,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_login_keyword': has_login_keyword,
        'is_shortened': is_shortened
    }

# 3. Small List of Test URLs
test_urls = [
    "https://google.com",
    "https://github.com",
    "http://bit.ly/test",
    "http://192.168.1.1/login",
    "http://fake-bank-login.com"
]

print("=" * 70)
print("[TEST] Testing Trained ML Model (model.pkl)")
print("=" * 70)

# 4. Predict each URL
for url in test_urls:
    feats_dict = extract_features(url)
    df_feat = pd.DataFrame([feats_dict])
    
    pred_class = int(model.predict(df_feat)[0])
    probs = model.predict_proba(df_feat)[0]
    confidence = round(float(probs[pred_class]) * 100, 2)
    prediction = "Malicious" if pred_class == 1 else "Safe"
    
    print(f"\nURL: {url}")
    print(f"Features: {feats_dict}")
    print(f"Prediction: {prediction}")
    print(f"Confidence: {confidence}%")

print("\n" + "=" * 70)

# 5. Calculate and print model accuracy on test dataset
df = pd.read_csv('dataset.csv')
feature_cols = ['url_length', 'has_https', 'num_dots', 'has_ip', 'has_login_keyword', 'is_shortened']
X = df[feature_cols]
y = df['label']

_, X_test, _, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
accuracy = model.score(X_test, y_test)

print(f"Model Accuracy (X_test, y_test): {accuracy * 100:.2f}%")
print("=" * 70)
