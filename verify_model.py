"""
Verification Script for Trained QR Shield Model (model.pkl)
Tests model inference on diverse real-world sample URLs
"""

import pickle
import re
from urllib.parse import urlparse

# Load model.pkl
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("============================================================")
    print("[VERIFY] Successfully loaded trained model.pkl")
    print("============================================================")
except Exception as e:
    print(f"FAILED to load model.pkl: {e}")
    exit(1)

SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'shorturl.at', 'cutt.ly']
LOGIN_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'banking', 'auth', 'credential', 'signin', 'password']

def extract_features(url):
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    hostname = parsed.hostname or url_lower

    return [
        len(url),                                                                               # url_length
        1 if url_lower.startswith('https://') or parsed.scheme == 'https' else 0,              # has_https
        url.count('.'),                                                                         # num_dots
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) or '0x' in hostname else 0,          # has_ip
        1 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0,                              # has_login_keyword
        1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0                             # is_shortened
    ]

# Diverse test URL Suite
TEST_URLS = [
    ("https://github.com/security/qr-shield", "Safe"),
    ("https://en.wikipedia.org/wiki/Machine_learning", "Safe"),
    ("https://www.google.com/search?q=cybersecurity", "Safe"),
    ("https://www.amazon.com/dp/B08N5WRWNW", "Safe"),
    ("http://192.168.1.105/login-bank-verification/auth.php", "Malicious"),
    ("http://bit.ly/3x89a_update_account_verify", "Malicious"),
    ("http://appleid-support-verify-security.top/login.html", "Malicious"),
    ("http://paypaI-security-login.club/user/update", "Malicious"),
    ("http://10.0.0.1/admin/login.php?session=9823", "Malicious")
]

print(f"{'URL':<60} | {'EXPECTED':<10} | {'PREDICTED':<10} | {'CONFIDENCE':<10} | {'RESULT'}")
print("-" * 105)

all_passed = True
for url, expected in TEST_URLS:
    feats = [extract_features(url)]
    pred_class = model.predict(feats)[0]
    probs = model.predict_proba(feats)[0]
    
    pred_label = "Malicious" if pred_class == 1 else "Safe"
    conf = round(float(probs[pred_class]) * 100, 1)
    
    status = "PASSED" if pred_label == expected else "FAILED"
    if status == "FAILED":
        all_passed = False
        
    print(f"{url:<60} | {expected:<10} | {pred_label:<10} | {conf:<9}% | {status}")

print("-" * 105)
if all_passed:
    print("[SUMMARY] VERIFICATION SUCCESSFUL: 100% of test URLs predicted correctly!")
else:
    print("[SUMMARY] VERIFICATION FAILED: Discrepancies detected.")
