import pickle
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
import requests

# Add parent directory to path to import generate_dataset
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generate_dataset import extract_advanced_13_features

def check_gsb(url):
    api_key = os.environ.get('GSB_API_KEY')
    if not api_key:
        return "Not Checked"
    payload = {
        "client": { "clientId": "qr-shield", "clientVersion": "1.0.0" },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}", json=payload, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if "matches" in data and len(data["matches"]) > 0:
                return "Flagged"
            return "Clean"
    except Exception:
        pass
    return "Error"

app = Flask(__name__)
CORS(app)

# Load trained 13-feature Random Forest model
MODEL = None
model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model.pkl')
try:
    with open(model_path, 'rb') as f:
        MODEL = pickle.load(f)
    print("[SUCCESS] Flask ML Microservice loaded 13-feature model.pkl!")
except Exception as e:
    print(f"[WARNING] Failed to load model.pkl: {e}")

FEATURE_COLS = [
    'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdomains',
    'has_at_symbol', 'has_hyphen_in_domain', 'has_login_keyword', 'url_entropy',
    'tld_risk_score', 'domain_length', 'is_shortened', 'is_whitelisted'
]

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json() or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    feats = extract_advanced_13_features(url)
    
    if MODEL is None:
        # Fallback heuristic
        pred_label = "Malicious" if (feats['has_ip'] or feats['is_shortened'] or feats['has_login_keyword']) and not feats['is_whitelisted'] else "Safe"
        confidence = 85.0
    else:
        input_array = np.array([[feats[col] for col in FEATURE_COLS]])
        pred_class = MODEL.predict(input_array)[0]
        probs = MODEL.predict_proba(input_array)[0]
        confidence = round(float(probs[pred_class]) * 100, 2)
        pred_label = "Safe" if pred_class == 0 else "Malicious"

    gsb_status = check_gsb(url)

    return jsonify({
        "url": url,
        "prediction": pred_label,
        "confidence": confidence,
        "gsb_status": gsb_status,
        "features": feats
    })
