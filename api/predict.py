import pickle
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys

# Add parent directory to path to import generate_dataset
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generate_dataset import extract_advanced_13_features

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

    return jsonify({
        "url": url,
        "prediction": pred_label,
        "confidence": confidence,
        "features": feats
    })
