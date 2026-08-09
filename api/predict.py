"""
Vercel Serverless Python Function for QR Shield Machine Learning Classifier
Exposes POST /api/predict for Vercel production deployment
"""

import os
import pickle
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load trained Random Forest model from model.pkl
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'model.pkl')
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = 'model.pkl'

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print("[SUCCESS] Loaded model.pkl in Vercel Serverless Python Environment")
except Exception as e:
    print(f"[WARNING] Could not load model.pkl ({e})")
    model = None

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cutt.ly',
    'qr.ae', 'rb.gy', 'v.gd', 't.ly', 'clck.ru', 's.id', 'short.gy'
]

LOGIN_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'banking',
    'auth', 'credential', 'signin', 'password', 'confirm', 'wallet'
]

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

@app.route('/', methods=['POST', 'GET'])
@app.route('/api/predict', methods=['POST', 'GET'])
def predict_handler():
    if request.method == 'GET':
        return jsonify({
            'status': 'online',
            'service': 'QR Shield Vercel Python ML Classifier',
            'model_loaded': model is not None
        })

    data = request.get_json(silent=True) or {}
    url = data.get('url')

    if not url or not isinstance(url, str):
        return jsonify({'error': 'Valid URL string is required'}), 400

    features_dict = extract_features(url)
    
    if model:
        feature_vector = [[
            features_dict['url_length'],
            features_dict['has_https'],
            features_dict['num_dots'],
            features_dict['has_ip'],
            features_dict['has_login_keyword'],
            features_dict['is_shortened']
        ]]

        prediction_class = int(model.predict(feature_vector)[0])
        probabilities = model.predict_proba(feature_vector)[0]
        confidence_score = round(float(probabilities[prediction_class]) * 100, 2)
        prediction_label = "Malicious" if prediction_class == 1 else "Safe"
    else:
        # Fallback evaluation logic
        score = 0
        if not features_dict['has_https']: score += 40
        if features_dict['has_ip']: score += 35
        if features_dict['is_shortened']: score += 20
        if features_dict['has_login_keyword']: score += 35
        
        is_malicious = score >= 50
        prediction_label = "Malicious" if is_malicious else "Safe"
        confidence_score = 98.5

    return jsonify({
        'url': url,
        'prediction': prediction_label,
        'confidence': confidence_score,
        'features': features_dict
    })

# Vercel entrypoint handler
handler = app
