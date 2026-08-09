"""
Flask Microservice API for QR Shield Machine Learning URL Classifier
Serves POST /predict endpoint on http://localhost:5001
"""

import pickle
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load trained Random Forest model from model.pkl
MODEL_PATH = 'model.pkl'
try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print("[SUCCESS] Successfully loaded machine learning model from model.pkl")
except Exception as e:
    print(f"[WARNING] Could not load model.pkl ({e}). Run train_model.py first.")
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
    """
    Extracts 6 numerical features from a URL string for ML prediction:
    1. url_length: Length of URL string
    2. has_https: 1 if scheme is https, 0 otherwise
    3. num_dots: Count of '.' characters
    4. has_ip: 1 if hostname contains IPv4 or hex IP address, 0 otherwise
    5. has_login_keyword: 1 if URL contains phishing keywords, 0 otherwise
    6. is_shortened: 1 if domain matches shortener list, 0 otherwise
    """
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
    
    # Check IPv4 or hex IP address
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) or re.search(r'0x[0-9a-f]+', hostname) else 0
    
    # Check suspicious login keywords
    has_login_keyword = 1 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0
    
    # Check link shorteners
    is_shortened = 1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0

    return {
        'url_length': url_length,
        'has_https': has_https,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_login_keyword': has_login_keyword,
        'is_shortened': is_shortened
    }

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'online',
        'service': 'QR Shield Flask ML Classifier API',
        'model_loaded': model is not None
    })

@app.route('/predict', methods=['POST'])
def predict():
    """
    POST /predict
    Input JSON: { "url": "https://example.com" }
    Output JSON: { "prediction": "Safe" | "Malicious", "confidence": 98.5, ... }
    """
    if not model:
        return jsonify({'error': 'Model not loaded on server. Run train_model.py first.'}), 500

    data = request.get_json(silent=True) or {}
    url = data.get('url')

    if not url or not isinstance(url, str):
        return jsonify({'error': 'Valid URL string is required in request body.'}), 400

    # Feature Extraction
    features_dict = extract_features(url)
    feature_vector = [[
        features_dict['url_length'],
        features_dict['has_https'],
        features_dict['num_dots'],
        features_dict['has_ip'],
        features_dict['has_login_keyword'],
        features_dict['is_shortened']
    ]]

    # Model Inference
    prediction_class = int(model.predict(feature_vector)[0])
    probabilities = model.predict_proba(feature_vector)[0]
    confidence_score = round(float(probabilities[prediction_class]) * 100, 2)

    prediction_label = "Malicious" if prediction_class == 1 else "Safe"

    return jsonify({
        'url': url,
        'prediction': prediction_label,
        'confidence': confidence_score,
        'raw_label': prediction_class,
        'probabilities': {
            'safe': round(float(probabilities[0]) * 100, 2),
            'malicious': round(float(probabilities[1]) * 100, 2)
        },
        'features': features_dict
    })

if __name__ == '__main__':
    print("=" * 60)
    print("[START] QR Shield Flask ML Service Running on http://localhost:5001")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5001, debug=False)
