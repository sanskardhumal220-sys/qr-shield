import time
import pickle
import numpy as np
from generate_dataset import extract_advanced_13_features

def test_stability():
    url = "https://www.investopedia.com/terms/q/quick-response-qr-code.asp"
    
    print("="*60)
    print(f"Running ML Stability Test (10 Iterations)")
    print(f"Target URL: {url}")
    print("="*60)

    try:
        model = pickle.load(open('model.pkl', 'rb'))
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    FEATURE_COLS = [
        'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdomains',
        'has_at_symbol', 'has_hyphen_in_domain', 'has_login_keyword', 'url_entropy',
        'tld_risk_score', 'domain_length', 'is_shortened', 'is_whitelisted'
    ]

    results = []

    for i in range(1, 11):
        try:
            feats = extract_advanced_13_features(url)
            input_array = np.array([[feats[col] for col in FEATURE_COLS]])
            pred_class = model.predict(input_array)[0]
            probs = model.predict_proba(input_array)[0]
            confidence = round(float(probs[pred_class]) * 100, 2)
            pred_label = "Safe" if pred_class == 0 else "Malicious"
            
            results.append((pred_label, confidence))
            print(f"Iteration {i:2d}: Prediction={pred_label:9s} | Confidence={confidence}%")
        except Exception as e:
            print(f"Iteration {i:2d}: Error - {e}")

    print("-" * 60)
    unique_results = set(results)
    if len(unique_results) == 1:
        print("[SUCCESS] Model is 100% deterministic and stable.")
    else:
        print("[FAILED] Model produced varying results for the same URL!")
        print(f"Unique Outputs: {unique_results}")

if __name__ == '__main__':
    test_stability()
