import sys
import pickle
import requests
import pandas as pd
import numpy as np
import io
from generate_dataset import extract_advanced_13_features
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def fetch_urlhaus_malicious(limit=100):
    print(f"Fetching {limit} live malicious URLs from URLHaus...")
    try:
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        lines = resp.text.split('\n')
        urls = []
        for line in lines:
            if not line or line.startswith('#'):
                continue
            parts = line.split('","')
            if len(parts) > 2:
                mal_url = parts[2].strip('"')
                urls.append(mal_url)
                if len(urls) >= limit:
                    break
        print(f"  -> Fetched {len(urls)} malicious URLs")
        return urls
    except Exception as e:
        print(f"Failed to fetch URLHaus: {e}")
        return []

def get_safe_urls(limit=100):
    print(f"Loading {limit} known safe URLs (Top Domains)...")
    base_domains = [
        "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
        "yahoo.com", "amazon.com", "instagram.com", "linkedin.com", "twitter.com",
        "netflix.com", "github.com", "microsoft.com", "apple.com", "zoom.us",
        "reddit.com", "quora.com", "stackoverflow.com", "twitch.tv", "bing.com",
        "office.com", "nytimes.com", "cnn.com", "bbc.co.uk", "wsj.com",
        "forbes.com", "bloomberg.com", "reuters.com", "washingtonpost.com", "theguardian.com",
        "ebay.com", "walmart.com", "etsy.com", "target.com", "homedepot.com",
        "bestbuy.com", "ikea.com", "craigslist.org", "zillow.com", "airbnb.com",
        "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "capitalone.com",
        "americanexpress.com", "citi.com", "discover.com", "usbank.com", "fidelity.com",
        "adobe.com", "salesforce.com", "oracle.com", "sap.com", "ibm.com",
        "cisco.com", "intel.com", "amd.com", "nvidia.com", "qualcomm.com",
        "spotify.com", "pandora.com", "soundcloud.com", "hulu.com", "disneyplus.com",
        "hbomax.com", "vimeo.com", "dailymotion.com", "imdb.com", "rottentomatoes.com",
        "weather.com", "accuweather.com", "wunderground.com", "webmd.com", "mayoclinic.org",
        "nih.gov", "cdc.gov", "who.int", "nasa.gov", "noaa.gov",
        "usps.com", "ups.com", "fedex.com", "dhl.com", "expedia.com",
        "booking.com", "kayak.com", "tripadvisor.com", "skyscanner.net", "hotels.com",
        "yelp.com", "opentable.com", "grubhub.com", "doordash.com", "ubereats.com"
    ]
    
    urls = []
    for domain in base_domains:
        urls.append(f"https://www.{domain}/")
        urls.append(f"https://{domain}/login")
        if len(urls) >= limit:
            break
            
    return urls[:limit]

def run_validation():
    print("=" * 70)
    print("[VALIDATION] Real-World Dataset Accuracy Test")
    print("=" * 70)
    
    try:
        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)
        print("[OK] Calibrated Model Loaded")
    except Exception as e:
        print(f"[ERROR] Failed to load model.pkl: {e}")
        sys.exit(1)
        
    malicious_urls = fetch_urlhaus_malicious(100)
    safe_urls = get_safe_urls(100)
    
    if len(malicious_urls) < 50 or len(safe_urls) < 50:
        print("[ERROR] Failed to collect enough test data.")
        sys.exit(1)
        
    print("\n[PROCESS] Extracting features for all URLs...")
    X_test = []
    y_test = []
    
    for url in malicious_urls:
        feats = extract_advanced_13_features(url)
        X_test.append(feats)
        y_test.append(1)
        
    for url in safe_urls:
        feats = extract_advanced_13_features(url)
        X_test.append(feats)
        y_test.append(0)
        
    feature_cols = [
        'url_length', 'num_dots', 'has_https', 'has_ip', 'num_subdomains',
        'has_at_symbol', 'has_hyphen_in_domain', 'has_login_keyword', 'url_entropy',
        'tld_risk_score', 'domain_length', 'is_shortened', 'is_whitelisted'
    ]
    
    df_test = pd.DataFrame(X_test, columns=feature_cols)
    
    print("\n[PREDICT] Running calibrated inference...")
    y_pred = model.predict(df_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    fp_rate = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    
    print("\n" + "=" * 70)
    print("🎯 REAL-WORLD PERFORMANCE REPORT")
    print("=" * 70)
    print(f"Total Samples Tested : {len(y_test)}")
    print(f"Accuracy             : {accuracy * 100:.2f}%  (Target: >= 90%)")
    print(f"Precision            : {precision * 100:.2f}%")
    print(f"Recall               : {recall * 100:.2f}%")
    print(f"F1 Score             : {f1 * 100:.2f}%")
    print(f"False Positive Rate  : {fp_rate * 100:.2f}%   (Target: < 10%)")
    print("-" * 70)
    
    target_met = accuracy >= 0.90 and fp_rate < 0.10
    if target_met:
        print("✅ SUCCESS: Model meets production targets on real-world data!")
    else:
        print("❌ WARNING: Model failed to meet real-world targets.")

if __name__ == '__main__':
    run_validation()
