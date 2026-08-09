"""
Dataset Generator for QR Shield ML Classifier (Advanced 8-Feature Version)
Generates 2,000+ balanced sample URLs (1,000 Safe, 1,000 Malicious) with whitelisting and TLD risk metrics.
"""

import csv
import re
from urllib.parse import urlparse
import random

SAFE_DOMAINS_WHITELIST = [
    'google.com', 'wikipedia.org', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'stackoverflow.com', 'cloudflare.com', 'w3schools.com', 'youtube.com',
    'linkedin.com', 'twitter.com', 'facebook.com', 'nytimes.com', 'bbc.com',
    'mit.edu', 'stanford.edu', 'harvard.edu', 'nih.gov', 'usa.gov', 'pypi.org',
    'npmjs.com', 'scikit-learn.org', 'khanacademy.org', 'reddit.com', 'geeksforgeeks.org',
    'kaggle.com', 'huggingface.co', 'bloomberg.com', 'reuters.com', 'medium.com', 'httpbin.org'
]

HIGH_RISK_TLDS = ['.top', '.xyz', '.buzz', '.club', '.work', '.kim', '.info', '.online', '.site', '.vip', '.monster', '.zip', '.mov']
SAFE_TLDS = ['.gov', '.edu', '.org', '.mil', '.int']

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cutt.ly',
    'qr.ae', 'rb.gy', 'v.gd', 't.ly', 'clck.ru', 's.id', 'short.gy'
]

LOGIN_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'banking',
    'auth', 'credential', 'signin', 'password', 'confirm', 'wallet'
]

def extract_advanced_features(url):
    """
    Extracts 8 numerical features from a URL string:
    1. url_length: Total length of URL string
    2. has_https: 1 if HTTPS, 0 if HTTP
    3. num_dots: Count of '.' characters
    4. has_ip: 1 if raw IP host or hex IP address, 0 otherwise
    5. has_login_keyword: 1 if suspicious auth keyword present, 0 otherwise
    6. is_shortened: 1 if link shortener, 0 otherwise
    7. is_whitelisted: 1 if domain in trusted whitelist, 0 otherwise
    8. tld_risk_score: 0 (Safer .gov/.edu/.org), 1 (Standard .com/.net), 2 (High-Risk .top/.xyz/.buzz)
    """
    url_str = str(url).strip()
    url_lower = url_str.lower()
    
    try:
        parsed = urlparse(url_lower if '://' in url_lower else 'https://' + url_lower)
        hostname = parsed.hostname or url_lower
    except Exception:
        hostname = url_lower

    url_length = len(url_str)
    has_https = 1 if url_lower.startswith('https://') or (parsed.scheme == 'https') else 0
    num_dots = url_str.count('.')
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) or re.search(r'0x[0-9a-f]+', hostname) else 0
    has_login_keyword = 1 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0
    is_shortened = 1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0
    
    # Whitelist & TLD Analysis (Improvement: .org, .gov, .edu are automatically trusted)
    is_whitelisted = 1 if (any(hostname.endswith(wd) for wd in SAFE_DOMAINS_WHITELIST) or any(hostname.endswith(stld) for stld in ['.gov', '.edu', '.org'])) else 0
    
    tld_risk_score = 1 # Default neutral .com/.net/.io
    if any(hostname.endswith(stld) for stld in SAFE_TLDS):
        tld_risk_score = 0 # High Trust (.gov, .edu, .org)
    elif any(hostname.endswith(rtld) for rtld in HIGH_RISK_TLDS):
        tld_risk_score = 2 # High Risk (.top, .xyz, .buzz)

    return {
        'url_length': url_length,
        'has_https': has_https,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_login_keyword': has_login_keyword,
        'is_shortened': is_shortened,
        'is_whitelisted': is_whitelisted,
        'tld_risk_score': tld_risk_score
    }

def main():
    random.seed(42)
    rows = []

    # 1. Generate 1,000 Safe Real-World URLs (label = 0)
    for _ in range(1000):
        domain = random.choice(SAFE_DOMAINS_WHITELIST)
        sub = random.choice(["docs", "support", "blog", "news", "developer", "api", "help", ""])
        path = random.choice(["/index.html", "/article/2026/security", "/user/profile", "/docs/api/v1", "/questions/9842", "/search?q=test", ""])
        scheme = random.choice(["https://", "https://", "https://", "http://"]) # Include HTTP safe sites to avoid marking HTTP always malicious!
        
        full_url = f"{scheme}{sub + '.' if sub else ''}{domain}{path}"
        feats = extract_advanced_features(full_url)
        feats['label'] = 0
        rows.append(feats)

    # 2. Generate 1,000 Malicious Real-World Phishing URLs (label = 1)
    phish_words = ["login", "verify", "account-update", "secure-banking", "auth-identity", "confirm-wallet", "security-alert"]
    phish_tlds = [".top", ".xyz", ".buzz", ".club", ".work", ".kim", ".info", ".online", ".site"]
    
    for _ in range(1000):
        is_ip_type = random.random() < 0.25
        is_shortener_type = random.random() < 0.25
        
        if is_ip_type:
            host = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            path = f"/{random.choice(phish_words)}/index.php?id={random.randint(1000,9999)}"
            full_url = f"http://{host}{path}"
        elif is_shortener_type:
            sd = random.choice(SHORTENER_DOMAINS)
            path = f"/{random.choice(phish_words)}_{random.randint(100,999)}"
            full_url = f"http://{sd}{path}"
        else:
            brand = random.choice(["paypaI", "g00gle", "appIe-id", "microsoft-verify", "binance-secure", "bankofamerıca"])
            tld = random.choice(phish_tlds)
            path = f"/{random.choice(phish_words)}/update.html"
            scheme = random.choice(["http://", "http://", "https://"]) # Include HTTPS phishing sites!
            full_url = f"{scheme}{brand}{tld}{path}"
            
        feats = extract_advanced_features(full_url)
        feats['label'] = 1
        rows.append(feats)

    # Write to dataset.csv
    fieldnames = ['url_length', 'has_https', 'num_dots', 'has_ip', 'has_login_keyword', 'is_shortened', 'is_whitelisted', 'tld_risk_score', 'label']
    with open('dataset.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[SUCCESS] Generated 2,000 balanced sample URLs (1,000 Safe, 1,000 Malicious) into dataset.csv!")

if __name__ == '__main__':
    main()
