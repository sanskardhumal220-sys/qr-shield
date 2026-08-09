"""
Dataset Generator for QR Shield ML Classifier
"""
import csv
import re
from urllib.parse import urlparse

# Representative sample URLs for training dataset
SAFE_URLS = [
    "https://github.com/security/qr-shield",
    "https://www.google.com/search?q=cybersecurity",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.apple.com/support",
    "https://microsoft.com/en-us/security",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.nytimes.com/section/technology",
    "https://github.com/scikit-learn/scikit-learn",
    "https://www.cloudflare.com/learning/access-management/phishing-attacks/",
    "https://medium.com/topic/cybersecurity",
    "https://www.reddit.com/r/netsec/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://www.bbc.com/news/technology",
    "https://www.pypi.org/project/scikit-learn/",
    "https://www.npmJS.com/package/jsqr",
    "https://www.scikit-learn.org/stable/modules/ensemble.html",
    "https://www.khanacademy.org/computing/computer-science",
    "https://news.ycombinator.com/",
    "https://www.w3schools.com/html/default.asp",
    "https://caniuse.com/",
    "https://www.geeksforgeeks.org/machine-learning/",
    "https://www.kaggle.com/datasets",
    "https://huggingface.co/models",
    "https://www.mit.edu/",
    "https://www.stanford.edu/",
    "https://www.harvard.edu/",
    "https://www.reuters.com/technology",
    "https://www.bloomberg.com/technology"
]

MALICIOUS_URLS = [
    "http://192.168.1.105/login-bank-verification/auth.php?id=94032",
    "http://bit.ly/3x89a_update_account_verify",
    "http://secure-paypal-login-update-account.xyz/verify",
    "http://appleid-support-verify-security.top/login.html",
    "http://10.0.0.1/admin/login.php?session=9823472",
    "http://g00gle-security-login-verify.buzz/auth",
    "http://tinyurl.com/y8x9z7w2-banking-verify",
    "http://paypaI-security-login.club/user/update",
    "http://bankofamerıca-account-update.info/login",
    "http://169.254.169.254/latest/meta-data/credentials",
    "http://is.gd/verify_login_account_99823",
    "http://binance-login-verification-secure.online/auth",
    "http://microsoft-verify-account-credential.xyz/",
    "http://192.168.0.1/login.html?user=admin&pass=secret",
    "http://shorturl.at/xK921_login_banking",
    "http://0x7f000001/admin/auth.php",
    "http://account-verify-login-update-pass.top/",
    "http://t.co/98x21A_verify_account",
    "http://security-update-bank-login.buzz/verify",
    "http://verify-account-paypal-secure-login.kim/",
    "http://192.168.1.1/router-login-verify",
    "http://cutt.ly/login_verify_bank_security",
    "http://my-bank-login-verify-account-secure.xyz/app",
    "http://login-verify-credential-update-security.top/",
    "http://goo.gl/x98a1-login-verify"
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cutt.ly',
    'qr.ae', 'rb.gy', 'v.gd', 't.ly', 'clck.ru', 's.id', 'short.gy'
]

LOGIN_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'banking', 'auth', 'credential', 'signin', 'password', 'confirm', 'wallet']

def extract_features_from_url(url):
    """
    Extracts numerical features from a URL string:
    - url_length: Length of URL
    - has_https: 1 if scheme is https, 0 otherwise
    - num_dots: Count of '.' characters
    - has_ip: 1 if hostname is IP address or contains IP pattern, 0 otherwise
    - has_login_keyword: 1 if contains phishing keywords, 0 otherwise
    - is_shortened: 1 if domain matches shortener list, 0 otherwise
    """
    url_lower = url.lower()
    parsed = urlparse(url_lower)
    hostname = parsed.hostname or url_lower

    url_length = len(url)
    has_https = 1 if parsed.scheme == 'https' or url_lower.startswith('https://') else 0
    num_dots = url.count('.')
    
    # IP Host check
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname) or re.search(r'0x[0-9a-f]+', hostname) else 0
    
    # Login keywords check
    has_login_keyword = 1 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0
    
    # Shortener check
    is_shortened = 1 if any(sd in hostname for sd in SHORTENER_DOMAINS) else 0

    return {
        'url_length': url_length,
        'has_https': has_https,
        'num_dots': num_dots,
        'has_ip': has_ip,
        'has_login_keyword': has_login_keyword,
        'is_shortened': is_shortened
    }

def main():
    rows = []
    
    # Process Safe URLs (label = 0)
    for url in SAFE_URLS:
        feats = extract_features_from_url(url)
        feats['label'] = 0
        rows.append(feats)
        
    # Process Malicious URLs (label = 1)
    for url in MALICIOUS_URLS:
        feats = extract_features_from_url(url)
        feats['label'] = 1
        rows.append(feats)

    # Synthesize additional variations for robust model generalization (total 1000+ samples)
    import random
    random.seed(42)

    for _ in range(500):
        # Synthetic Safe URL
        domain = random.choice(["github.com", "google.com", "wikipedia.org", "apple.com", "microsoft.com", "amazon.com", "nytimes.com", "bbc.com", "stackoverflow.com", "cloudflare.com"])
        sub = random.choice(["docs", "app", "blog", "api", "support", "news", "learn", ""])
        path = random.choice(["/security/guide", "/item/9402", "/article/2026", "/docs/v2", "/search?q=test", "/home"])
        s_url = f"https://{sub + '.' if sub else ''}{domain}{path}"
        feats = extract_features_from_url(s_url)
        feats['label'] = 0
        rows.append(feats)

        # Synthetic Malicious URL
        m_domain = random.choice(["login-verify-account.xyz", "secure-bank-update.top", "192.168.1.100", "bit.ly/x942a", "tinyurl.com/verify88", "paypaI-auth-login.club"])
        m_path = random.choice(["/auth.php?token=94827", "/verify-account/login", "/banking/credential", "/signin/password"])
        m_proto = random.choice(["http://", "http://"])
        m_url = f"{m_proto}{m_domain}{m_path}"
        feats = extract_features_from_url(m_url)
        feats['label'] = 1
        rows.append(feats)

    # Write to dataset.csv
    fieldnames = ['url_length', 'has_https', 'num_dots', 'has_ip', 'has_login_keyword', 'is_shortened', 'label']
    with open('dataset.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[SUCCESS] Generated dataset.csv with {len(rows)} samples successfully!")

if __name__ == '__main__':
    main()
