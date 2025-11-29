import re
import json
from difflib import SequenceMatcher
from email.utils import parseaddr
from app.utils.feature_extractor import FeatureExtractor

# ----------------------------
# Load domain blacklist
# ----------------------------
def load_blacklist():
    try:
        with open('app/utils/blacklist.json') as f:
            return json.load(f)
    except:
        return {
            "domains": ["scamoffers.org", "phishing.com"],
            "ips": ["192.168.1.1", "10.0.0.1"]
        }

# ----------------------------
# Extract sender domain
# ----------------------------
def extract_domain(email):
    _, domain = parseaddr(email)
    if '@' in domain:
        return domain.split('@')[-1].lower()
    return domain.lower()

# ----------------------------
# Check for slight variations of legit domains
# ----------------------------
def is_typo(domain, legit_domain):
    if domain == legit_domain:
        return False

    # Length difference too high → ignore
    if abs(len(domain) - len(legit_domain)) > 2:
        return False

    # Similarity check
    if SequenceMatcher(None, domain, legit_domain).ratio() > 0.90:
        return True

    # Leetspeak replacements
    substitutions = {
        'o': '0', 'l': '1', 'i': '1', 'e': '3',
        'a': '4', 's': '5', 'b': '6', 't': '7', 'g': '9'
    }

    for o, s in substitutions.items():
        if legit_domain.replace(o, s) == domain:
            return True
        if domain.replace(s, o) == legit_domain:
            return True

    return False

# ----------------------------
# Spam keyword detector
# ----------------------------
def detect_spam_keywords(text):
    keywords = [
        'urgent', 'verify', 'account', 'suspended', 'won', 'prize',
        'free', 'offer', 'click', 'below', 'limited', 'time',
        'action required', 'password', 'login', 'security alert',
        'confirm', 'billing'
    ]
    return [kw for kw in keywords if kw in text.lower()]

# ----------------------------
# FIXED phishing URL detection (less aggressive)
# ----------------------------
def detect_phishing_urls(text, blacklist_domains):

    urls = re.findall(r'(https?://[^\s]+)', text)
    phishing = []
    extractor = FeatureExtractor()

    SAFE_BRANDS = [
        'amazon', 'google', 'gmail', 'microsoft', 'outlook',
        'yahoo', 'office', 'apple', 'github', 'paypal', 'netflix'
    ]

    for url in urls:
        domain = re.sub(r'https?://([^/]+).*', r'\1', url).lower()
        url_lower = url.lower()

        reasons = 0  # count phishing indicators

        # Blacklist domain → strong reason
        if domain in blacklist_domains:
            reasons += 2

        # Shortener URLs
        if any(s in url_lower for s in ['bit.ly', 'tinyurl.com', 'goo.gl']):
            reasons += 1

        # IP address URLs (weaker rule)
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            reasons += 0.5

        # Advanced URL features
        features = extractor.extract_features(url)

        if features.get('has_suspicious_tld'):
            reasons += 1

        if features.get('has_phishing_keyword'):
            reasons += 1

        # Brand impersonation but IGNORE verified brands
        if features.get('has_brand_impersonation'):
            if not any(brand in domain for brand in SAFE_BRANDS):
                reasons += 1

        # FINAL: mark as phishing only if >= 2 indicators match
        if reasons >= 2:
            phishing.append(url)

    return phishing

# ----------------------------
# Malicious attachment checker
# ----------------------------
def check_malicious_attachments(attachments):
    bad_exts = ['.exe', '.scr', '.bat', '.cmd', '.msi', '.js', '.vbs', '.jar']
    return [
        att['filename']
        for att in attachments
        if any(att['filename'].lower().endswith(ext) for ext in bad_exts)
    ]
