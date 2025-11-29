import os
import re
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime
from functools import lru_cache
from typing import Tuple, Dict

import requests
import whois

# Base dir kept for your DB_PATH export if other modules use it
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "../../history.db")

logger = logging.getLogger(__name__)

# =============== Tunables ===============
WHOIS_TIMEOUT_SECS = int(os.environ.get("WHOIS_TIMEOUT_SECS", "6"))
HTTP_TIMEOUT_SECS = int(os.environ.get("HTTP_TIMEOUT_SECS", "6"))
SKIP_WHOIS = os.environ.get("FEATURE_WHOIS", "1") == "0"  # set FEATURE_WHOIS=0 to skip WHOIS during training
REQUESTS_ENABLED = os.environ.get("FEATURE_HTTP", "1") == "1"  # scrape page for login form
# ========================================

TRUSTED_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.in",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
}

PHISHING_KEYWORDS = [
    "login", "verify", "account", "secure", "bank",
    "update", "confirm", "password", "signin", "bit"
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".ml", ".tk", ".cc", ".club",
    ".info", ".support", ".click", ".work", ".online"
]

def validate_url(url: str) -> Tuple[bool, str]:
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "Missing domain"
        domain = parsed.netloc.split(":")[0]
        if "." not in domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return False, "Invalid domain"
        return True, "OK"
    except Exception as e:
        return False, f"Validation error: {e}"

def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

class FeatureExtractor:
    """
    Extracts **deterministic** features used both by training and inference.
    Keep fields and order stable for model compatibility.
    """

    # Define the canonical feature list (ordering matters!)
    FEATURE_NAMES = [
        "is_valid",
        "domain_age",          # days, -1 if unknown
        "has_https",
        "url_length",
        "num_hyphens",
        "has_suspicious_tld",
        "has_phishing_keyword",
        "has_brand_impersonation",
        "has_login_form"       # best-effort HTML probe (optional HTTP)
    ]

    def __init__(self):
        socket.setdefaulttimeout(WHOIS_TIMEOUT_SECS)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml",
        })

    def get_feature_names(self):
        return list(self.FEATURE_NAMES)

    @lru_cache(maxsize=10_000)
    def _get_domain_age(self, domain: str) -> int:
        """Return domain age in days using WHOIS; -1 if unavailable."""
        if SKIP_WHOIS:
            return -1
        try:
            # whois library can hang; enforce a socket timeout
            socket.setdefaulttimeout(WHOIS_TIMEOUT_SECS)
            w = whois.whois(domain)
            creation_date = getattr(w, "creation_date", None)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                return (datetime.now() - creation_date).days
        except Exception as e:
            logger.debug(f"WHOIS failed for {domain}: {e}")
        return -1

    def _has_login_form(self, url: str) -> bool:
        """Best-effort HTML check for forms/password fields."""
        if not REQUESTS_ENABLED:
            return False
        try:
            resp = self.session.get(url, timeout=HTTP_TIMEOUT_SECS, allow_redirects=True)
            html = resp.text.lower()
            # quick-and-safe heuristics (no heavy parsing to avoid deps)
            if "<form" in html and ("password" in html or "signin" in html or "login" in html):
                return True
        except Exception as e:
            logger.debug(f"HTTP probe failed for {url}: {e}")
        return False

    def extract_features(self, url: str) -> Dict:
        # Start with defaults for ALL features
        feats = {name: 0 for name in self.FEATURE_NAMES}
        feats["domain_age"] = -1  # explicit numeric default

        valid, _ = validate_url(url)
        if not valid:
            feats["is_valid"] = 0
            feats["has_https"] = 0
            feats["url_length"] = len(url or "")
            return feats

        url = normalize_url(url)
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]
        lower_domain = domain.lower()

        feats["is_valid"] = 1
        feats["has_https"] = 1 if parsed.scheme == "https" else 0
        feats["url_length"] = len(url)
        feats["num_hyphens"] = domain.count("-")

        # TLD suspicion
        feats["has_suspicious_tld"] = 1 if any(lower_domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

        # phishingy keywords
        feats["has_phishing_keyword"] = 1 if any(kw in lower_domain for kw in PHISHING_KEYWORDS) else 0

        # brand impersonation
        feats["has_brand_impersonation"] = 1 if any(
            (brand in lower_domain) and (not lower_domain.endswith(official))
            for brand, official in TRUSTED_BRANDS.items()
        ) else 0

        # WHOIS age
        feats["domain_age"] = self._get_domain_age(domain)

        # HTML form probe
        feats["has_login_form"] = 1 if self._has_login_form(url) else 0

        return feats
