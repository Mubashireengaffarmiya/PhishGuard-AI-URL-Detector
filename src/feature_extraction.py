"""
Feature extraction module for PhishGuard AI.
Extracts 42 comprehensive structural, lexical, statistical, security, keyword,
and domain features from a given URL with deterministic feature ordering.
"""

import ipaddress
import math
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import numpy as np
import pandas as pd

from src.config import (
    SUSPICIOUS_KEYWORDS,
    KNOWN_URL_SHORTENERS,
    SUSPICIOUS_TLDS,
    STANDARD_WEB_PORTS,
)
from src.utils import normalize_url, setup_logger

logger = setup_logger("FeatureExtraction")

# Strict, deterministic list of feature names (42 features)
FEATURE_NAMES: List[str] = [
    # A. URL Structure Features
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "fragment_length",
    "qty_dot",
    "qty_hyphen",
    "qty_slash",
    "qty_questionmark",
    "qty_equal",
    "qty_and",
    "qty_percent",
    "qty_special_chars",
    "qty_digits",
    "qty_letters",
    "qty_subdomains",
    # B. Suspicious Character / Pattern Features
    "has_at_symbol",
    "has_hash_symbol",
    "has_percent_symbol",
    "has_double_slash_redirect",
    "excessive_hyphens",
    "excessive_special_chars",
    "has_consecutive_special_chars",
    # C. Security Features
    "is_https",
    "is_http",
    "is_ip_address",
    "is_suspicious_port",
    "is_shortened",
    # D. Suspicious Keyword Features
    "qty_suspicious_keywords",
    "has_suspicious_keywords",
    # E. Statistical / Ratio Features
    "digit_ratio",
    "special_char_ratio",
    "hyphen_ratio",
    "letter_ratio",
    "url_entropy",
    "max_consecutive_digits",
    "suspicious_pattern_count",
    # F. Domain Characteristics
    "is_numeric_heavy_domain",
    "high_subdomain_count",
    "is_suspicious_tld",
    "domain_entropy",
    "domain_vowel_count"
]

SPECIAL_CHARS_REGEX = re.compile(r"[-_.~!*'();:@&=+$,/?%#[\]]")


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy of a string representing information density / randomness.
    """
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in set(text)]
    return round(-sum(p * math.log2(p) for p in prob_dist), 4)


def is_ip_address_host(host: str) -> int:
    """
    Returns 1 if host is a valid IPv4 or IPv6 address, else 0.
    """
    if not host:
        return 0
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0


def extract_features_from_url(url_string: str) -> Dict[str, Any]:
    """
    Extracts all 42 features for a single URL string.
    Normalizes the URL first without performing any network requests.
    """
    normalized, _, _ = normalize_url(url_string)
    parsed = urlparse(normalized)

    full_url = normalized
    domain = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    scheme = parsed.scheme.lower() if parsed.scheme else ""

    url_len = len(full_url)
    domain_len = len(domain)
    path_len = len(path)
    query_len = len(query)
    frag_len = len(fragment)

    # Counts
    dots = full_url.count(".")
    hyphens = full_url.count("-")
    slashes = full_url.count("/")
    questionmarks = full_url.count("?")
    equals = full_url.count("=")
    ands = full_url.count("&")
    percents = full_url.count("%")
    digits = sum(c.isdigit() for c in full_url)
    letters = sum(c.isalpha() for c in full_url)
    special_chars = len(SPECIAL_CHARS_REGEX.findall(full_url))

    # Subdomains calculation
    # e.g., 'a.b.example.com' -> ['a', 'b', 'example', 'com'] -> 2 subdomains
    subdomain_count = 0
    if domain and not is_ip_address_host(domain):
        parts = domain.split(".")
        if len(parts) > 2:
            subdomain_count = len(parts) - 2

    # Suspicious character / pattern features
    has_at = 1 if "@" in full_url else 0
    has_hash = 1 if "#" in full_url else 0
    has_percent = 1 if "%" in full_url else 0

    # Look for '//' inside path or query (open redirect or deceptive path)
    has_double_slash = 1 if "//" in (path + query) else 0

    excessive_hyphens = 1 if hyphens > 3 else 0
    excessive_special = 1 if special_chars > 5 else 0

    # Consecutive special characters (e.g., '..', '--', '%20%20', '//', '?=')
    consec_special = 1 if re.search(r"[-_.!*'();:@&=+$,/?%#[\]]{2,}", full_url) else 0

    # Security features
    is_https = 1 if scheme == "https" else 0
    is_http = 1 if scheme == "http" else 0
    is_ip = is_ip_address_host(domain)

    # Port checking
    port = parsed.port
    is_suspicious_port = 1 if (port is not None and port not in STANDARD_WEB_PORTS) else 0

    # URL shortener detection
    is_shortener = 0
    domain_lower = domain.lower()
    for shortener in KNOWN_URL_SHORTENERS:
        if domain_lower == shortener or domain_lower.endswith(f".{shortener}"):
            is_shortener = 1
            break

    # Suspicious keywords
    full_url_lower = full_url.lower()
    keyword_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    qty_suspicious_keywords = len(keyword_matches)
    has_suspicious_keywords = 1 if qty_suspicious_keywords > 0 else 0

    # Ratios
    safe_len = max(url_len, 1)
    digit_ratio = round(digits / safe_len, 4)
    special_char_ratio = round(special_chars / safe_len, 4)
    hyphen_ratio = round(hyphens / safe_len, 4)
    letter_ratio = round(letters / safe_len, 4)

    # Entropy
    url_entropy = calculate_shannon_entropy(full_url)
    domain_entropy = calculate_shannon_entropy(domain)

    # Consecutive digits (max run)
    digit_runs = re.findall(r"\d+", full_url)
    max_consec_digits = max([len(r) for r in digit_runs], default=0)

    # Suspicious pattern count composite
    pattern_count = (
        has_at + has_double_slash + is_ip + is_suspicious_port +
        is_shortener + excessive_hyphens + excessive_special + consec_special
    )

    # Domain features
    domain_digits = sum(c.isdigit() for c in domain)
    is_numeric_heavy = 1 if domain_len > 0 and (domain_digits / max(domain_len, 1)) > 0.3 else 0
    high_subdomain = 1 if subdomain_count >= 3 else 0

    # Suspicious TLD check
    is_suspicious_tld = 0
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            is_suspicious_tld = 1
            break

    # Domain vowel count
    domain_vowels = sum(c in "aeiouAEIOU" for c in domain)

    features: Dict[str, Any] = {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "query_length": query_len,
        "fragment_length": frag_len,
        "qty_dot": dots,
        "qty_hyphen": hyphens,
        "qty_slash": slashes,
        "qty_questionmark": questionmarks,
        "qty_equal": equals,
        "qty_and": ands,
        "qty_percent": percents,
        "qty_special_chars": special_chars,
        "qty_digits": digits,
        "qty_letters": letters,
        "qty_subdomains": subdomain_count,
        "has_at_symbol": has_at,
        "has_hash_symbol": has_hash,
        "has_percent_symbol": has_percent,
        "has_double_slash_redirect": has_double_slash,
        "excessive_hyphens": excessive_hyphens,
        "excessive_special_chars": excessive_special,
        "has_consecutive_special_chars": consec_special,
        "is_https": is_https,
        "is_http": is_http,
        "is_ip_address": is_ip,
        "is_suspicious_port": is_suspicious_port,
        "is_shortened": is_shortener,
        "qty_suspicious_keywords": qty_suspicious_keywords,
        "has_suspicious_keywords": has_suspicious_keywords,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
        "hyphen_ratio": hyphen_ratio,
        "letter_ratio": letter_ratio,
        "url_entropy": url_entropy,
        "max_consecutive_digits": max_consec_digits,
        "suspicious_pattern_count": pattern_count,
        "is_numeric_heavy_domain": is_numeric_heavy,
        "high_subdomain_count": high_subdomain,
        "is_suspicious_tld": is_suspicious_tld,
        "domain_entropy": domain_entropy,
        "domain_vowel_count": domain_vowels
    }

    # Verify that all FEATURE_NAMES are present
    assert len(features) == len(FEATURE_NAMES), f"Mismatch in feature count: expected {len(FEATURE_NAMES)}, got {len(features)}"

    return features


def extract_features_dataframe(urls: pd.Series) -> pd.DataFrame:
    """
    Extracts features for a pandas Series of URLs, preserving FEATURE_NAMES column ordering.
    """
    feature_list = []
    total = len(urls)
    logger.info(f"Extracting {len(FEATURE_NAMES)} features from {total} URLs...")

    for idx, url in enumerate(urls):
        try:
            feat_dict = extract_features_from_url(str(url))
            feature_list.append(feat_dict)
        except Exception as e:
            logger.warning(f"Error extracting features for '{url}': {e}. Using zero-filled defaults.")
            feature_list.append({k: 0 for k in FEATURE_NAMES})

        if (idx + 1) % 500 == 0 or (idx + 1) == total:
            logger.info(f"Processed {idx + 1}/{total} URLs ({((idx + 1) / total) * 100:.1f}%)")

    df_features = pd.DataFrame(feature_list)[FEATURE_NAMES]
    return df_features


def get_feature_metadata() -> Dict[str, Any]:
    """
    Returns descriptive metadata for all 42 extracted features.
    """
    return {
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "categories": {
            "URL Structure": [
                "url_length", "domain_length", "path_length", "query_length", "fragment_length",
                "qty_dot", "qty_hyphen", "qty_slash", "qty_questionmark", "qty_equal", "qty_and",
                "qty_percent", "qty_special_chars", "qty_digits", "qty_letters", "qty_subdomains"
            ],
            "Suspicious Patterns": [
                "has_at_symbol", "has_hash_symbol", "has_percent_symbol",
                "has_double_slash_redirect", "excessive_hyphens", "excessive_special_chars",
                "has_consecutive_special_chars"
            ],
            "Security Flags": [
                "is_https", "is_http", "is_ip_address", "is_suspicious_port", "is_shortened"
            ],
            "Keywords": [
                "qty_suspicious_keywords", "has_suspicious_keywords"
            ],
            "Ratios & Statistics": [
                "digit_ratio", "special_char_ratio", "hyphen_ratio", "letter_ratio",
                "url_entropy", "max_consecutive_digits", "suspicious_pattern_count"
            ],
            "Domain Attributes": [
                "is_numeric_heavy_domain", "high_subdomain_count", "is_suspicious_tld",
                "domain_entropy", "domain_vowel_count"
            ]
        }
    }
