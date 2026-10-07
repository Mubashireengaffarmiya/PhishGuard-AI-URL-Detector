"""
Explainable "Why?" Engine for PhishGuard AI.
Generates URL-specific, feature-derived human-readable security explanations,
distinguishing between positive trust indicators and suspicious threat vectors.
"""

from typing import Dict, Any, List
from src.config import SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, KNOWN_URL_SHORTENERS
from src.utils import setup_logger

logger = setup_logger("ExplanationEngine")


def generate_explanation(
    features: Dict[str, Any],
    classification: str,
    risk_score: float,
    raw_url: str
) -> Dict[str, Any]:
    """
    Synthesizes exact, feature-driven explanations for why the URL was classified as
    Safe, Suspicious, or Phishing.
    """
    suspicious_reasons: List[Dict[str, str]] = []
    positive_indicators: List[Dict[str, str]] = []

    # 1. Scheme Security
    if features.get("is_http", 0) == 1:
        suspicious_reasons.append({
            "title": "Unencrypted HTTP Protocol",
            "detail": "URL uses plaintext 'http://' rather than modern encrypted 'https://', exposing credentials to interception.",
            "severity": "Medium"
        })
    elif features.get("is_https", 0) == 1:
        positive_indicators.append({
            "title": "TLS/HTTPS Encryption",
            "detail": "URL uses modern 'https://' protocol providing cryptographic transport encryption."
        })

    # 2. Host Type (IP vs Domain)
    if features.get("is_ip_address", 0) == 1:
        suspicious_reasons.append({
            "title": "Raw IP Address Host",
            "detail": "Host is specified as a direct IPv4/IPv6 numerical address rather than a registered domain name—a tactic typical of rogue servers.",
            "severity": "High"
        })
    else:
        positive_indicators.append({
            "title": "Standard Domain Host",
            "detail": "Uses a standard registered domain host name rather than an unresolvable or direct numeric IP address."
        })

    # 3. Suspicious Keywords
    url_lower = raw_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        kw_str = ", ".join([f"'{k}'" for k in matched_keywords[:5]])
        suspicious_reasons.append({
            "title": f"Targeted Phishing Keywords Detected ({len(matched_keywords)})",
            "detail": f"Contains security or authentication keywords commonly used in credential harvesting: {kw_str}.",
            "severity": "High" if len(matched_keywords) >= 2 else "Medium"
        })
    else:
        positive_indicators.append({
            "title": "Clean Lexical Content",
            "detail": "No deceptive authentication, payment, or banking lure keywords were detected."
        })

    # 4. URL Length & Structure
    url_len = features.get("url_length", 0)
    if url_len > 80:
        suspicious_reasons.append({
            "title": "Abnormally Long URL",
            "detail": f"URL spans {url_len} characters. Attackers frequently inflate URL length to obscure the actual destination domain on mobile devices.",
            "severity": "Low"
        })
    elif url_len < 60:
        positive_indicators.append({
            "title": "Standard URL Length",
            "detail": f"Concise URL length ({url_len} characters) consistent with standard web navigation."
        })

    # 5. Subdomain Structure
    subdomain_count = features.get("qty_subdomains", 0)
    if subdomain_count >= 3:
        suspicious_reasons.append({
            "title": "Excessive Subdomains",
            "detail": f"Contains {subdomain_count} subdomain levels, a technique often used to disguise brand names in deep domain hierarchies.",
            "severity": "High"
        })
    elif subdomain_count <= 1:
        positive_indicators.append({
            "title": "Normal Subdomain Depth",
            "detail": f"Domain contains {subdomain_count} subdomains, typical of authentic web services."
        })

    # 6. @ Symbol Deception
    if features.get("has_at_symbol", 0) == 1:
        suspicious_reasons.append({
            "title": "Userinfo Redirection (@ Symbol)",
            "detail": "Contains the '@' symbol. In standard URL parsing, everything before '@' is treated as user authentication info, redirecting to the host that follows.",
            "severity": "Critical"
        })

    # 7. Non-standard Web Port
    if features.get("is_suspicious_port", 0) == 1:
        suspicious_reasons.append({
            "title": "Non-Standard Web Port",
            "detail": "Specifies an unusual custom port rather than standard web ports (80/443), frequently seen in temporary malware command or phishing servers.",
            "severity": "High"
        })

    # 8. URL Shortener Detection
    if features.get("is_shortened", 0) == 1:
        suspicious_reasons.append({
            "title": "URL Shortener Service Detected",
            "detail": "URL uses a link-shortening service that conceals the ultimate landing destination from the user.",
            "severity": "Medium"
        })

    # 9. Top-Level Domain (TLD) Abuse
    if features.get("is_suspicious_tld", 0) == 1:
        suspicious_reasons.append({
            "title": "High-Abuse Top-Level Domain",
            "detail": "The domain resides on a TLD statistically associated with high rates of malicious campaign registration.",
            "severity": "High"
        })

    # 10. Delimiters and Patterns
    hyphens = features.get("qty_hyphen", 0)
    if hyphens >= 4:
        suspicious_reasons.append({
            "title": "Excessive Hyphenation",
            "detail": f"Domain or path contains {hyphens} hyphens, often used to simulate legitimate brand names (e.g., 'paypal-security-update').",
            "severity": "Medium"
        })

    if features.get("has_double_slash_redirect", 0) == 1:
        suspicious_reasons.append({
            "title": "Deceptive Double Slash Path",
            "detail": "Contains '//' within the path or query string, indicating potential open-redirect deception.",
            "severity": "High"
        })

    if features.get("has_consecutive_special_chars", 0) == 1:
        suspicious_reasons.append({
            "title": "Consecutive Special Delimiters",
            "detail": "Features consecutive punctuation or special characters typical of automated URL obfuscation.",
            "severity": "Low"
        })

    # 11. Shannon Entropy
    entropy = features.get("url_entropy", 0.0)
    if entropy > 4.5:
        suspicious_reasons.append({
            "title": "High Character Entropy",
            "detail": f"Elevated character entropy ({entropy:.2f} bits/symbol) points to pseudo-random tokens or obfuscated payloads.",
            "severity": "Medium"
        })
    elif entropy < 3.8:
        positive_indicators.append({
            "title": "Natural Character Entropy",
            "detail": f"Balanced character entropy ({entropy:.2f} bits/symbol) reflects typical human-readable naming."
        })

    # Construct synthesized summary narrative
    if classification == "PHISHING":
        summary = (
            f"The analyzed URL exhibits high-confidence characteristics of a malicious or phishing destination (Risk Score: {risk_score}/100). "
            f"Key risk drivers include {len(suspicious_reasons)} distinct anomaly patterns, such as "
            f"{suspicious_reasons[0]['title'].lower() if suspicious_reasons else 'anomalous feature combinations'}."
        )
        recommendation = "DO NOT open this link or input credentials, passwords, or personal details."
    elif classification == "SUSPICIOUS":
        summary = (
            f"The analyzed URL exhibits several suspicious characteristics (Risk Score: {risk_score}/100) that warrant caution. "
            f"Identified {len(suspicious_reasons)} potential warning flags."
        )
        recommendation = "Exercise heightened caution. Verify the domain identity independently before interacting."
    else:
        summary = (
            f"The analyzed URL appears structurally legitimate (Risk Score: {risk_score}/100). "
            f"Identified {len(positive_indicators)} positive safety markers with minimal anomalous indicators."
        )
        recommendation = "URL demonstrates standard legitimate properties. Standard browsing precautions apply."

    return {
        "summary": summary,
        "recommendation": recommendation,
        "suspicious_reasons": suspicious_reasons,
        "positive_indicators": positive_indicators,
        "total_suspicious_flags": len(suspicious_reasons),
        "total_positive_flags": len(positive_indicators)
    }
