"""
Explanation Service for PhishGuard AI.
Provides grounded, feature-derived indicators, categorizes features,
synthesizes safe URL trust factors, and distinguishes between heuristic indicators,
model weights, and actual feature importance.
"""

from typing import Dict, Any, List, Optional
from src.config import SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, KNOWN_URL_SHORTENERS
from src.explanation import generate_explanation
from src.utils import setup_logger

logger = setup_logger("ExplanationService")


class ExplanationService:
    """
    Synthesizes multi-layered technical explanations for URL analysis results.
    Ensures technical honesty and avoids fabricated causality.
    """

    FEATURE_TAXONOMY = {
        "URL Structure": [
            ("url_length", "Total URL Length", "Total characters in the URL string", "Longer URLs (>75 chars) frequently hide destination paths."),
            ("domain_length", "Domain Host Length", "Character length of the hostname", "Excessively long domain names can disguise brand names."),
            ("path_length", "Path String Length", "Characters in the URL path component", "Deep paths are used to conceal tracking tokens or fake directories."),
            ("query_length", "Query String Length", "Length of parameters following '?'", "Long query strings may contain encoded redirects or payloads."),
            ("fragment_length", "Fragment Length", "Length of fragment identifier after '#'", "Used in client-side redirects and anchor manipulation."),
            ("qty_slash", "Forward Slash Count", "Total forward slashes in URL", "High slash counts indicate nested directories or deceptive paths."),
            ("qty_subdomains", "Subdomain Count", "Number of subdomain labels", "Excessive subdomains (>=3) often simulate trusted hostnames."),
        ],
        "Character Analysis": [
            ("qty_digits", "Digit Count", "Total numeric digits [0-9]", "High digit counts appear in randomly generated or automated hostnames."),
            ("digit_ratio", "Digit Ratio", "Ratio of digits to total URL length", "Values above 20% suggest automated generation or tracking hashes."),
            ("qty_special_chars", "Special Character Count", "Count of punctuation and symbols", "Excessive symbols are used to bypass simple text filters."),
            ("special_char_ratio", "Special Character Ratio", "Proportion of non-alphanumeric chars", "High ratios correlate with obfuscated URLs."),
            ("qty_hyphen", "Hyphen Count", "Total hyphens '-' in URL", "Multiple hyphens simulate genuine domain names (e.g. 'paypal-update')."),
            ("hyphen_ratio", "Hyphen Ratio", "Ratio of hyphens to URL length", "Unusually high hyphenation is common in phishing typosquatting."),
            ("url_entropy", "Shannon Entropy (URL)", "Information randomness in bits/symbol", "High entropy (>4.5) indicates cryptographic hashes or random tokens."),
            ("domain_entropy", "Shannon Entropy (Domain)", "Randomness of hostname characters", "High domain entropy indicates algorithmically generated domains (DGA)."),
            ("max_consecutive_digits", "Max Consecutive Digits", "Longest continuous run of numbers", "Long numeric sequences suggest IP-like strings or victim IDs."),
        ],
        "Domain & Host Attributes": [
            ("is_ip_address", "Raw IP Address Host", "True if hostname is direct IP", "Direct IP addresses bypass domain reputation and WHOIS scrutiny."),
            ("is_suspicious_tld", "Suspicious TLD Flag", "True if domain uses high-abuse TLD", "High-abuse TLDs (.xyz, .top, .tk) offer cheap malicious registration."),
            ("is_numeric_heavy_domain", "Numeric Heavy Domain", "Domain contains >30% digits", "Commonly seen in disposable phishing campaign domains."),
            ("high_subdomain_count", "Excessive Subdomains", "Domain has 3 or more subdomains", "Attackers prepend brand names like 'bank.com.attacker.com'."),
            ("domain_vowel_count", "Domain Vowel Count", "Vowels present in domain label", "Very low vowel counts indicate random consonant strings."),
        ],
        "Security Flags & Heuristics": [
            ("is_https", "HTTPS Protocol", "Secure TLS/SSL transport", "Authentic services prioritize HTTPS; absence raises risk."),
            ("is_http", "Unencrypted HTTP", "Plaintext HTTP connection", "Exposes credentials and session tokens to interception."),
            ("is_shortened", "URL Shortener Service", "Known link-shortener domain", "Shorteners conceal destination domains from the user."),
            ("has_at_symbol", "@ Symbol Redirection", "Contains userinfo '@' delimiter", "Browsers interpret everything before '@' as userinfo, redirecting to after."),
            ("is_suspicious_port", "Non-Standard Port", "Specifies port other than 80/443", "Frequently utilized by temporary phishing servers or rogue proxies."),
            ("qty_suspicious_keywords", "Phishing Keywords Count", "Keywords matching credential lures", "Words like 'login', 'verify', 'update' are typical phishing bait."),
            ("has_suspicious_keywords", "Suspicious Keyword Flag", "Whether keywords were identified", "Direct lexical indicator of targeted credential harvesting."),
            ("has_double_slash_redirect", "Double Slash in Path", "Contains '//' after authority", "Technique used in open-redirect attacks."),
            ("has_consecutive_special_chars", "Consecutive Special Chars", "Adjacent symbols (e.g. '--', '..')", "Common in obfuscated attack patterns."),
        ]
    }

    def __init__(self):
        pass

    def get_indicator_breakdown(self, features: Dict[str, Any], raw_url: str) -> List[Dict[str, Any]]:
        """
        Builds a comprehensive indicator evaluation table with:
        Indicator, Observed Value, Why It Matters, Risk Interpretation, Limitation.
        """
        indicators = []

        # 1. Scheme
        is_https = features.get("is_https", 0) == 1
        is_http = features.get("is_http", 0) == 1
        indicators.append({
            "indicator": "Transport Protocol",
            "observed_value": "HTTPS (Encrypted)" if is_https else ("HTTP (Plaintext)" if is_http else "Custom Scheme"),
            "why_it_matters": "HTTPS provides transport encryption and domain identity verification. HTTP exposes data in plaintext.",
            "risk_interpretation": "Low Risk" if is_https else "Elevated Risk",
            "severity": "Safe" if is_https else "Medium",
            "limitation": "Legitimate sites occasionally use HTTP, and phishing sites can also obtain free SSL/TLS certificates."
        })

        # 2. Host Type
        is_ip = features.get("is_ip_address", 0) == 1
        indicators.append({
            "indicator": "Host Representation",
            "observed_value": "Direct IP Address" if is_ip else "Registered Domain Name",
            "why_it_matters": "Legitimate organizations rarely serve public web services via raw IP addresses.",
            "risk_interpretation": "Critical Risk" if is_ip else "Standard Baseline",
            "severity": "Critical" if is_ip else "Safe",
            "limitation": "Local network devices and legitimate intranet portals may use IP addresses."
        })

        # 3. Phishing Keywords
        kw_count = features.get("qty_suspicious_keywords", 0)
        url_lower = raw_url.lower()
        matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        kw_str = ", ".join(matched_kws[:4]) if matched_kws else "None detected"
        indicators.append({
            "indicator": "Targeted Phishing Keywords",
            "observed_value": f"{kw_count} keyword(s) ({kw_str})",
            "why_it_matters": "Attackers routinely include words like 'verify', 'account', 'login' to induce urgency.",
            "risk_interpretation": "High Suspicion" if kw_count >= 2 else ("Moderate Suspicion" if kw_count == 1 else "Clean Lexical"),
            "severity": "High" if kw_count >= 2 else ("Medium" if kw_count == 1 else "Safe"),
            "limitation": "Legitimate login and account recovery pages naturally include authentication words."
        })

        # 4. URL Length
        length = features.get("url_length", 0)
        indicators.append({
            "indicator": "Total URL Length",
            "observed_value": f"{length} characters",
            "why_it_matters": "Attackers inflate URL length to truncate visible domains on mobile browsers.",
            "risk_interpretation": "Suspicious (>80 chars)" if length > 80 else "Standard Length",
            "severity": "Medium" if length > 80 else "Safe",
            "limitation": "Legitimate analytics URLs and cloud storage links often exceed 100 characters."
        })

        # 5. Subdomain Structure
        subdomains = features.get("qty_subdomains", 0)
        indicators.append({
            "indicator": "Subdomain Count",
            "observed_value": f"{subdomains} subdomain level(s)",
            "why_it_matters": "Multiple subdomains allow embedding legitimate brand names before rogue domains.",
            "risk_interpretation": "High Suspicion (>=3)" if subdomains >= 3 else "Normal Hierarchy",
            "severity": "High" if subdomains >= 3 else "Safe",
            "limitation": "Complex corporate networks (e.g. AWS, Microsoft Azure) use multiple subdomain levels."
        })

        # 6. URL Shortener
        is_short = features.get("is_shortened", 0) == 1
        indicators.append({
            "indicator": "URL Shortening Service",
            "observed_value": "Detected" if is_short else "None Detected",
            "why_it_matters": "Shorteners obfuscate the real target destination, concealing phishing domains.",
            "risk_interpretation": "Requires Caution" if is_short else "Transparent Destination",
            "severity": "Medium" if is_short else "Safe",
            "limitation": "Short links are widely used for social media, marketing, and legitimate convenience."
        })

        # 7. Suspicious TLD
        is_tld = features.get("is_suspicious_tld", 0) == 1
        indicators.append({
            "indicator": "Top-Level Domain (TLD) Reputation",
            "observed_value": "High-Abuse TLD" if is_tld else "Standard / Commercial TLD",
            "why_it_matters": "Certain TLDs (.xyz, .top, .work) exhibit disproportionate rates of spam and phishing.",
            "risk_interpretation": "Elevated Risk" if is_tld else "Neutral Baseline",
            "severity": "High" if is_tld else "Safe",
            "limitation": "Many legitimate startups and open-source projects operate under modern TLDs like .xyz."
        })

        # 8. Character Entropy
        entropy = features.get("url_entropy", 0.0)
        indicators.append({
            "indicator": "Shannon Character Entropy",
            "observed_value": f"{entropy:.2f} bits/symbol",
            "why_it_matters": "High entropy (>4.5) indicates randomized tokens, obfuscated hex strings, or DGA naming.",
            "risk_interpretation": "High Randomness" if entropy > 4.5 else "Natural Language Distribution",
            "severity": "Medium" if entropy > 4.5 else "Safe",
            "limitation": "Session tokens, UUIDs, and CDN asset hashes naturally produce high entropy."
        })

        # 9. At Symbol
        has_at = features.get("has_at_symbol", 0) == 1
        if has_at:
            indicators.append({
                "indicator": "Userinfo Redirection (@ Symbol)",
                "observed_value": "Present in URL",
                "why_it_matters": "RFC 3986 specifies that text before '@' is user authentication info, directing traffic to host after '@'.",
                "risk_interpretation": "Severe Deception Vector",
                "severity": "Critical",
                "limitation": "Extremely rare in modern legitimate web URLs."
            })

        # 10. Non-Standard Port
        is_port = features.get("is_suspicious_port", 0) == 1
        if is_port:
            indicators.append({
                "indicator": "Non-Standard Web Port",
                "observed_value": "Custom Port Specified",
                "why_it_matters": "Non-standard ports (outside 80/443) are frequently used to host temporary attack servers.",
                "risk_interpretation": "Elevated Risk",
                "severity": "High",
                "limitation": "Development servers and internal corporate services often use custom ports."
            })

        return indicators

    def get_safe_url_explanation(self, features: Dict[str, Any], individual_predictions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes grounded reasons why a URL is assessed as lower risk,
        along with the mandatory technical disclaimer.
        """
        trust_factors = []

        if features.get("is_https", 0) == 1:
            trust_factors.append({
                "factor": "TLS/HTTPS Encryption Active",
                "evidence": "URL specifies 'https://' protocol providing cryptographic data-in-transit encryption."
            })

        if features.get("is_ip_address", 0) == 0:
            trust_factors.append({
                "factor": "Registered Domain Host",
                "evidence": "Host resolves to a standard domain structure rather than a raw IP address."
            })

        if features.get("qty_suspicious_keywords", 0) == 0:
            trust_factors.append({
                "factor": "Clean Lexical Content",
                "evidence": "No deceptive credential harvesting keywords (e.g. 'login', 'verify', 'bank') were detected."
            })

        if features.get("is_suspicious_port", 0) == 0:
            trust_factors.append({
                "factor": "Standard Web Port",
                "evidence": "Traffic operates over standard HTTP/HTTPS ports without obscure port offsets."
            })

        if features.get("is_shortened", 0) == 0:
            trust_factors.append({
                "factor": "Transparent Destination Host",
                "evidence": "Destination is directly visible; no known link-shortening redirection service was detected."
            })

        if features.get("is_suspicious_tld", 0) == 0:
            trust_factors.append({
                "factor": "Standard Top-Level Domain",
                "evidence": "Host resides on a standard commercial/organizational TLD with established reputation."
            })

        entropy = features.get("url_entropy", 0.0)
        if entropy < 4.0:
            trust_factors.append({
                "factor": "Natural Character Entropy",
                "evidence": f"URL character entropy ({entropy:.2f} bits) reflects natural language rather than obfuscated tokens."
            })

        # Consensus factor
        all_safe = all(m["label"] == "SAFE" for m in individual_predictions.values())
        if all_safe:
            trust_factors.append({
                "factor": "Unanimous Multi-Model Consensus",
                "evidence": "Logistic Regression, Decision Tree, and Random Forest all independently classified this URL as SAFE."
            })

        return {
            "trust_factors": trust_factors,
            "disclaimer": (
                "A SAFE classification is a machine-learning assessment based on structural and lexical indicators. "
                "It does not guarantee that a website is trustworthy, secure, or free from server-side compromise. "
                "Always verify the website identity before entering sensitive information."
            )
        }
