"""
Risk Score computation module for PhishGuard AI.
Calculates a 0-100 bounded risk score combining ensemble ML probability,
structural heuristic indicators, and supplementary intelligence signals.
Maps to application thresholds: SAFE (0-29), SUSPICIOUS (30-69), PHISHING (70-100).
"""

from typing import Dict, Any, Optional
from src.config import (
    RISK_THRESHOLD_SAFE_MAX,
    RISK_THRESHOLD_SUSPICIOUS_MAX,
)
from src.utils import format_risk_badge, setup_logger

logger = setup_logger("RiskScore")


def calculate_risk_score(
    ensemble_phishing_prob: float,
    features: Dict[str, Any],
    threat_intel: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Computes a composite security risk score on a scale of 0 to 100.

    Formula:
    Base ML Score (65% weight) = ensemble_phishing_prob * 65
    Heuristic Security Risk (35% weight) = heuristic penalty sum (capped at 35)
    Supplementary Threat Intelligence (bonus/penalty offset if available)
    Final score bounded to [0, 100].
    """
    # 1. Base ML Contribution (0 to 65 points)
    ml_contribution = ensemble_phishing_prob * 65.0

    # 2. Heuristic Indicator Penalties (0 to 35 points)
    heuristic_points = 0.0
    heuristic_breakdown = {}

    # IP address instead of domain (+10)
    if features.get("is_ip_address", 0) == 1:
        heuristic_points += 10.0
        heuristic_breakdown["Raw IP Address Host"] = +10.0

    # HTTP plaintext (+5)
    if features.get("is_http", 0) == 1:
        heuristic_points += 5.0
        heuristic_breakdown["Unencrypted HTTP Scheme"] = +5.0

    # @ Symbol present (+8)
    if features.get("has_at_symbol", 0) == 1:
        heuristic_points += 8.0
        heuristic_breakdown["@ Symbol Redirection Risk"] = +8.0

    # Suspicious keywords (+4 per keyword, max 12)
    kw_count = features.get("qty_suspicious_keywords", 0)
    if kw_count > 0:
        kw_pts = min(12.0, kw_count * 4.0)
        heuristic_points += kw_pts
        heuristic_breakdown[f"Suspicious Keywords ({kw_count})"] = +kw_pts

    # Suspicious TLD (+7)
    if features.get("is_suspicious_tld", 0) == 1:
        heuristic_points += 7.0
        heuristic_breakdown["High-Abuse / Suspicious TLD"] = +7.0

    # URL Shortener (+5)
    if features.get("is_shortened", 0) == 1:
        heuristic_points += 5.0
        heuristic_breakdown["URL Shortener Domain"] = +5.0

    # Excessive hyphens or special chars (+4)
    if features.get("excessive_hyphens", 0) == 1 or features.get("excessive_special_chars", 0) == 1:
        heuristic_points += 4.0
        heuristic_breakdown["Excessive Delimiters / Hyphens"] = +4.0

    # High subdomain count (+5)
    if features.get("high_subdomain_count", 0) == 1:
        heuristic_points += 5.0
        heuristic_breakdown["High Subdomain Count (>=3)"] = +5.0

    # Suspicious non-standard port (+8)
    if features.get("is_suspicious_port", 0) == 1:
        heuristic_points += 8.0
        heuristic_breakdown["Non-Standard Web Port"] = +8.0

    # Consecutive special characters (+3)
    if features.get("has_consecutive_special_chars", 0) == 1:
        heuristic_points += 3.0
        heuristic_breakdown["Consecutive Delimiters / Pattern"] = +3.0

    # Double slash redirect in path (+6)
    if features.get("has_double_slash_redirect", 0) == 1:
        heuristic_points += 6.0
        heuristic_breakdown["Double Slash Redirect in Path"] = +6.0

    # Cap heuristic contribution at 35 points
    capped_heuristic = min(35.0, heuristic_points)

    # 3. Threat Intelligence Offset (if enabled and populated)
    intel_offset = 0.0
    if threat_intel and threat_intel.get("status") == "success":
        # If reputation API flags as malicious
        rep_hits = threat_intel.get("reputation_positives", 0)
        if rep_hits > 0:
            intel_offset += min(20.0, rep_hits * 5.0)
            heuristic_breakdown[f"Threat Intelligence Positives ({rep_hits})"] = intel_offset

    # Compute raw combined score
    raw_score = ml_contribution + capped_heuristic + intel_offset

    # Bound strictly between 0 and 100
    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    # Map to classification categories
    if final_score <= RISK_THRESHOLD_SAFE_MAX:
        classification = "SAFE"
    elif final_score <= RISK_THRESHOLD_SUSPICIOUS_MAX:
        classification = "SUSPICIOUS"
    else:
        classification = "PHISHING"

    status_label, emoji, css_color = format_risk_badge(final_score)

    return {
        "risk_score": final_score,
        "classification": classification,
        "status_label": status_label,
        "emoji": emoji,
        "css_color": css_color,
        "components": {
            "ml_base_score": round(ml_contribution, 2),
            "heuristic_score": round(capped_heuristic, 2),
            "threat_intel_offset": round(intel_offset, 2),
            "heuristic_breakdown": heuristic_breakdown
        },
        "thresholds": {
            "safe_max": RISK_THRESHOLD_SAFE_MAX,
            "suspicious_max": RISK_THRESHOLD_SUSPICIOUS_MAX,
            "phishing_min": RISK_THRESHOLD_SUSPICIOUS_MAX + 1
        }
    }
