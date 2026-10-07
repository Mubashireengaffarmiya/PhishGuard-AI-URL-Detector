"""
Demo Service for PhishGuard AI.
Supplies verified, pre-tested demonstration scenarios for faculty reviews,
hackathon judges, and viva presentations.
All demo samples are explicitly labeled: 'DEMO / SAMPLE DATA'.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
from src.config import ASSETS_DIR
from src.qr_scanner import generate_sample_qr_image
from src.utils import setup_logger

logger = setup_logger("DemoService")


class DemoService:
    """
    Curates and provisions faculty demonstration scenarios.
    """

    DEMO_CASES = [
        {
            "id": "demo-safe-bank",
            "title": "Legitimate Banking Portal (SAFE Baseline)",
            "category": "Normal URL",
            "url": "https://www.chase.com/personal/banking",
            "description": "Standard legitimate financial institution URL. HTTPS enabled, recognized registered commercial domain, balanced character entropy, zero deceptive keywords in host.",
            "expected_outcome": "SAFE",
            "talking_points": [
                "Demonstrates baseline safe scoring: 0-29 Risk score band.",
                "Unanimous multi-model agreement across Random Forest, Decision Tree, and Logistic Regression.",
                "Highlights absence of deceptive delimiters, raw IP hosts, or obfuscated paths."
            ]
        },
        {
            "id": "demo-phish-credential",
            "title": "Targeted PayPal Credential Harvester (PHISHING)",
            "category": "Suspicious URL",
            "url": "http://192.168.1.105:8080/secure-paypal-login/verify-account.php?token=928473847291&action=update",
            "description": "Blatant multi-factor phishing URL: raw IP address host, non-standard port 8080, unencrypted HTTP, brand spoofing keywords ('paypal', 'login', 'verify', 'update'), and long numeric query token.",
            "expected_outcome": "PHISHING",
            "talking_points": [
                "Triggers multiple high-severity heuristic penalties simultaneously (+10 raw IP, +5 HTTP, +12 keywords, +8 port).",
                "Machine-learning models detect severe anomaly combinations in feature space.",
                "Provides clear visual contrast on risk gauge (>85/100 risk score)."
            ]
        },
        {
            "id": "demo-disagreement",
            "title": "Model Disagreement & Divergence Case",
            "category": "Model Disagreement",
            "url": "http://secure-update-login-auth.com/account/details",
            "description": "Borderline lexical pattern with multiple keywords on standard commercial TLD over HTTP without numeric payload. Creates feature conflict where linear and tree models split opinions.",
            "expected_outcome": "DISAGREEMENT DETECTED",
            "talking_points": [
                "Demonstrates PhishGuard's transparent model disagreement detection.",
                "Explains why linear Logistic Regression and non-linear Tree ensembles can diverge on keyword-dense but structurally short paths.",
                "Shows how the weighted ensemble (RF 50%, DT 25%, LR 25%) resolves voting divergence systematically."
            ]
        },
        {
            "id": "demo-tld-abuse",
            "title": "High-Abuse TLD Typosquatting (SUSPICIOUS)",
            "category": "Suspicious URL",
            "url": "https://netflix-billing-update.xyz/login/customer",
            "description": "Uses a known high-abuse .xyz TLD combined with brand typosquatting, hyphens, and authentication lures.",
            "expected_outcome": "PHISHING / SUSPICIOUS",
            "talking_points": [
                "Demonstrates TLD abuse heuristic and hyphenation ratio feature extraction.",
                "Illustrates why free SSL/TLS certificates (HTTPS active) do NOT make a site legitimate."
            ]
        },
        {
            "id": "demo-qr",
            "title": "QR Code Phishing (Quishing) Scenario",
            "category": "QR Scan",
            "url": "https://auth-verification-portal.net/account/confirm",
            "description": "Simulates a physical or email-embedded QR code leading to a credential verification lure.",
            "expected_outcome": "QR URL Extraction -> ML Evaluation",
            "talking_points": [
                "Demonstrates multi-modal intake: OpenCV safely decodes the QR matrix without navigating to the URL.",
                "Enforces explicit user review before submitting extracted link to ML prediction engine."
            ]
        },
        {
            "id": "demo-ocr-multi",
            "title": "Invoice / Screenshot Multi-URL Extraction",
            "category": "Image OCR",
            "url": "https://support.service-desk-security.com/ticket-login",
            "description": "Simulates an email or SMS screenshot with visible URL strings and OCR confidence assessment.",
            "expected_outcome": "OCR Extraction -> Bounding Box -> ML Evaluation",
            "talking_points": [
                "Highlights local Tesseract OCR engine with character-level confidence reporting.",
                "Showcases conservative error correction candidate suggestions (e.g. 1 -> l in domain names).",
                "Demonstrates deduplication when an image contains both printed text and QR codes."
            ]
        }
    ]

    @classmethod
    def get_all_demos(cls) -> List[Dict[str, Any]]:
        """Returns all pre-configured demo cases."""
        return cls.DEMO_CASES

    @classmethod
    def get_demo_by_id(cls, demo_id: str) -> Optional[Dict[str, Any]]:
        """Finds demo case by identifier."""
        for case in cls.DEMO_CASES:
            if case["id"] == demo_id:
                return case
        return None

    @classmethod
    def ensure_demo_qr_exists(cls) -> Path:
        """Generates sample QR image on disk if not already present."""
        qr_path = ASSETS_DIR / "demo_phishing_qr.png"
        if not qr_path.exists():
            generate_sample_qr_image(qr_path, "https://auth-verification-portal.net/account/confirm")
        return qr_path
