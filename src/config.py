"""
Configuration module for PhishGuard AI.
Centralizes all paths, thresholds, heuristic lists, ensemble weights, and runtime options.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Base project paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
NOTEBOOKS_DIR = BASE_DIR / "notebooks"
MODELS_DIR = BASE_DIR / "models"
DATABASE_DIR = BASE_DIR / "database"
REPORTS_DIR = BASE_DIR / "reports"
GENERATED_REPORTS_DIR = REPORTS_DIR / "generated_reports"
TESTS_DIR = BASE_DIR / "tests"
ASSETS_DIR = BASE_DIR / "assets"

# Auto-ensure runtime directories exist
for directory in [DATA_RAW_DIR, DATA_PROCESSED_DIR, MODELS_DIR, DATABASE_DIR, GENERATED_REPORTS_DIR, ASSETS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Dataset paths
DEFAULT_RAW_DATASET_CSV = DATA_RAW_DIR / "phishing_urls_dataset.csv"
DEFAULT_PROCESSED_DATASET_CSV = DATA_PROCESSED_DIR / "extracted_features.csv"

# Model artifact paths
LOGISTIC_REGRESSION_PATH = MODELS_DIR / "logistic_regression.pkl"
DECISION_TREE_PATH = MODELS_DIR / "decision_tree.pkl"
RANDOM_FOREST_PATH = MODELS_DIR / "random_forest.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
FEATURE_METADATA_PATH = MODELS_DIR / "feature_metadata.pkl"
EVALUATION_METRICS_PATH = MODELS_DIR / "evaluation_metrics.pkl"

# Database path
DATABASE_PATH = DATABASE_DIR / "scans.db"

# Risk Score Thresholds (Application-level configurable bounds: 0 - 100)
# 0 - 29: SAFE
# 30 - 69: SUSPICIOUS
# 70 - 100: PHISHING
RISK_THRESHOLD_SAFE_MAX = 29
RISK_THRESHOLD_SUSPICIOUS_MAX = 69

# Model Ensemble Weights (Sums to 1.0)
ENSEMBLE_WEIGHTS = {
    "random_forest": 0.50,
    "decision_tree": 0.25,
    "logistic_regression": 0.25,
}

# Configurable Suspicious Keywords List (Domain/Path/Query search)
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "secure", "security", "update", "password", "bank", "banking",
    "payment", "wallet", "confirm", "confirmation", "recover", "reset",
    "free", "bonus", "reward", "claim", "urgent", "support",
    "paypal", "appleid", "netflix", "ebayisapi", "webscr", "auth",
    "billing", "credential", "suspend", "unusual", "security-alert"
]

# Configurable URL Shortener Domains
KNOWN_URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at", "is.gd",
    "buff.ly", "ow.ly", "goo.gl", "bitly.com", "tiny.cc",
    "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "bc.vc",
    "rb.gy", "v.gd", "clck.ru", "bl.ink", "lnkd.in"
]

# Configurable Suspicious / High-Abuse Top Level Domains (TLDs)
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".work",
    ".loan", ".click", ".fit", ".country", ".kim", ".racing",
    ".download", ".stream", ".trade", ".party", ".bid", ".date",
    ".accountant", ".cricket", ".science", ".men", ".win"
]

# Standard Free/Legitimate Public Ports
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}

# Threat Intelligence Configuration
THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "false").lower() in ("true", "1", "yes")
REPUTATION_API_KEY = os.getenv("REPUTATION_API_KEY", "")
DNS_ENABLED = os.getenv("DNS_ENABLED", "true").lower() in ("true", "1", "yes")
WHOIS_ENABLED = os.getenv("WHOIS_ENABLED", "true").lower() in ("true", "1", "yes")
SSL_ENABLED = os.getenv("SSL_ENABLED", "true").lower() in ("true", "1", "yes")
NETWORK_TIMEOUT_SECONDS = int(os.getenv("NETWORK_TIMEOUT_SECONDS", "3"))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FILE = BASE_DIR / "phishguard.log"
