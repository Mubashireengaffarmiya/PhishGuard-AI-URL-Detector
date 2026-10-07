"""
Utility functions for URL normalization, validation, sanitization, and logging.
"""

import html
import logging
import re
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, urlunparse
from src.config import LOG_FORMAT, LOG_LEVEL, LOG_FILE


def setup_logger(name: str = "PhishGuard") -> logging.Logger:
    """
    Configures and returns a thread-safe logger for PhishGuard AI.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
        formatter = logging.Formatter(LOG_FORMAT)

        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler
        try:
            fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception:
            pass  # Fallback to console only if file access fails

    return logger


logger = setup_logger("Utils")


def normalize_url(raw_url: str) -> Tuple[str, bool, str]:
    """
    Safely trims, sanitizes, and normalizes a candidate URL string.

    Returns:
        (normalized_url, scheme_was_added, error_message)
    """
    if not raw_url or not isinstance(raw_url, str):
        return "", False, "URL cannot be empty."

    cleaned = raw_url.strip()
    # Strip dangerous wrapper characters like < > " ' `
    cleaned = cleaned.strip("<>\"'`()[]{}")

    if not cleaned:
        return "", False, "URL contains only whitespace or delimiters."

    # Prevent command execution or injection attempts
    if any(c in cleaned for c in ['\r', '\n', '\0']):
        return "", False, "URL contains invalid newline or control characters."

    scheme_added = False
    # If no protocol scheme is specified, default safely to https://
    # We check if it matches scheme:// or if it lacks a colon before the first slash
    parsed = urlparse(cleaned)
    if not parsed.scheme:
        # Check if user typed something like 'localhost:8080' or 'example.com/login'
        cleaned = f"https://{cleaned}"
        scheme_added = True
        parsed = urlparse(cleaned)

    # Re-validate parsed URL
    netloc = parsed.netloc or parsed.path.split('/')[0]
    if not netloc:
        return "", False, "Unable to extract a valid domain or host from the URL."

    # Reconstruct normalized URL with lowercased scheme and hostname
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    
    # Reassemble netloc safely
    rebuilt_netloc = f"{hostname}{port_part}" if hostname else parsed.netloc

    normalized = urlunparse((
        parsed.scheme.lower(),
        rebuilt_netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return normalized, scheme_added, ""


def is_valid_url(url_string: str) -> Tuple[bool, str]:
    """
    Validates whether a string constitutes a structurally sound web URL.
    Returns (is_valid, reason).
    """
    if not url_string:
        return False, "Input is empty."

    norm, _, err = normalize_url(url_string)
    if err:
        return False, err

    parsed = urlparse(norm)
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are analyzed."

    if not parsed.netloc:
        return False, "Missing network location / domain."

    # Hostname validation
    host = parsed.hostname
    if not host:
        return False, "Invalid or missing hostname."

    # Check for basic host validity: must have at least one character and no illegal characters
    if any(ch in host for ch in [' ', '\t', '\n', '<', '>', '"', '\\', '^', '`', '{', '|', '}']):
        return False, "Hostname contains illegal characters."

    return True, "Valid URL format."


def sanitize_for_display(text: str) -> str:
    """
    Escapes HTML to prevent XSS attacks when displaying user-supplied URLs in the UI.
    """
    if not text:
        return ""
    return html.escape(text)


def format_risk_badge(risk_score: float) -> Tuple[str, str, str]:
    """
    Returns (status_label, emoji, css_color) based on application risk thresholds.
    """
    if risk_score < 30:
        return "SAFE", "🟢", "#10B981"  # Emerald Green
    elif risk_score < 70:
        return "SUSPICIOUS", "🟠", "#F59E0B"  # Amber Orange
    else:
        return "PHISHING", "🔴", "#EF4444"  # Crimson Red
