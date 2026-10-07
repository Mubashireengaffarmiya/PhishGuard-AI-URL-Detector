"""
QR Service for PhishGuard AI.
Wraps OpenCV QR decoder, validates extracted payloads, supports sample QR generation,
and enforces explicit user confirmation before ML evaluation.
"""

from pathlib import Path
from typing import Tuple, Dict, Any, Optional, Union
import numpy as np
from PIL import Image

from src.qr_scanner import QRScanner, generate_sample_qr_image
from src.utils import setup_logger, normalize_url, is_valid_url

logger = setup_logger("QRService")


class QRService:
    """
    Dedicated service for safe QR code decoding and URL extraction.
    Never navigates to or opens decoded destinations automatically.
    """

    def __init__(self, scanner: Optional[QRScanner] = None):
        self.scanner = scanner or QRScanner()

    def decode_qr(self, image_input: Union[str, Path, bytes, Image.Image, np.ndarray]) -> Dict[str, Any]:
        """
        Decodes a QR code and validates whether it constitutes a web URL.
        """
        success, payload, msg = self.scanner.decode_image(image_input)
        if not success or not payload:
            return {
                "success": False,
                "payload": "",
                "is_url": False,
                "normalized_url": "",
                "message": msg
            }

        norm_url, scheme_added, norm_err = normalize_url(payload)
        valid, val_reason = is_valid_url(norm_url) if not norm_err else (False, norm_err)

        return {
            "success": True,
            "payload": payload,
            "is_url": valid,
            "normalized_url": norm_url if valid else "",
            "scheme_added": scheme_added,
            "message": "Valid URL extracted from QR code." if valid else f"Decoded text is not a web URL: {val_reason}"
        }

    def generate_demo_qr(self, target_path: Path, url: str = "https://phishguard-ai.internal/verify-account") -> Path:
        """Generates a demo QR code image on disk."""
        return generate_sample_qr_image(target_path, url)
