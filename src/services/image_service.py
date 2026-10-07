"""
Image Scan Service for PhishGuard AI.
Coordinates multi-modal image intelligence: runs both local OCR text recognition
and OpenCV QR code detection on uploaded screenshots, merges and deduplicates URL
candidates, and presents them for user confirmation before model inference.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import numpy as np
from PIL import Image

from src.services.ocr_service import OCRService
from src.qr_scanner import QRScanner
from src.services.prediction_service import PredictionService
from src.utils import setup_logger, normalize_url

logger = setup_logger("ImageScanService")


class ImageScanService:
    """
    Unified image processing service combining OCR and QR code decoding.
    Extracts, deduplicates, and manages candidate review workflows.
    """

    def __init__(self, ocr_service: Optional[OCRService] = None, qr_scanner: Optional[QRScanner] = None):
        self.ocr_service = ocr_service or OCRService()
        self.qr_scanner = qr_scanner or QRScanner()

    def process_image(
        self,
        image_input: Union[str, Path, bytes, Image.Image, np.ndarray],
        filename: str = "uploaded_image.png"
    ) -> Dict[str, Any]:
        """
        Executes complete multi-modal scanning on an image:
        1. OCR text extraction & URL detection
        2. QR code detection & payload decoding
        3. Candidate deduplication & source merging
        4. Image quality profiling
        """
        # 1. OCR Extraction
        ocr_result = self.ocr_service.extract_text_and_urls(image_input)

        # 2. QR Code Decoding
        qr_success, qr_payload, qr_msg = self.qr_scanner.decode_image(image_input)
        qr_url = None
        if qr_success and qr_payload:
            norm_qr, _, err = normalize_url(qr_payload)
            if not err:
                qr_url = norm_qr

        # 3. Combine & Deduplicate Candidates
        merged_candidates: List[Dict[str, Any]] = []
        seen_urls = set()

        # Add QR URL if detected
        if qr_url:
            merged_candidates.append({
                "url": qr_url,
                "raw_text": qr_payload,
                "source": "QR_CODE",
                "confidence": "High",
                "corrections": [],
                "from_qr": True,
                "from_ocr": False
            })
            seen_urls.add(qr_url.lower())

        # Merge OCR candidates
        for cand in ocr_result.get("detected_urls", []):
            url_norm = cand["normalized"]
            url_norm_lower = url_norm.lower()

            if url_norm_lower in seen_urls:
                # URL appeared in both QR and OCR! Update source
                for item in merged_candidates:
                    if item["url"].lower() == url_norm_lower:
                        item["source"] = "Both (OCR + QR)"
                        item["from_ocr"] = True
            else:
                merged_candidates.append({
                    "url": url_norm,
                    "raw_text": cand["raw_extracted"],
                    "source": "IMAGE_OCR",
                    "confidence": cand["confidence_level"],
                    "corrections": cand["corrections"],
                    "from_qr": False,
                    "from_ocr": True
                })
                seen_urls.add(url_norm_lower)

        return {
            "status": "success" if (ocr_result.get("status") == "success" or qr_success) else "no_data",
            "filename": filename,
            "ocr_status": ocr_result.get("status"),
            "ocr_message": ocr_result.get("message"),
            "raw_ocr_text": ocr_result.get("raw_text", ""),
            "ocr_confidence": ocr_result.get("ocr_confidence", 0.0),
            "qr_detected": qr_success,
            "qr_payload": qr_payload if qr_success else None,
            "qr_message": qr_msg,
            "total_candidates": len(merged_candidates),
            "candidates": merged_candidates,
            "annotated_image": ocr_result.get("annotated_image"),
            "quality": ocr_result.get("quality", {})
        }
