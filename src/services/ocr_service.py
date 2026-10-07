"""
OCR Service for PhishGuard AI.
Handles local Optical Character Recognition via Tesseract / pytesseract,
URL pattern detection, OCR confidence calculation, conservative OCR error
correction candidates, image quality validation (blur/resolution), and bounding-box overlay.
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Union
import re
import cv2
import numpy as np
from PIL import Image

from src.utils import setup_logger, normalize_url, is_valid_url

logger = setup_logger("OCRService")

# Common Tesseract executable paths on Windows
TESSERACT_CANDIDATE_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    r"C:\Users\mubas\AppData\Local\Programs\Tesseract-OCR\tesseract.exe",
]


class OCRService:
    """
    Local OCR engine and URL extraction pipeline with image quality diagnostics
    and conservative character correction preview.
    """

    # Comprehensive URL regex pattern supporting protocols, www, domains, paths, query, and IP addresses
    URL_REGEX = re.compile(
        r'(?:https?://|www\.)[^\s<>"\'`\(\)\[\]\{\}]+|'
        r'(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|xyz|top|info|biz|io|co|uk|de|ca|ru|fr|jp|au|online|site|app|live|shop|club|tech|pro|cloud|ai|dev|me|us|in|space|store|vip|link|bid|stream|trade)[^\s<>"\'`\(\)\[\]\{\}]*|'
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{2,5})?(?:/[^\s<>"\'`\(\)\[\]\{\}]*)?',
        re.IGNORECASE
    )

    def __init__(self):
        self._init_tesseract()

    def _init_tesseract(self) -> bool:
        """Finds and configures the Tesseract OCR binary path."""
        try:
            import pytesseract
            # Check candidate paths
            for candidate in TESSERACT_CANDIDATE_PATHS:
                if Path(candidate).exists():
                    pytesseract.pytesseract.tesseract_cmd = candidate
                    logger.info(f"Configured Tesseract OCR binary from: {candidate}")
                    return True
            # Check default PATH
            ver = pytesseract.get_tesseract_version()
            logger.info(f"Tesseract found on system PATH: {ver}")
            return True
        except Exception as e:
            logger.warning(f"Tesseract not configured or not accessible: {e}")
            return False

    def is_ocr_available(self) -> Tuple[bool, str]:
        """Returns whether local OCR engine is ready for use."""
        try:
            import pytesseract
            ver = pytesseract.get_tesseract_version()
            return True, f"Tesseract OCR v{ver} Ready"
        except Exception as e:
            return False, f"OCR Engine Unavailable: {e}"

    def analyze_image_quality(self, cv_img: np.ndarray) -> Dict[str, Any]:
        """
        Assesses image quality indicators: blur/sharpness, resolution, and contrast.
        """
        if cv_img is None or cv_img.size == 0:
            return {
                "quality_ok": False,
                "is_blurry": True,
                "is_low_res": True,
                "sharpness_score": 0.0,
                "dimensions": (0, 0),
                "warnings": ["Image data is empty or invalid."]
            }

        height, width = cv_img.shape[:2]
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY) if len(cv_img.shape) == 3 else cv_img

        # 1. Sharpness via Laplacian variance
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        is_blurry = laplacian_var < 75.0

        # 2. Resolution check
        is_low_res = width < 300 or height < 150

        # 3. Contrast check (standard deviation of pixel intensity)
        contrast = float(np.std(gray))
        is_low_contrast = contrast < 25.0

        warnings = []
        if is_blurry:
            warnings.append(f"Image appears blurry or low-focus (Sharpness: {laplacian_var:.1f}). OCR accuracy may be reduced.")
        if is_low_res:
            warnings.append(f"Resolution is low ({width}x{height}px). Small URL text may not be resolved clearly.")
        if is_low_contrast:
            warnings.append("Low contrast between text and background detected.")

        return {
            "quality_ok": not (is_blurry and is_low_res),
            "is_blurry": is_blurry,
            "is_low_res": is_low_res,
            "is_low_contrast": is_low_contrast,
            "sharpness_score": round(laplacian_var, 1),
            "dimensions": (width, height),
            "contrast_score": round(contrast, 1),
            "warnings": warnings
        }

    def extract_text_and_urls(
        self,
        image_input: Union[str, Path, bytes, Image.Image, np.ndarray]
    ) -> Dict[str, Any]:
        """
        Extracts raw text, identifies URL candidates, calculates OCR confidence scores,
        suggests conservative character corrections, and marks bounding box coordinates.
        """
        ready, msg = self.is_ocr_available()
        if not ready:
            return {
                "status": "error",
                "message": msg,
                "raw_text": "",
                "detected_urls": [],
                "ocr_confidence": 0.0,
                "annotated_image": None,
                "quality": {}
            }

        # Convert input to OpenCV image
        cv_img = self._to_cv_image(image_input)
        if cv_img is None:
            return {
                "status": "error",
                "message": "Failed to decode input into image format.",
                "raw_text": "",
                "detected_urls": [],
                "ocr_confidence": 0.0,
                "annotated_image": None,
                "quality": {}
            }

        quality_report = self.analyze_image_quality(cv_img)

        try:
            import pytesseract
            # Run image_to_data to retrieve words, confidence, and bounding boxes
            data = pytesseract.image_to_data(cv_img, output_type=pytesseract.Output.DICT)
            raw_text = pytesseract.image_to_string(cv_img)

            # Extract confidence scores for valid text elements
            conf_scores = [float(c) for c in data.get("conf", []) if str(c).replace(".", "", 1).isdigit() and float(c) > 0]
            avg_ocr_conf = round(float(np.mean(conf_scores)), 1) if conf_scores else 0.0

            # Find URL candidates in raw text
            detected_candidates = self._find_url_candidates(raw_text)

            # Also scan line-by-line in data boxes to associate bounding boxes
            annotated_img = cv_img.copy()
            urls_with_metadata = []

            for raw_cand in detected_candidates:
                # Clean candidate
                cand_clean = raw_cand.strip(".,;:!'\"<>[]{}()").strip()
                if len(cand_clean) < 4:
                    continue

                # Compute conservative OCR error corrections
                corrections = self.suggest_ocr_corrections(cand_clean)

                # Determine extraction confidence
                cand_conf = "High" if avg_ocr_conf >= 75 else ("Medium" if avg_ocr_conf >= 45 else "Low")

                # Try to locate bounding box in data
                bbox = self._locate_bbox(cand_clean, data)
                if bbox:
                    x, y, w, h = bbox
                    # Draw subtle cyan bounding box
                    cv2.rectangle(annotated_img, (x, y), (x + w, y + h), (255, 240, 0), 2)
                    cv2.putText(annotated_img, "URL", (x, max(15, y - 5)), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 240, 0), 1)

                urls_with_metadata.append({
                    "raw_extracted": cand_clean,
                    "normalized": normalize_url(cand_clean)[0] if normalize_url(cand_clean)[0] else cand_clean,
                    "confidence_level": cand_conf,
                    "corrections": corrections,
                    "bounding_box": bbox,
                    "source": "IMAGE_OCR"
                })

            # Convert annotated image to RGB PIL for UI display
            pil_annotated = Image.fromarray(cv2.cvtColor(annotated_img, cv2.COLOR_BGR2RGB))

            return {
                "status": "success",
                "message": f"Successfully extracted {len(urls_with_metadata)} URL candidate(s).",
                "raw_text": raw_text.strip(),
                "detected_urls": urls_with_metadata,
                "ocr_confidence": avg_ocr_conf,
                "annotated_image": pil_annotated,
                "quality": quality_report
            }

        except Exception as e:
            logger.error(f"OCR execution failed: {e}")
            return {
                "status": "error",
                "message": f"OCR processing failure: {str(e)}",
                "raw_text": "",
                "detected_urls": [],
                "ocr_confidence": 0.0,
                "annotated_image": None,
                "quality": quality_report
            }

    def _find_url_candidates(self, text: str) -> List[str]:
        """Searches text for regex URL patterns and deduplicates while preserving order."""
        if not text:
            return []
        matches = self.URL_REGEX.findall(text)
        deduped = []
        seen = set()
        for m in matches:
            cleaned = m.strip().strip(".,;:!'\"<>[]{}()")
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                deduped.append(cleaned)
        return deduped

    def suggest_ocr_corrections(self, raw_candidate: str) -> List[Dict[str, str]]:
        """
        Suggests conservative, user-reviewable OCR error corrections without automatic replacement:
        - 1 <-> l / I (e.g., paypa1.com -> paypal.com)
        - 0 <-> O / o (e.g., micr0soft.com -> microsoft.com)
        - rn <-> m (e.g., arnazon.com -> amazon.com)
        - vv <-> w (e.g., vvww.google.com -> www.google.com)
        """
        suggestions = []

        # 1. Digit '1' in domain name where letters are expected
        if "1" in raw_candidate:
            cand = raw_candidate.replace("1", "l")
            if cand != raw_candidate:
                suggestions.append({
                    "original": raw_candidate,
                    "corrected_candidate": cand,
                    "rule": "Replaced '1' with 'l' (common OCR substitution in alphabetic words)"
                })

        # 2. Digit '0' in domain name
        if "0" in raw_candidate:
            cand = raw_candidate.replace("0", "o")
            if cand != raw_candidate:
                suggestions.append({
                    "original": raw_candidate,
                    "corrected_candidate": cand,
                    "rule": "Replaced '0' with 'o' (common OCR zero/letter confusion)"
                })

        # 3. 'rn' to 'm'
        if "rn" in raw_candidate and not raw_candidate.startswith("http"):
            cand = raw_candidate.replace("rn", "m")
            suggestions.append({
                "original": raw_candidate,
                "corrected_candidate": cand,
                "rule": "Replaced 'rn' with 'm' (OCR ligature confusion)"
            })

        # 4. 'vv' to 'w'
        if "vv" in raw_candidate.lower():
            cand = re.sub(r'vv', 'w', raw_candidate, flags=re.IGNORECASE)
            suggestions.append({
                "original": raw_candidate,
                "corrected_candidate": cand,
                "rule": "Replaced 'vv' with 'w' (double-v OCR confusion)"
            })

        return suggestions

    def _locate_bbox(self, search_text: str, data: Dict[str, Any]) -> Optional[Tuple[int, int, int, int]]:
        """Locates the bounding box for words corresponding to the URL in Tesseract output."""
        try:
            words = data.get("text", [])
            for i, w in enumerate(words):
                if w and len(w) >= 4 and (w.lower() in search_text.lower() or search_text.lower() in w.lower()):
                    x = data["left"][i]
                    y = data["top"][i]
                    width = data["width"][i]
                    height = data["height"][i]
                    return (x, y, width, height)
        except Exception:
            pass
        return None

    def _to_cv_image(self, image_input: Union[str, Path, bytes, Image.Image, np.ndarray]) -> Optional[np.ndarray]:
        """Converts diverse image input formats into OpenCV BGR numpy array."""
        try:
            if isinstance(image_input, (str, Path)):
                return cv2.imread(str(image_input))
            elif isinstance(image_input, bytes):
                nparr = np.frombuffer(image_input, np.uint8)
                return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            elif isinstance(image_input, Image.Image):
                rgb = np.array(image_input.convert("RGB"))
                return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
            elif isinstance(image_input, np.ndarray):
                return image_input
        except Exception as e:
            logger.error(f"Image conversion error: {e}")
        return None
