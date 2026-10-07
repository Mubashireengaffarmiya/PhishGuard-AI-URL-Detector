"""
QR Code scanning and safe decoding module for PhishGuard AI.
Decodes QR image payloads using OpenCV QRCodeDetector, extracts and validates
embedded URLs without executing or navigating to the destination.
"""

from pathlib import Path
from typing import Tuple, Optional, Union
import cv2
import numpy as np
from PIL import Image

from src.utils import setup_logger, normalize_url, is_valid_url

logger = setup_logger("QRScanner")


class QRScanner:
    """
    Safely processes and extracts URLs from QR code images.
    """

    def __init__(self):
        self.detector = cv2.QRCodeDetector()

    def decode_image(self, image_input: Union[str, Path, bytes, Image.Image, np.ndarray]) -> Tuple[bool, str, str]:
        """
        Decodes a QR code from a file path, raw bytes, PIL Image, or numpy array.

        Returns:
            (success: bool, extracted_payload: str, message: str)
        """
        cv_img = None

        try:
            if isinstance(image_input, (str, Path)):
                img_path = str(image_input)
                cv_img = cv2.imread(img_path)
                if cv_img is None:
                    return False, "", f"Could not read image file from path: {img_path}"

            elif isinstance(image_input, bytes):
                nparr = np.frombuffer(image_input, np.uint8)
                cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if cv_img is None:
                    return False, "", "Could not decode byte stream into image."

            elif isinstance(image_input, Image.Image):
                # Convert PIL Image to OpenCV BGR format
                rgb_img = np.array(image_input.convert("RGB"))
                cv_img = cv2.cvtColor(rgb_img, cv2.COLOR_RGB2BGR)

            elif isinstance(image_input, np.ndarray):
                cv_img = image_input

            else:
                return False, "", f"Unsupported image input type: {type(image_input)}"

            if cv_img is None or cv_img.size == 0:
                return False, "", "Empty or invalid image data."

            # Attempt detection and decoding with OpenCV QRCodeDetector
            decoded_text, points, _ = self.detector.detectAndDecode(cv_img)

            if decoded_text:
                logger.info(f"QR Code decoded successfully. Payload length: {len(decoded_text)}")
                return True, decoded_text.strip(), "QR Code successfully decoded."

            # Fallback: preprocess image (grayscale and thresholding) for low-contrast QR codes
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            # Try adaptive threshold
            thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
            decoded_text, _, _ = self.detector.detectAndDecode(thresh)
            if decoded_text:
                return True, decoded_text.strip(), "QR Code decoded after image enhancement."

            # Try Otsu threshold
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            decoded_text, _, _ = self.detector.detectAndDecode(otsu)
            if decoded_text:
                return True, decoded_text.strip(), "QR Code decoded with Otsu thresholding."

            return False, "", "No QR code could be detected in the provided image."

        except Exception as e:
            logger.error(f"Error during QR code decoding: {e}")
            return False, "", f"QR decoding error: {str(e)}"

    def extract_url_from_qr(self, image_input: Union[str, Path, bytes, Image.Image, np.ndarray]) -> Tuple[bool, str, str]:
        """
        Decodes a QR code and validates that the payload constitutes a usable web URL.

        Returns:
            (is_valid_url: bool, url_extracted: str, status_message: str)
        """
        success, payload, msg = self.decode_image(image_input)
        if not success:
            return False, "", msg

        # Normalize and validate the extracted text
        normalized, _, norm_err = normalize_url(payload)
        if norm_err:
            return False, payload, f"Decoded QR payload is not a valid URL: {norm_err}"

        valid, val_reason = is_valid_url(normalized)
        if not valid:
            return False, payload, f"Decoded text is not a supported web URL ({val_reason}): '{payload}'"

        return True, normalized, "Valid URL extracted from QR code."


def generate_sample_qr_image(target_path: Path, url: str = "https://github.com/phishguard-ai") -> Path:
    """
    Generates a sample QR code image for demonstration and testing purposes.
    """
    import qrcode
    target_path.parent.mkdir(parents=True, exist_ok=True)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(target_path))
    logger.info(f"Generated sample QR image at: {target_path}")
    return target_path
