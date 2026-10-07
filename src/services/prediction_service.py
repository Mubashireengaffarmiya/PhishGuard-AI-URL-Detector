"""
Prediction Service for PhishGuard AI.
Wraps PhishGuardPredictor, handles inference lifecycle, computes ensemble
metrics, integrates risk scoring, and logs scans to the database with source tracking.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from src.prediction import PhishGuardPredictor
from src.risk_score import calculate_risk_score
from src.explanation import generate_explanation
from src.database import ScanDatabase
from src.threat_intelligence import collect_threat_intelligence
from src.utils import setup_logger, normalize_url, is_valid_url

logger = setup_logger("PredictionService")

# Global singleton predictor instance
_PREDICTOR_INSTANCE: Optional[PhishGuardPredictor] = None
_DATABASE_INSTANCE: Optional[ScanDatabase] = None


def get_predictor() -> PhishGuardPredictor:
    """Returns singleton PhishGuardPredictor instance, caching loaded models in memory."""
    global _PREDICTOR_INSTANCE
    if _PREDICTOR_INSTANCE is None:
        logger.info("Initializing global PhishGuardPredictor singleton...")
        _PREDICTOR_INSTANCE = PhishGuardPredictor()
    return _PREDICTOR_INSTANCE


def get_database() -> ScanDatabase:
    """Returns singleton ScanDatabase instance."""
    global _DATABASE_INSTANCE
    if _DATABASE_INSTANCE is None:
        _DATABASE_INSTANCE = ScanDatabase()
    return _DATABASE_INSTANCE


class PredictionService:
    """
    High-level facade for end-to-end URL risk analysis across all input channels.
    Manual URL, QR Code, and Image/OCR extracted URLs all route through this service.
    """

    def __init__(self, predictor: Optional[PhishGuardPredictor] = None, db: Optional[ScanDatabase] = None):
        self.predictor = predictor or get_predictor()
        self.db = db or get_database()

    def analyze_url(
        self,
        raw_url: str,
        input_source: str = "MANUAL_URL",
        include_threat_intel: bool = False,
        persist: bool = True
    ) -> Dict[str, Any]:
        """
        Executes end-to-end security analysis for a single URL candidate.

        Args:
            raw_url: The unvalidated URL candidate string
            input_source: One of 'MANUAL_URL', 'QR_CODE', 'IMAGE_OCR', 'DEMO'
            include_threat_intel: If True, performs passive DNS/SSL/WHOIS checks
            persist: If True, logs the scan to the database

        Returns:
            Structured dictionary containing model predictions, ensemble results,
            risk score, explanation narrative, threat intelligence, and scan metadata.
        """
        cleaned_url = raw_url.strip() if raw_url else ""
        if not cleaned_url:
            raise ValueError("URL input cannot be empty.")

        # 1. Normalization & Validation
        norm_url, scheme_added, norm_err = normalize_url(cleaned_url)
        if norm_err:
            raise ValueError(f"Normalization failed: {norm_err}")

        valid, val_reason = is_valid_url(norm_url)
        if not valid:
            raise ValueError(f"Invalid URL structure ({val_reason}): {cleaned_url}")

        # 2. Core Machine Learning Prediction (Preserving original logic)
        ml_result = self.predictor.predict_url(cleaned_url)

        # 3. Optional Passive Threat Intelligence
        threat_intel_data = None
        if include_threat_intel:
            try:
                threat_intel_data = collect_threat_intelligence(norm_url)
            except Exception as e:
                logger.warning(f"Threat intelligence collection encountered an error: {e}")
                threat_intel_data = {"status": "error", "message": str(e)}

        # 4. Composite Risk Score Calculation
        risk_result = calculate_risk_score(
            ensemble_phishing_prob=ml_result["ensemble"]["phishing_probability"],
            features=ml_result["features"],
            threat_intel=threat_intel_data
        )

        # 5. Explainable Security Narrative
        explanation_result = generate_explanation(
            features=ml_result["features"],
            classification=risk_result["classification"],
            risk_score=risk_result["risk_score"],
            raw_url=ml_result["submitted_url"]
        )

        # 6. Assemble Comprehensive Result Object
        scan_id = None
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 7. Persistence (if enabled)
        if persist and self.db:
            try:
                scan_id = self.db.save_scan(
                    url=ml_result["submitted_url"],
                    normalized_url=ml_result["normalized_url"],
                    classification=risk_result["classification"],
                    risk_score=risk_result["risk_score"],
                    lr_prediction=ml_result["individual_predictions"]["Logistic Regression"]["label"],
                    dt_prediction=ml_result["individual_predictions"]["Decision Tree"]["label"],
                    rf_prediction=ml_result["individual_predictions"]["Random Forest"]["label"],
                    ensemble_prob=ml_result["ensemble"]["phishing_probability"],
                    reason_summary=explanation_result.get("summary", ""),
                    features=ml_result["features"]
                )
            except Exception as e:
                logger.error(f"Failed to persist scan to database: {e}")

        complete_result = {
            "scan_id": scan_id or 0,
            "timestamp": timestamp_str,
            "input_source": input_source,
            "submitted_url": ml_result["submitted_url"],
            "normalized_url": ml_result["normalized_url"],
            "scheme_was_added": ml_result["scheme_was_added"],
            "classification": risk_result["classification"],
            "risk_score": risk_result["risk_score"],
            "status_label": risk_result["status_label"],
            "emoji": risk_result["emoji"],
            "css_color": risk_result["css_color"],
            "risk_breakdown": risk_result["components"],
            "thresholds": risk_result["thresholds"],
            "ensemble": ml_result["ensemble"],
            "individual_predictions": ml_result["individual_predictions"],
            "features": ml_result["features"],
            "explanation": explanation_result,
            "threat_intel": threat_intel_data,
        }

        # Record in unified session telemetry
        try:
            from src.services.telemetry_service import get_telemetry_service
            get_telemetry_service().record_url_scan(complete_result)
        except Exception as te:
            logger.debug(f"Telemetry recording in analyze_url skipped: {te}")

        return complete_result
