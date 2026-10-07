"""
Prediction and Ensemble module for PhishGuard AI.
Loads persisted ML models and scaler, extracts features from a candidate URL,
generates individual model classifications and probabilities, and computes
a transparent weighted ensemble prediction with disagreement detection.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import numpy as np

from src.config import (
    LOGISTIC_REGRESSION_PATH,
    DECISION_TREE_PATH,
    RANDOM_FOREST_PATH,
    SCALER_PATH,
    FEATURE_METADATA_PATH,
    ENSEMBLE_WEIGHTS,
)
from src.feature_extraction import FEATURE_NAMES, extract_features_from_url
from src.utils import setup_logger, normalize_url

logger = setup_logger("PredictionEngine")


class PhishGuardPredictor:
    """
    Inference and ensemble prediction engine.
    Caches models in memory and evaluates candidate URLs safely.
    """

    def __init__(
        self,
        lr_path: Path = LOGISTIC_REGRESSION_PATH,
        dt_path: Path = DECISION_TREE_PATH,
        rf_path: Path = RANDOM_FOREST_PATH,
        scaler_path: Path = SCALER_PATH,
        metadata_path: Path = FEATURE_METADATA_PATH,
        weights: Optional[Dict[str, float]] = None
    ):
        self.lr_path = lr_path
        self.dt_path = dt_path
        self.rf_path = rf_path
        self.scaler_path = scaler_path
        self.metadata_path = metadata_path
        self.weights = weights or ENSEMBLE_WEIGHTS

        self.lr_model = None
        self.dt_model = None
        self.rf_model = None
        self.scaler = None
        self.feature_metadata = None

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """
        Loads all required model artifacts from disk.
        """
        missing = []
        for name, path in [
            ("Logistic Regression", self.lr_path),
            ("Decision Tree", self.dt_path),
            ("Random Forest", self.rf_path),
            ("Scaler", self.scaler_path),
            ("Feature Metadata", self.metadata_path),
        ]:
            if not path.exists():
                missing.append(f"{name} ({path})")

        if missing:
            err_msg = f"Missing model artifacts: {', '.join(missing)}. Please run model training first."
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        logger.info("Loading pre-trained models and scaler...")
        self.lr_model = joblib.load(self.lr_path)
        self.dt_model = joblib.load(self.dt_path)
        self.rf_model = joblib.load(self.rf_path)
        self.scaler = joblib.load(self.scaler_path)
        self.feature_metadata = joblib.load(self.metadata_path)
        logger.info("All model artifacts loaded successfully.")

    def predict_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Extracts features and predicts classification for a single URL.
        Never navigates to or executes the URL.
        """
        normalized_url, scheme_added, norm_err = normalize_url(raw_url)
        if norm_err:
            raise ValueError(f"URL Normalization failed: {norm_err}")

        # Extract features in strict deterministic order
        features_dict = extract_features_from_url(normalized_url)
        feature_vector = np.array([[features_dict[name] for name in FEATURE_NAMES]])

        # 1. Evaluate Decision Tree (unscaled)
        dt_pred = int(self.dt_model.predict(feature_vector)[0])
        dt_prob = float(self.dt_model.predict_proba(feature_vector)[0][1])

        # 2. Evaluate Random Forest (unscaled)
        rf_pred = int(self.rf_model.predict(feature_vector)[0])
        rf_prob = float(self.rf_model.predict_proba(feature_vector)[0][1])

        # 3. Evaluate Logistic Regression (scaled)
        feature_vector_scaled = self.scaler.transform(feature_vector)
        lr_pred = int(self.lr_model.predict(feature_vector_scaled)[0])
        lr_prob = float(self.lr_model.predict_proba(feature_vector_scaled)[0][1])

        # 4. Compute Weighted Transparent Ensemble
        w_rf = self.weights.get("random_forest", 0.50)
        w_dt = self.weights.get("decision_tree", 0.25)
        w_lr = self.weights.get("logistic_regression", 0.25)

        weighted_prob = (w_rf * rf_prob) + (w_dt * dt_prob) + (w_lr * lr_prob)
        weighted_prob = max(0.0, min(1.0, float(weighted_prob)))

        ensemble_pred = 1 if weighted_prob >= 0.50 else 0
        ensemble_label = "PHISHING" if ensemble_pred == 1 else "SAFE"

        # Disagreement check
        predictions_set = {lr_pred, dt_pred, rf_pred}
        has_disagreement = len(predictions_set) > 1

        disagreement_summary = ""
        if has_disagreement:
            votes_phish = sum([lr_pred, dt_pred, rf_pred])
            disagreement_summary = (
                f"Model divergence detected: {votes_phish}/3 models voted Phishing. "
                f"(LR: {'Phishing' if lr_pred else 'Safe'}, "
                f"DT: {'Phishing' if dt_pred else 'Safe'}, "
                f"RF: {'Phishing' if rf_pred else 'Safe'}). "
                f"Resolved via weighted ensemble probability ({weighted_prob * 100:.1f}%)."
            )

        return {
            "submitted_url": raw_url,
            "normalized_url": normalized_url,
            "scheme_was_added": scheme_added,
            "features": features_dict,
            "individual_predictions": {
                "Logistic Regression": {
                    "prediction": lr_pred,
                    "label": "PHISHING" if lr_pred == 1 else "SAFE",
                    "phishing_probability": round(lr_prob, 4),
                    "safe_probability": round(1.0 - lr_prob, 4),
                    "weight": w_lr
                },
                "Decision Tree": {
                    "prediction": dt_pred,
                    "label": "PHISHING" if dt_pred == 1 else "SAFE",
                    "phishing_probability": round(dt_prob, 4),
                    "safe_probability": round(1.0 - dt_prob, 4),
                    "weight": w_dt
                },
                "Random Forest": {
                    "prediction": rf_pred,
                    "label": "PHISHING" if rf_pred == 1 else "SAFE",
                    "phishing_probability": round(rf_prob, 4),
                    "safe_probability": round(1.0 - rf_prob, 4),
                    "weight": w_rf
                }
            },
            "ensemble": {
                "prediction": ensemble_pred,
                "label": ensemble_label,
                "phishing_probability": round(weighted_prob, 4),
                "safe_probability": round(1.0 - weighted_prob, 4),
                "has_disagreement": has_disagreement,
                "disagreement_summary": disagreement_summary,
                "weights_used": self.weights
            }
        }
