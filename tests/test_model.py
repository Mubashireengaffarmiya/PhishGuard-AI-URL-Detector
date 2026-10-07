
import numpy as np
import pytest

from src import prediction


class FakeModel:
    """Mock ML model for testing prediction logic."""

    def __init__(self, probability):
        self.probability = probability

    def predict(self, X):
        return np.array([int(self.probability >= 0.5)])

    def predict_proba(self, X):
        return np.array([[1 - self.probability, self.probability]])


class FakeScaler:
    """Mock scaler for Logistic Regression."""

    def transform(self, X):
        return X


@pytest.fixture
def predictor():
    """Create a predictor without loading actual model files."""

    model = prediction.PhishGuardPredictor.__new__(
        prediction.PhishGuardPredictor
    )

    model.lr_model = FakeModel(0.20)
    model.dt_model = FakeModel(0.30)
    model.rf_model = FakeModel(0.60)
    model.scaler = FakeScaler()

    model.weights = {
        "random_forest": 0.50,
        "decision_tree": 0.25,
        "logistic_regression": 0.25
    }

    return model


def test_model_import():
    assert prediction.PhishGuardPredictor is not None


def test_safe_prediction(predictor, monkeypatch):
    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: ("https://example.com", True, None)
    )

    monkeypatch.setattr(
        prediction,
        "extract_features_from_url",
        lambda url: {name: 0 for name in prediction.FEATURE_NAMES}
    )

    result = predictor.predict_url("example.com")

    assert result["ensemble"]["label"] == "SAFE"
    assert result["ensemble"]["prediction"] == 0


def test_phishing_prediction(predictor, monkeypatch):
    predictor.rf_model = FakeModel(0.95)
    predictor.dt_model = FakeModel(0.90)
    predictor.lr_model = FakeModel(0.85)

    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: ("https://suspicious.example", False, None)
    )

    monkeypatch.setattr(
        prediction,
        "extract_features_from_url",
        lambda url: {name: 0 for name in prediction.FEATURE_NAMES}
    )

    result = predictor.predict_url("https://suspicious.example")

    assert result["ensemble"]["label"] == "PHISHING"
    assert result["ensemble"]["prediction"] == 1


def test_invalid_url_raises_error(predictor, monkeypatch):
    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: (None, False, "Invalid URL")
    )

    with pytest.raises(ValueError, match="URL Normalization failed"):
        predictor.predict_url("invalid-url")


def test_ensemble_probability_is_bounded(predictor, monkeypatch):
    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: ("https://example.com", False, None)
    )

    monkeypatch.setattr(
        prediction,
        "extract_features_from_url",
        lambda url: {name: 0 for name in prediction.FEATURE_NAMES}
    )

    result = predictor.predict_url("https://example.com")

    probability = result["ensemble"]["phishing_probability"]

    assert 0.0 <= probability <= 1.0


def test_prediction_contains_all_models(predictor, monkeypatch):
    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: ("https://example.com", False, None)
    )

    monkeypatch.setattr(
        prediction,
        "extract_features_from_url",
        lambda url: {name: 0 for name in prediction.FEATURE_NAMES}
    )

    result = predictor.predict_url("https://example.com")

    assert set(result["individual_predictions"]) == {
        "Logistic Regression",
        "Decision Tree",
        "Random Forest"
    }


def test_model_disagreement_detection(predictor, monkeypatch):
    monkeypatch.setattr(
        prediction,
        "normalize_url",
        lambda url: ("https://example.com", False, None)
    )

    monkeypatch.setattr(
        prediction,
        "extract_features_from_url",
        lambda url: {name: 0 for name in prediction.FEATURE_NAMES}
    )

    result = predictor.predict_url("https://example.com")

    assert result["ensemble"]["has_disagreement"] is True
    assert result["ensemble"]["disagreement_summary"] != ""
