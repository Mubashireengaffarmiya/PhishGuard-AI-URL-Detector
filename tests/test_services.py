"""
Comprehensive Unit Test Suite for PhishGuard AI.
Tests prediction pipeline, explainability engine, safe trust factors,
multi-modal OCR and QR intake, error corrections, image quality diagnostics,
history persistence, privacy masking, PDF/JSON/CSV reports, and health checks.
All network-dependent operations are fully mocked or local to guarantee 100% offline passing.
"""

import pytest
import numpy as np
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw

from src.utils import normalize_url, is_valid_url
from src.feature_extraction import extract_features_from_url, FEATURE_NAMES
from src.services.prediction_service import PredictionService, get_predictor
from src.services.explanation_service import ExplanationService
from src.services.ai_service import AISecurityAnalystService
from src.services.threat_intelligence_service import ThreatIntelService
from src.services.history_service import HistoryService
from src.services.report_service import ReportService
from src.services.qr_service import QRService
from src.services.ocr_service import OCRService
from src.services.image_service import ImageScanService
from src.services.health_service import HealthService
from src.services.demo_service import DemoService
from src.services.telemetry_service import TelemetryService
from src.database import ScanDatabase


# 1. URL Normalization & Validation Tests
def test_url_normalization_handles_missing_scheme():
    norm, scheme_added, err = normalize_url("chase.com/login")
    assert not err
    assert scheme_added is True
    assert norm == "https://chase.com/login"


def test_url_normalization_rejects_empty_and_control_chars():
    _, _, err1 = normalize_url("")
    assert "empty" in err1.lower()

    _, _, err2 = normalize_url("https://example.com/\nmalicious")
    assert "newline or control" in err2.lower()


def test_is_valid_url():
    valid, _ = is_valid_url("https://www.paypal.com")
    assert valid is True

    invalid, reason = is_valid_url("ftp://ftp.example.com")
    assert invalid is False
    assert "only http and https" in reason.lower()


# 2. Feature Extraction Tests
def test_feature_extraction_completeness():
    features = extract_features_from_url("https://login-verify.paypal-security.xyz:8888/auth/login.php?user=123#anchor")
    assert len(features) == len(FEATURE_NAMES)
    assert features["is_https"] == 1
    assert features["is_suspicious_tld"] == 1
    assert features["is_suspicious_port"] == 1
    assert features["qty_suspicious_keywords"] >= 2
    assert features["url_entropy"] > 0


# 3. Prediction & Multi-Model Ensemble Tests
def test_prediction_service_safe_url():
    ps = PredictionService()
    res = ps.analyze_url("https://www.google.com", input_source="MANUAL_URL", persist=False)
    assert res["classification"] == "SAFE"
    assert res["risk_score"] < 30
    assert 0.0 <= res["ensemble"]["phishing_probability"] <= 1.0
    assert "Random Forest" in res["individual_predictions"]
    assert "Decision Tree" in res["individual_predictions"]
    assert "Logistic Regression" in res["individual_predictions"]


def test_prediction_service_phishing_url():
    ps = PredictionService()
    res = ps.analyze_url("http://192.168.1.1:8080/paypal-update-login.php?verify=account", input_source="MANUAL_URL", persist=False)
    assert res["classification"] == "PHISHING"
    assert res["risk_score"] >= 70
    assert res["ensemble"]["phishing_probability"] > 0.8


# 4. Explainability & Safe Trust Indicators
def test_explanation_service_indicators():
    exp = ExplanationService()
    features = extract_features_from_url("http://10.0.0.1:8080/verify-account")
    indicators = exp.get_indicator_breakdown(features, "http://10.0.0.1:8080/verify-account")
    assert len(indicators) >= 5
    for ind in indicators:
        assert "indicator" in ind
        assert "observed_value" in ind
        assert "why_it_matters" in ind
        assert "limitation" in ind


def test_safe_url_explanation_and_disclaimer():
    exp = ExplanationService()
    features = extract_features_from_url("https://chase.com")
    indiv = {
        "Random Forest": {"label": "SAFE"},
        "Decision Tree": {"label": "SAFE"},
        "Logistic Regression": {"label": "SAFE"},
    }
    safe_info = exp.get_safe_url_explanation(features, indiv)
    assert len(safe_info["trust_factors"]) >= 3
    assert "disclaimer" in safe_info
    assert "machine-learning assessment" in safe_info["disclaimer"]


# 5. History & Privacy Redaction Tests
def test_history_service_privacy_masking():
    url = "https://bank.example.com/portal/login.php?token=secret123"
    assert HistoryService.mask_url(url, "SHOW_ALL") == url
    assert HistoryService.mask_url(url, "MASK_QUERY") == "https://bank.example.com/portal/login.php"
    assert HistoryService.mask_url(url, "MASK_PATH") == "https://bank.example.com/***"
    assert "***" in HistoryService.mask_url(url, "MASK_ALL")


def test_history_database_persistence(tmp_path):
    db_path = tmp_path / "test_scans.db"
    test_db = ScanDatabase(db_path=db_path)
    hist = HistoryService(db=test_db)
    scan_id = test_db.save_scan(
        url="https://test.example.com",
        normalized_url="https://test.example.com",
        classification="SAFE",
        risk_score=15.0,
        lr_prediction="SAFE",
        dt_prediction="SAFE",
        rf_prediction="SAFE",
        ensemble_prob=0.15,
        reason_summary="Test summary",
        features={"url_length": 25}
    )
    assert scan_id > 0
    records = hist.get_history()
    assert len(records) >= 1
    assert records[0]["classification"] == "SAFE"

    csv_out = hist.export_csv()
    assert "test.example.com" in csv_out

    json_out = hist.export_json()
    assert "test.example.com" in json_out


# 6. Report Generator Tests
def test_report_service_pdf_and_json():
    with tempfile.TemporaryDirectory() as tmp_dir:
        rs = ReportService(output_dir=Path(tmp_dir))
        dummy_scan = {
            "id": 999,
            "url": "https://example.com/test",
            "submitted_url": "https://example.com/test",
            "normalized_url": "https://example.com/test",
            "timestamp": "2026-10-02 12:00:00",
            "classification": "SAFE",
            "risk_score": 10.0,
            "individual_predictions": {
                "Random Forest": {"label": "SAFE"},
                "Decision Tree": {"label": "SAFE"},
                "Logistic Regression": {"label": "SAFE"},
            },
            "ensemble": {"phishing_probability": 0.10, "has_disagreement": False},
            "explanation": {"summary": "Safe test URL"},
            "features": {"url_length": 22, "is_https": 1}
        }
        pdf_path = rs.generate_pdf_report(dummy_scan)
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000

        json_dump = rs.generate_json_report(dummy_scan)
        assert "SAFE" in json_dump

        csv_dump = rs.generate_csv_report(dummy_scan)
        assert "SAFE" in csv_dump


# 7. QR Decoder Tests
def test_qr_service_sample_generation_and_decoding():
    with tempfile.TemporaryDirectory() as tmp_dir:
        qr_file = Path(tmp_dir) / "sample_qr.png"
        qr_svc = QRService()
        qr_svc.generate_demo_qr(qr_file, url="https://verify.paypal.example.org")
        assert qr_file.exists()

        dec = qr_svc.decode_qr(qr_file)
        assert dec["success"] is True
        assert dec["is_url"] is True
        assert "verify.paypal.example.org" in dec["normalized_url"]


# 8. OCR Service Tests (URL Extraction & Corrections)
def test_ocr_service_url_regex():
    ocr = OCRService()
    sample_text = (
        "Please visit our support portal at https://secure-account.help-desk.com/login "
        "or visit www.service-login.xyz for assistance. Also notice 192.168.1.50:8000."
    )
    cands = ocr._find_url_candidates(sample_text)
    assert len(cands) >= 2
    assert any("secure-account.help-desk.com" in c for c in cands)


def test_ocr_service_conservative_corrections():
    ocr = OCRService()
    # 1 -> l test
    corr1 = ocr.suggest_ocr_corrections("paypa1.com")
    assert any(c["corrected_candidate"] == "paypal.com" for c in corr1)

    # 0 -> o test
    corr2 = ocr.suggest_ocr_corrections("micr0soft.com")
    assert any(c["corrected_candidate"] == "microsoft.com" for c in corr2)

    # vv -> w test
    corr3 = ocr.suggest_ocr_corrections("vvww.google.com")
    assert any("www.google.com" in c["corrected_candidate"] for c in corr3)


def test_image_quality_analysis():
    ocr = OCRService()
    # Create sharp image
    img = Image.new("RGB", (600, 400), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((50, 50), "High contrast sharp text", fill=(0, 0, 0))
    cv_img = np.array(img)

    quality = ocr.analyze_image_quality(cv_img)
    assert quality["dimensions"] == (600, 400)
    assert quality["is_low_res"] is False


# 9. AI Security Analyst Tests (Rule-Based Fallback)
def test_ai_security_analyst_grounded_fallback():
    ai = AISecurityAnalystService()
    dummy_scan = {
        "submitted_url": "http://192.168.1.1:8080/login",
        "classification": "PHISHING",
        "risk_score": 92.5,
        "ensemble": {"phishing_probability": 0.95, "has_disagreement": False},
        "individual_predictions": {
            "Random Forest": {"label": "PHISHING", "phishing_probability": 0.96},
            "Decision Tree": {"label": "PHISHING", "phishing_probability": 0.94},
            "Logistic Regression": {"label": "PHISHING", "phishing_probability": 0.95},
        },
        "features": {"is_ip_address": 1, "is_http": 1, "is_suspicious_port": 1, "url_entropy": 4.6}
    }

    ans_flagged = ai.answer_query("Why was this URL flagged?", dummy_scan)
    assert "Raw IP Host" in ans_flagged["response"] or "PHISHING" in ans_flagged["response"]

    ans_viva = ai.answer_query("Explain for faculty presentation", dummy_scan)
    assert "Academic & Viva Defense Summary" in ans_viva["response"]

    ans_actions = ai.answer_query("What should I do after receiving this link?", dummy_scan)
    assert "Incident Response Actions" in ans_actions["response"]


# 10. Health & Diagnostics Tests
def test_health_service_subsystems_check():
    h = HealthService.check_all_subsystems()
    assert h["overall_health"] in ("OPERATIONAL", "DEGRADED")
    assert h["total_components"] == 11
    assert h["ready_count"] >= 10
    names = [s["name"] for s in h["subsystems"]]
    assert "Logistic Regression Model" in names
    assert "Random Forest Model" in names
    assert "QR Code Scanner" in names
    assert "OCR Text Recognition Engine" in names


# 11. Demo Service Integrity Tests
def test_demo_service_cases():
    cases = DemoService.get_all_demos()
    assert len(cases) >= 6
    for c in cases:
        assert "id" in c
        assert "title" in c
        assert "url" in c
        assert "category" in c
        assert len(c["talking_points"]) >= 1


# 12. Telemetry & Dashboard Statistics Tests
def test_telemetry_service_initial_and_reset_state():
    tele = TelemetryService()
    stats = tele.get_session_stats()
    assert stats["total_scans"] == 0
    assert stats["safe_count"] == 0
    assert stats["phishing_count"] == 0
    assert stats["disagreement_count"] == 0
    assert stats["avg_phishing_prob"] == 0.0
    assert stats["image_scans"] == 0
    assert stats["qr_scans"] == 0
    assert stats["demo_scans"] == 0


def test_telemetry_service_safe_and_phishing_scans():
    tele = TelemetryService()

    # Scan 1: SAFE URL
    safe_scan = {
        "classification": "SAFE",
        "ensemble": {"phishing_probability": 0.04, "has_disagreement": False},
        "individual_predictions": {
            "Random Forest": {"label": "SAFE"},
            "Decision Tree": {"label": "SAFE"},
            "Logistic Regression": {"label": "SAFE"},
        }
    }
    stats = tele.record_url_scan(safe_scan)
    assert stats["total_scans"] == 1
    assert stats["safe_count"] == 1
    assert stats["phishing_count"] == 0
    assert stats["disagreement_count"] == 0
    assert pytest.approx(stats["avg_phishing_prob"], 0.001) == 0.04

    # Scan 2: PHISHING URL
    phish_scan = {
        "classification": "PHISHING",
        "ensemble": {"phishing_probability": 0.96, "has_disagreement": False},
        "individual_predictions": {
            "Random Forest": {"label": "PHISHING"},
            "Decision Tree": {"label": "PHISHING"},
            "Logistic Regression": {"label": "PHISHING"},
        }
    }
    stats = tele.record_url_scan(phish_scan)
    assert stats["total_scans"] == 2
    assert stats["safe_count"] == 1
    assert stats["phishing_count"] == 1
    assert stats["disagreement_count"] == 0
    # Average of 0.04 and 0.96 = 0.50
    assert pytest.approx(stats["avg_phishing_prob"], 0.001) == 0.50


def test_telemetry_service_model_divergence():
    tele = TelemetryService()
    divergent_scan = {
        "classification": "SUSPICIOUS",
        "ensemble": {"phishing_probability": 0.55, "has_disagreement": True},
        "individual_predictions": {
            "Random Forest": {"label": "PHISHING"},
            "Decision Tree": {"label": "SAFE"},
            "Logistic Regression": {"label": "SAFE"},
        }
    }
    stats = tele.record_url_scan(divergent_scan)
    assert stats["total_scans"] == 1
    assert stats["warning_count"] == 1
    assert stats["disagreement_count"] == 1
    assert pytest.approx(stats["avg_phishing_prob"], 0.001) == 0.55


def test_telemetry_service_image_qr_and_demo_scans():
    tele = TelemetryService()
    tele.record_image_scan()
    tele.record_image_scan()
    tele.record_qr_scan()
    tele.record_demo_scan()

    stats = tele.get_session_stats()
    assert stats["image_scans"] == 2
    assert stats["qr_scans"] == 1
    assert stats["demo_scans"] == 1


def test_telemetry_service_error_safety():
    tele = TelemetryService()
    # Invalid scan results (None, non-dict, missing classification)
    tele.record_url_scan(None)  # type: ignore
    tele.record_url_scan({})
    tele.record_url_scan({"error": "Failed to normalize"})

    stats = tele.get_session_stats()
    assert stats["total_scans"] == 0
    assert stats["safe_count"] == 0
    assert stats["phishing_count"] == 0


def test_database_dashboard_metrics_divergence_and_prob(tmp_path):
    from src.database import ScanDatabase
    db = ScanDatabase(db_path=tmp_path / "test_metrics.db")

    # Save a safe scan (agreeing)
    db.save_scan(
        url="https://google.com",
        normalized_url="https://google.com",
        classification="SAFE",
        risk_score=5.0,
        lr_prediction="SAFE",
        dt_prediction="SAFE",
        rf_prediction="SAFE",
        ensemble_prob=0.05,
        reason_summary="Safe test URL"
    )

    # Save a phishing scan with divergence (DT says SAFE, RF says PHISHING)
    db.save_scan(
        url="http://fake-bank-login.xyz",
        normalized_url="http://fake-bank-login.xyz",
        classification="PHISHING",
        risk_score=90.0,
        lr_prediction="PHISHING",
        dt_prediction="SAFE",
        rf_prediction="PHISHING",
        ensemble_prob=0.85,
        reason_summary="Phishing test URL"
    )

    metrics = db.get_dashboard_metrics()
    assert metrics["total_scans"] == 2
    assert metrics["safe_count"] == 1
    assert metrics["phishing_count"] == 1
    assert metrics["disagreement_count"] == 1
    assert pytest.approx(metrics["avg_phishing_prob"], 0.001) == 0.45


def test_telemetry_service_sync_with_database(tmp_path):
    from src.database import ScanDatabase
    db = ScanDatabase(db_path=tmp_path / "test_sync.db")
    db.save_scan(
        url="https://verified.gov",
        normalized_url="https://verified.gov",
        classification="SAFE",
        risk_score=2.0,
        lr_prediction="SAFE",
        dt_prediction="SAFE",
        rf_prediction="SAFE",
        ensemble_prob=0.02,
        reason_summary="Legitimate portal"
    )

    tele = TelemetryService()
    # Initially 0
    assert tele.get_session_stats()["total_scans"] == 0

    # Sync with DB
    stats = tele.sync_with_database(db)
    assert stats["total_scans"] == 1
    assert stats["safe_count"] == 1
    assert stats["phishing_count"] == 0
    assert pytest.approx(stats["avg_phishing_prob"], 0.001) == 0.02


def test_telemetry_service_deduplication_by_scan_id():
    tele = TelemetryService()
    scan_item = {
        "scan_id": 999,
        "classification": "SAFE",
        "ensemble": {"phishing_probability": 0.05, "has_disagreement": False},
        "individual_predictions": {
            "Random Forest": {"label": "SAFE"},
            "Decision Tree": {"label": "SAFE"},
            "Logistic Regression": {"label": "SAFE"},
        }
    }

    # Record first time
    s1 = tele.record_url_scan(scan_item)
    assert s1["total_scans"] == 1
    assert s1["safe_count"] == 1

    # Record second time with identical scan_id: must not double-count!
    s2 = tele.record_url_scan(scan_item)
    assert s2["total_scans"] == 1
    assert s2["safe_count"] == 1


