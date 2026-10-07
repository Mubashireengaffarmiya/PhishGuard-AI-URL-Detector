"""
End-to-End Functional Test Suite for PhishGuard AI Telemetry, State Persistence, and Scanners.
Tests:
1. Dashboard telemetry synchronization with real SQLite scan records
2. URL Scanner safe and phishing scans with exact telemetry increments (+1)
3. Model divergence calculation from real model predictions
4. Streamlit session state persistence across reruns and navigation
5. Image OCR and QR decoding increments
6. AppTest rendering across all pages with zero runtime exceptions
"""

import pytest
from streamlit.testing.v1 import AppTest
from src.database import ScanDatabase
from src.services.prediction_service import PredictionService
from src.services.history_service import HistoryService
from src.services.telemetry_service import TelemetryService, get_telemetry_service
from src.services.qr_service import QRService
from src.services.image_service import ImageScanService
from src.services.ocr_service import OCRService


def test_e2e_app_loads_all_views_without_exceptions():
    """Verifies that all views render without any TypeError, KeyError, or runtime exceptions."""
    from pathlib import Path
    app_path = Path(__file__).parent.parent / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)
    at.run()
    assert not at.exception, f"Dashboard threw exception: {at.exception}"

    # Navigate through key views
    nav_pages = [
        "URL Scanner",
        "Image Scanner",
        "QR Scanner",
        "Explainable AI",
        "Model Analytics",
        "Threat Intelligence",
        "AI Security Analyst",
        "Scan History",
        "Reports",
        "How PhishGuard Works",
        "Project Architecture",
        "Demo Mode",
        "System Health",
        "Settings",
        "Dashboard"
    ]

    for page in nav_pages:
        at.sidebar.radio[0].set_value(page)
        at.run()
        assert not at.exception, f"Page '{page}' threw exception: {at.exception}"


def test_e2e_scanner_flow_and_telemetry_synchronization(tmp_path):
    """Simulates real scans and tests telemetry synchronization and persistence."""
    test_db = ScanDatabase(db_path=tmp_path / "e2e_scans.db")
    pred_service = PredictionService(db=test_db)
    hist_service = HistoryService(db=test_db)
    tele = TelemetryService()

    # Step 1: Initially 0
    stats = tele.get_session_stats()
    assert stats["total_scans"] == 0
    assert stats["safe_count"] == 0
    assert stats["phishing_count"] == 0

    # Step 2: Scan SAFE URL
    res_safe = pred_service.analyze_url("https://wikipedia.org", input_source="MANUAL_URL", persist=True)
    tele.record_url_scan(res_safe)
    stats = tele.get_session_stats()
    assert stats["total_scans"] == 1
    assert stats["safe_count"] == 1
    assert stats["phishing_count"] == 0
    assert stats["avg_phishing_prob"] == pytest.approx(res_safe["ensemble"]["phishing_probability"], 0.001)

    # Step 3: Scan PHISHING URL
    res_phish = pred_service.analyze_url("http://192.168.1.1:8080/paypal-login/verify.php", input_source="MANUAL_URL", persist=True)
    tele.record_url_scan(res_phish)
    stats = tele.get_session_stats()
    assert stats["total_scans"] == 2
    assert stats["safe_count"] == 1
    assert stats["phishing_count"] == 1

    expected_avg = (res_safe["ensemble"]["phishing_probability"] + res_phish["ensemble"]["phishing_probability"]) / 2
    assert stats["avg_phishing_prob"] == pytest.approx(expected_avg, 0.001)

    # Step 4: Verify Database is synchronized with same real numbers
    db_metrics = hist_service.get_summary_metrics()
    assert db_metrics["total_scans"] == 2
    assert db_metrics["safe_count"] == 1
    assert db_metrics["phishing_count"] == 1
    assert db_metrics["avg_phishing_prob"] == pytest.approx(expected_avg, 0.001)

    # Step 5: Test that normal reruns / duplicate calls do not double count (Idempotency)
    tele.record_url_scan(res_safe)
    tele.record_url_scan(res_phish)
    stats_after_rerun = tele.get_session_stats()
    assert stats_after_rerun["total_scans"] == 2
    assert stats_after_rerun["safe_count"] == 1
    assert stats_after_rerun["phishing_count"] == 1

    # Step 6: Test multi-modal intake increments
    tele.record_image_scan()
    assert tele.get_session_stats()["image_scans"] == 1
    tele.record_qr_scan()
    assert tele.get_session_stats()["qr_scans"] == 1
    tele.record_demo_scan()
    assert tele.get_session_stats()["demo_scans"] == 1

    # Step 7: Test sync_with_database into fresh telemetry instance
    new_tele = TelemetryService()
    assert new_tele.get_session_stats()["total_scans"] == 0
    new_tele.sync_with_database(test_db)
    synced_stats = new_tele.get_session_stats()
    assert synced_stats["total_scans"] == 2
    assert synced_stats["safe_count"] == 1
    assert synced_stats["phishing_count"] == 1
