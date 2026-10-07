"""
Services package for PhishGuard AI.
Modular business logic, prediction engine wrapping, explainability,
OCR extraction, QR decoding, AI assistant, and health diagnostics.
"""

from src.services.prediction_service import PredictionService
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
from src.services.telemetry_service import TelemetryService, get_telemetry_service

__all__ = [
    "PredictionService",
    "ExplanationService",
    "AISecurityAnalystService",
    "ThreatIntelService",
    "HistoryService",
    "ReportService",
    "QRService",
    "OCRService",
    "ImageScanService",
    "HealthService",
    "DemoService",
    "TelemetryService",
    "get_telemetry_service",
]
