"""
Report Service for PhishGuard AI.
Wraps ReportLab PDF SecurityReportGenerator, generates machine-readable JSON exports,
and structures CSV security audit summaries for individual scans and bulk exports.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import json
import pandas as pd
from datetime import datetime

from src.report_generator import SecurityReportGenerator
from src.config import GENERATED_REPORTS_DIR
from src.utils import setup_logger

logger = setup_logger("ReportService")


class ReportService:
    """
    Generates downloadable cybersecurity audit reports in PDF, JSON, and CSV formats.
    """

    def __init__(self, output_dir: Path = GENERATED_REPORTS_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.pdf_generator = SecurityReportGenerator(output_dir=self.output_dir)

    def generate_pdf_report(self, scan_data: Dict[str, Any]) -> Path:
        """
        Produces a publication-quality PDF audit report using ReportLab.
        """
        # Adapt keys to match what SecurityReportGenerator expects
        formatted_data = dict(scan_data)
        if "submitted_url" in formatted_data and "url" not in formatted_data:
            formatted_data["url"] = formatted_data["submitted_url"]
        if "individual_predictions" in formatted_data:
            indiv = formatted_data["individual_predictions"]
            formatted_data["lr_prediction"] = indiv.get("Logistic Regression", {}).get("label", "N/A")
            formatted_data["dt_prediction"] = indiv.get("Decision Tree", {}).get("label", "N/A")
            formatted_data["rf_prediction"] = indiv.get("Random Forest", {}).get("label", "N/A")
        if "ensemble" in formatted_data:
            formatted_data["ensemble_prob"] = formatted_data["ensemble"].get("phishing_probability", 0.0)
        if "explanation" in formatted_data and "reason_summary" not in formatted_data:
            formatted_data["reason_summary"] = formatted_data["explanation"].get("summary", "")

        return self.pdf_generator.generate_pdf(formatted_data)

    def generate_json_report(self, scan_data: Dict[str, Any]) -> str:
        """Serializes complete scan telemetry and results to formatted JSON."""
        return json.dumps(scan_data, indent=2, default=str)

    def generate_csv_report(self, scan_data: Dict[str, Any]) -> str:
        """Flattens primary scan findings into a concise CSV record."""
        flat_record = {
            "Scan ID": scan_data.get("scan_id") or scan_data.get("id", "UNSAVED"),
            "Timestamp": scan_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "Input Source": scan_data.get("input_source", "MANUAL_URL"),
            "URL": scan_data.get("submitted_url") or scan_data.get("url", ""),
            "Classification": scan_data.get("classification", ""),
            "Risk Score": scan_data.get("risk_score", 0.0),
            "Ensemble Phishing Probability (%)": round(scan_data.get("ensemble", {}).get("phishing_probability", 0.0) * 100, 2),
            "Model Agreement": "Disagreement" if scan_data.get("ensemble", {}).get("has_disagreement") else "Unanimous",
            "Random Forest": scan_data.get("individual_predictions", {}).get("Random Forest", {}).get("label", ""),
            "Decision Tree": scan_data.get("individual_predictions", {}).get("Decision Tree", {}).get("label", ""),
            "Logistic Regression": scan_data.get("individual_predictions", {}).get("Logistic Regression", {}).get("label", ""),
        }
        df = pd.DataFrame([flat_record])
        return df.to_csv(index=False)
