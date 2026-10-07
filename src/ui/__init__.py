"""
UI Package for PhishGuard AI.
Modular views and design components for the Streamlit SOC application.
"""

from src.ui.theme import get_theme_css
from src.ui.components import (
    render_header,
    render_footer,
    render_status_badge,
    render_scan_pipeline_stepper,
    render_risk_gauge,
    render_model_breakdown_cards,
    render_defensive_recommendations
)
from src.ui.dashboard_view import render_dashboard_view
from src.ui.scanner_view import render_scanner_view
from src.ui.image_scanner_view import render_image_scanner_view
from src.ui.qr_scanner_view import render_qr_scanner_view
from src.ui.explainability_view import render_explainability_view
from src.ui.analytics_view import render_analytics_view
from src.ui.threat_intel_view import render_threat_intel_view
from src.ui.ai_analyst_view import render_ai_analyst_view
from src.ui.history_view import render_history_view
from src.ui.reports_view import render_reports_view
from src.ui.how_it_works_view import render_how_it_works_view
from src.ui.architecture_view import render_architecture_view
from src.ui.demo_view import render_demo_view
from src.ui.health_view import render_health_view
from src.ui.settings_view import render_settings_view

__all__ = [
    "get_theme_css",
    "render_header",
    "render_footer",
    "render_status_badge",
    "render_scan_pipeline_stepper",
    "render_risk_gauge",
    "render_model_breakdown_cards",
    "render_defensive_recommendations",
    "render_dashboard_view",
    "render_scanner_view",
    "render_image_scanner_view",
    "render_qr_scanner_view",
    "render_explainability_view",
    "render_analytics_view",
    "render_threat_intel_view",
    "render_ai_analyst_view",
    "render_history_view",
    "render_reports_view",
    "render_how_it_works_view",
    "render_architecture_view",
    "render_demo_view",
    "render_health_view",
    "render_settings_view",
]
