"""
PHISHGUARD AI — Explainable Machine-Learning Phishing URL Detection Platform
Enterprise & Academic Security Operations Center (SOC) Console.
"""

import streamlit as st
from pathlib import Path

# Core Services
from src.services.prediction_service import PredictionService, get_predictor, get_database
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

# UI Views & Theme
from src.ui.theme import get_theme_css
from src.ui.components import render_header, render_footer
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

# Configure Streamlit Application Window
st.set_page_config(
    page_title="PhishGuard AI — Cybersecurity SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Service Caching
@st.cache_resource(show_spinner="Initializing ML Ensemble & Platform Subsystems...")
def init_platform_services():
    """Initializes and caches singleton prediction engine and platform services."""
    predictor = get_predictor()
    db = get_database()
    pred_service = PredictionService(predictor=predictor, db=db)
    exp_service = ExplanationService()
    ai_service = AISecurityAnalystService()
    threat_service = ThreatIntelService()
    hist_service = HistoryService(db=db)
    rep_service = ReportService()
    ocr_service = OCRService()
    qr_service = QRService()
    img_service = ImageScanService(ocr_service=ocr_service, qr_scanner=qr_service.scanner)
    tele_service = get_telemetry_service()
    tele_service.sync_with_database(db)
    return {
        "prediction_service": pred_service,
        "explanation_service": exp_service,
        "ai_service": ai_service,
        "threat_service": threat_service,
        "history_service": hist_service,
        "report_service": rep_service,
        "qr_service": qr_service,
        "ocr_service": ocr_service,
        "image_service": img_service,
        "telemetry_service": tele_service
    }


def main():
    # Initialize Services
    services = init_platform_services()

    # Session State Initialization
    if "session_stats" not in st.session_state:
        st.session_state["session_stats"] = {
            "total_scans": 0,
            "safe_count": 0,
            "phishing_count": 0,
            "warning_count": 0,
            "disagreement_count": 0,
            "avg_phishing_prob": 0.0,
            "image_scans": 0,
            "qr_scans": 0,
            "demo_scans": 0
        }

    # Ensure session telemetry is synchronized with persistent database
    services["telemetry_service"].sync_with_database(
        services["history_service"].db,
        st.session_state["session_stats"]
    )

    if "theme" not in st.session_state:
        st.session_state["theme"] = "Cyber Dark"

    if "animations_enabled" not in st.session_state:
        st.session_state["animations_enabled"] = True

    if "privacy_mode" not in st.session_state:
        st.session_state["privacy_mode"] = "SHOW_ALL"

    if "active_scan" not in st.session_state:
        st.session_state["active_scan"] = None

    if "nav_selection" not in st.session_state:
        st.session_state["nav_selection"] = "Dashboard"

    # Inject Custom Theme CSS
    theme_css = get_theme_css(
        theme=st.session_state["theme"],
        animations_enabled=st.session_state["animations_enabled"]
    )
    st.markdown(theme_css, unsafe_allow_html=True)

    # Sidebar Navigation Console
    with st.sidebar:
        st.markdown(
            """
            <div style="text-align: center; padding: 0.75rem 0.5rem 1.25rem 0.5rem; background: linear-gradient(180deg, rgba(17, 27, 49, 0.7) 0%, rgba(10, 16, 32, 0) 100%); border-radius: 12px; margin-bottom: 0.5rem; border: 1px solid rgba(56, 189, 248, 0.12); box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.1);">
                <div style="font-size: 2.35rem; filter: drop-shadow(0 0 14px rgba(0, 240, 255, 0.5)); margin-bottom: 0.2rem;">🛡️</div>
                <div style="font-weight: 800; font-size: 1.3rem; letter-spacing: -0.03em; color: #f8fafc; text-shadow: 0 0 20px rgba(56, 189, 248, 0.3);">
                    PHISHGUARD AI
                </div>
                <div style="font-size: 0.7rem; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.09em; font-weight: 700; margin-top: 0.15rem;">
                    Threat Intelligence Console
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        nav_options = [
            ("Dashboard", "📊 Dashboard"),
            ("URL Scanner", "🔍 URL Scanner"),
            ("Image Scanner", "🖼️ Image Scanner (OCR)"),
            ("QR Scanner", "📱 QR Code Scanner"),
            ("Explainable AI", "🔬 Explainable AI (XAI)"),
            ("Model Analytics", "📈 Model Analytics"),
            ("Threat Intelligence", "🌐 Threat Intelligence"),
            ("AI Security Analyst", "🤖 AI Security Analyst"),
            ("Scan History", "📜 Scan History"),
            ("Reports", "📑 Reports & Export"),
            ("How PhishGuard Works", "📚 How PhishGuard Works"),
            ("Project Architecture", "🏛️ Project Architecture"),
            ("Demo Mode", "🎓 Faculty Demo Mode"),
            ("System Health", "🏥 System Health"),
            ("Settings", "⚙️ Settings & Privacy"),
        ]

        # Determine current selection index
        current_nav = st.session_state["nav_selection"]
        nav_keys = [opt[0] for opt in nav_options]
        default_idx = nav_keys.index(current_nav) if current_nav in nav_keys else 0

        selected_page = st.radio(
            "Navigation Menu",
            options=nav_keys,
            format_func=lambda k: dict(nav_options).get(k, k),
            index=default_idx,
            label_visibility="collapsed"
        )
        st.session_state["nav_selection"] = selected_page

        st.markdown("<div style='margin-top: 0.75rem;'></div>", unsafe_allow_html=True)

        # Sidebar Live Status Pill - 3D Glass Panel
        st.markdown(
            """
            <div style="padding: 0.65rem 0.85rem; background: linear-gradient(135deg, rgba(17, 27, 49, 0.8) 0%, rgba(10, 16, 32, 0.85) 100%); border: 1px solid rgba(56, 189, 248, 0.22); border-top: 1px solid rgba(255, 255, 255, 0.12); border-radius: 10px; box-shadow: 0 6px 18px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.08);">
                <div style="font-size: 0.68rem; color: #94a3b8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">Engine Subsystem</div>
                <div style="display: flex; align-items: center; gap: 0.45rem; margin-top: 0.3rem;">
                    <span style="height: 9px; width: 9px; background-color: #10b981; border-radius: 50%; display: inline-block; box-shadow: 0 0 8px #10b981;"></span>
                    <span style="font-size: 0.8rem; font-weight: 700; color: #f8fafc;">3/3 ML Models Active</span>
                </div>
                <div style="font-size: 0.7rem; color: #64748b; margin-top: 0.25rem;">Ensemble: RF (50%), DT (25%), LR (25%)</div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.caption("PhishGuard AI v2.4.0 &bull; Academic Viva &amp; Enterprise SOC")

    # Render Main Page Header
    render_header(current_page=selected_page)

    # Route to Selected View
    if selected_page == "Dashboard":
        render_dashboard_view(
            session_stats=st.session_state["session_stats"],
            history_service=services["history_service"]
        )

    elif selected_page == "URL Scanner":
        render_scanner_view(
            prediction_service=services["prediction_service"],
            explanation_service=services["explanation_service"],
            report_service=services["report_service"],
            prefill_url=""
        )

    elif selected_page == "Image Scanner":
        render_image_scanner_view(
            image_service=services["image_service"],
            prediction_service=services["prediction_service"],
            explanation_service=services["explanation_service"],
            report_service=services["report_service"]
        )

    elif selected_page == "QR Scanner":
        render_qr_scanner_view(
            qr_service=services["qr_service"],
            prediction_service=services["prediction_service"],
            explanation_service=services["explanation_service"],
            report_service=services["report_service"]
        )

    elif selected_page == "Explainable AI":
        render_explainability_view(
            explanation_service=services["explanation_service"]
        )

    elif selected_page == "Model Analytics":
        render_analytics_view()

    elif selected_page == "Threat Intelligence":
        render_threat_intel_view(
            threat_intel_service=services["threat_service"]
        )

    elif selected_page == "AI Security Analyst":
        render_ai_analyst_view(
            ai_service=services["ai_service"]
        )

    elif selected_page == "Scan History":
        render_history_view(
            history_service=services["history_service"],
            report_service=services["report_service"]
        )

    elif selected_page == "Reports":
        render_reports_view(
            report_service=services["report_service"],
            history_service=services["history_service"]
        )

    elif selected_page == "How PhishGuard Works":
        render_how_it_works_view()

    elif selected_page == "Project Architecture":
        render_architecture_view()

    elif selected_page == "Demo Mode":
        render_demo_view(
            prediction_service=services["prediction_service"],
            explanation_service=services["explanation_service"],
            report_service=services["report_service"]
        )

    elif selected_page == "System Health":
        render_health_view()

    elif selected_page == "Settings":
        render_settings_view()

    # Render Main Page Footer
    render_footer()


if __name__ == "__main__":
    main()
