"""
Faculty Demo Mode View for PhishGuard AI.
Provides pre-vetted, presentation-ready demonstration scenarios with
one-click evaluation triggers for viva defenses and evaluator walkthroughs.
All cases are explicitly labeled: 'DEMO / SAMPLE DATA'.
"""

from typing import Dict, Any, List, Optional
import streamlit as st

from src.services.demo_service import DemoService
from src.services.prediction_service import PredictionService
from src.services.explanation_service import ExplanationService
from src.services.report_service import ReportService
from src.services.telemetry_service import get_telemetry_service
from src.ui.scanner_view import _display_scan_result


def render_demo_view(
    prediction_service: PredictionService,
    explanation_service: ExplanationService,
    report_service: ReportService,
    telemetry_service: Optional[Any] = None,
    **kwargs
):
    """Renders the Faculty Demo Mode interface."""
    st.markdown("### 🎓 Faculty & Hackathon Demonstration Console")
    st.caption("One-click curated demonstration cases illustrating multi-model consensus, divergence detection, and heuristic penalty triggers.")

    st.markdown(
        """
        <div style="background: rgba(129, 140, 248, 0.1); border: 1px solid rgba(129, 140, 248, 0.3); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1.25rem;">
            <strong style="color: #a78bfa;">DEMO / SAMPLE DATA NOTICE:</strong>
            <span style="font-size: 0.85rem; color: #cbd5e1;">
                All scenarios below are curated synthetic or real-world historical patterns intended strictly for academic demonstration and faculty evaluation.
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    demo_cases = DemoService.get_all_demos()

    for idx, case in enumerate(demo_cases):
        with st.container():
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span class="pg-badge pg-badge-ready" style="font-size: 0.7rem;">{case['category']}</span>
                            <h4 style="margin: 0.35rem 0 0.25rem 0; color: #f8fafc; font-size: 1.05rem;">{case['title']}</h4>
                            <div style="font-family: 'JetBrains Mono'; font-size: 0.85rem; color: #38bdf8; margin-bottom: 0.5rem;">{case['url']}</div>
                            <p style="font-size: 0.85rem; color: #94a3b8; margin: 0 0 0.5rem 0; line-height: 1.4;">{case['description']}</p>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Expandable Talking Points for Evaluator
            with st.expander("🎓 Talking Points for Faculty / Judges"):
                for tp in case["talking_points"]:
                    st.markdown(f"&bull; {tp}")

            # One-click Load Demo Button
            btn_key = f"btn_demo_run_{case['id']}"
            if st.button(f"🚀 Load & Evaluate: {case['title']}", key=btn_key, type="primary"):
                with st.spinner(f"Evaluating {case['url']}..."):
                    res = prediction_service.analyze_url(
                        raw_url=case["url"],
                        input_source="DEMO",
                        persist=True
                    )
                    tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                    tele.record_demo_scan()
                    tele.record_url_scan(res)

                    st.session_state["demo_active_scan"] = res

            st.markdown("<hr style='margin: 0.5rem 0 1rem 0; opacity: 0.1;'>", unsafe_allow_html=True)

    # Render results for evaluated demo case
    if "demo_active_scan" in st.session_state and st.session_state["demo_active_scan"]:
        st.markdown("### 📋 Demo Evaluation Results")
        _display_scan_result(st.session_state["demo_active_scan"], explanation_service, report_service)
