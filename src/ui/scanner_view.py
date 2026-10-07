"""
URL Scanner View for PhishGuard AI.
Primary real-time URL risk analysis interface with normalization indicators,
visual pipeline animation, large risk gauge, model consensus cards,
grounded explainability table, and one-click PDF report export.
"""

from typing import Dict, Any, Optional
import streamlit as st
import time

from src.services.prediction_service import PredictionService
from src.services.explanation_service import ExplanationService
from src.services.report_service import ReportService
from src.ui.components import (
    render_scan_pipeline_stepper,
    render_risk_gauge,
    render_model_breakdown_cards,
    render_defensive_recommendations
)


def render_scanner_view(
    prediction_service: PredictionService,
    explanation_service: ExplanationService,
    report_service: ReportService,
    prefill_url: str = "",
    telemetry_service: Optional[Any] = None,
    **kwargs
):
    """Renders the main URL scanning console."""
    st.markdown("### 🔍 URL Security Scanner")
    st.caption("Inspect structural and lexical phishing indicators across multi-model ensembles. PhishGuard never navigates to target servers.")

    # Input Form
    with st.container():
        input_col, btn_col = st.columns([8, 2])
        url_input = input_col.text_input(
            "Target Website URL",
            value=prefill_url,
            placeholder="e.g. https://secure-portal.example.com/login or naked domain 'example.com'",
            help="Full URLs, naked domains, and port-specified addresses are supported. URLs are never visited.",
            label_visibility="collapsed"
        )
        scan_clicked = btn_col.button("🛡️ Scan URL", type="primary", use_container_width=True)

    # Passive Threat Intelligence Checkbox
    include_threat_intel = st.checkbox(
        "Enable Supplementary Threat Intelligence (DNS, SSL, WHOIS passive checks)",
        value=False,
        help="Connects passively to TLS/DNS/WHOIS ports to gather infrastructure metadata. May increase scan latency."
    )

    # Process scan if button clicked or URL was pre-filled and not yet analyzed in this session
    if scan_clicked or (prefill_url and "last_analyzed_url" in st.session_state and st.session_state["last_analyzed_url"] != prefill_url):
        cleaned_url = url_input.strip()
        if not cleaned_url:
            st.warning("⚠️ Please provide a URL or domain to evaluate.")
            return

        render_scan_pipeline_stepper()

        try:
            with st.spinner("Analyzing lexical structures and running model ensemble..."):
                result = prediction_service.analyze_url(
                    raw_url=cleaned_url,
                    input_source="MANUAL_URL",
                    include_threat_intel=include_threat_intel,
                    persist=True
                )
                from src.services.telemetry_service import get_telemetry_service
                tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                tele.record_url_scan(result)

                st.session_state["active_scan"] = result
                st.session_state["last_analyzed_url"] = cleaned_url

        except ValueError as val_err:
            st.error(f"❌ Input Validation Error: {val_err}")
            return
        except Exception as err:
            st.error(f"❌ An error occurred during analysis: {err}")
            with st.expander("Technical Exception Details"):
                st.exception(err)
            return

    # Render Active Scan Results if present
    if "active_scan" in st.session_state and st.session_state["active_scan"]:
        res = st.session_state["active_scan"]
        _display_scan_result(res, explanation_service, report_service)


def _display_scan_result(res: Dict[str, Any], explanation_service: ExplanationService, report_service: ReportService):
    """Renders the comprehensive security findings for an evaluated URL."""
    classification = res["classification"]
    risk_score = res["risk_score"]
    phish_prob = res["ensemble"]["phishing_probability"]
    safe_prob = res["ensemble"]["safe_probability"]
    has_disagreement = res["ensemble"]["has_disagreement"]

    # 1. URL Normalization Banner
    st.markdown("---")
    c_meta1, c_meta2 = st.columns([7, 3])
    with c_meta1:
        st.markdown(f"**Submitted URL:** `{res['submitted_url']}`")
        st.markdown(f"**Normalized URL:** `{res['normalized_url']}`")
    with c_meta2:
        if res.get("scheme_was_added"):
            st.info("ℹ️ Scheme 'https://' was added automatically.")
        st.caption(f"Scan ID: #{res.get('scan_id', 'Session')} &bull; Source: {res.get('input_source', 'MANUAL')}")

    # 2. Top Result Card & Risk Gauge
    col_card, col_gauge = st.columns([6, 4])

    with col_card:
        card_class = "pg-result-safe" if classification == "SAFE" else ("pg-result-suspicious" if classification == "SUSPICIOUS" else "pg-result-phishing")
        icon = "✅" if classification == "SAFE" else ("⚠️" if classification == "SUSPICIOUS" else "🚨")

        st.markdown(
            f"""
            <div class="{card_class}">
                <div style="font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; color: #cbd5e1;">Final Security Assessment</div>
                <h2 style="margin: 0.25rem 0 0.5rem 0; font-size: 2rem; color: #f8fafc; font-weight: 800;">
                    {icon} {classification}
                </h2>
                <p style="font-size: 0.9rem; color: #cbd5e1; line-height: 1.4; margin-bottom: 1rem;">
                    {res['explanation']['summary']}
                </p>
                <div style="display: flex; gap: 1rem; font-family: 'JetBrains Mono'; font-size: 0.95rem;">
                    <div>
                        <span style="color: #94a3b8; font-size: 0.72rem; display: block;">MODEL PHISHING PROB</span>
                        <strong style="color: #f87171;">{phish_prob * 100:.2f}%</strong>
                    </div>
                    <div>
                        <span style="color: #94a3b8; font-size: 0.72rem; display: block;">SAFE PROBABILITY</span>
                        <strong style="color: #34d399;">{safe_prob * 100:.2f}%</strong>
                    </div>
                    <div>
                        <span style="color: #94a3b8; font-size: 0.72rem; display: block;">COMPOSITE RISK</span>
                        <strong style="color: #38bdf8;">{risk_score}/100</strong>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_gauge:
        gauge_fig = render_risk_gauge(phishing_prob=phish_prob, risk_score=risk_score)
        st.plotly_chart(gauge_fig, use_container_width=True)

    # 3. Model Disagreement Notice (if any)
    if has_disagreement:
        st.warning(
            f"⚖️ **Model Divergence Detected**: {res['ensemble']['disagreement_summary']}"
        )

    # 4. Multi-Model Breakdown Cards
    st.markdown("#### 🤖 Machine-Learning Ensemble Consensus")
    render_model_breakdown_cards(res["individual_predictions"])

    # 5. Grounded Explainability Section
    st.markdown("#### 🔬 Explainable AI Analysis")
    if classification == "SAFE":
        safe_exp = explanation_service.get_safe_url_explanation(res["features"], res["individual_predictions"])
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.06); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
                <h4 style="color: #34d399; margin: 0 0 0.5rem 0;">Why does PhishGuard AI consider this URL lower risk?</h4>
                <ul style="margin: 0; padding-left: 1.25rem; font-size: 0.85rem; color: #cbd5e1;">
            """
            + "".join([f"<li><strong>{f['factor']}:</strong> {f['evidence']}</li>" for f in safe_exp["trust_factors"]])
            + f"""
                </ul>
                <p style="margin-top: 0.75rem; font-size: 0.75rem; color: #94a3b8; font-style: italic;">
                    {safe_exp['disclaimer']}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Indicators Table
    indicators = explanation_service.get_indicator_breakdown(res["features"], res["submitted_url"])
    with st.expander("🔎 Detailed Technical Indicator Breakdown", expanded=(classification != "SAFE")):
        st.caption("Each indicator displays observed feature values, security rationale, and technical limitations.")
        for ind in indicators:
            c1, c2, c3, c4 = st.columns([3, 2, 4, 3])
            c1.markdown(f"**{ind['indicator']}**")
            c2.markdown(f"`{ind['observed_value']}`")
            c3.markdown(f"<span style='font-size:0.82rem; color:#cbd5e1;'>{ind['why_it_matters']}</span>", unsafe_allow_html=True)
            c4.caption(f"⚠️ Limitation: {ind['limitation']}")
            st.markdown("<hr style='margin: 0.35rem 0; opacity: 0.1;'>", unsafe_allow_html=True)

    # 6. Defensive Recommendations
    render_defensive_recommendations(classification)

    # 7. Action Controls: Report & AI Assistant Quick Links
    st.markdown("#### ⚡ Quick Actions")
    qa_col1, qa_col2, qa_col3 = st.columns(3)

    with qa_col1:
        if st.button("📄 Generate Audit PDF Report", key="btn_pdf_scan", use_container_width=True):
            with st.spinner("Compiling formal PDF security report..."):
                pdf_path = report_service.generate_pdf_report(res)
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Download PDF Audit Report",
                        data=f.read(),
                        file_name=pdf_path.name,
                        mime="application/pdf",
                        key="dl_pdf_ready",
                        use_container_width=True
                    )

    with qa_col2:
        if st.button("💬 Consult AI Security Analyst", key="btn_ask_ai", use_container_width=True):
            st.session_state["nav_selection"] = "AI Security Analyst"
            st.rerun()

    with qa_col3:
        json_str = report_service.generate_json_report(res)
        st.download_button(
            label="💾 Export JSON Telemetry",
            data=json_str,
            file_name=f"scan_{res.get('scan_id', 'export')}.json",
            mime="application/json",
            key="dl_json_quick",
            use_container_width=True
        )

    # 8. Feature Explorer Expander
    with st.expander("📊 View All 42 Extracted Features (Categorized)"):
        f_tabs = st.tabs(["URL Structure", "Character Analysis", "Domain Attributes", "Security Indicators", "Raw JSON"])
        features = res["features"]

        for tab, (cat_name, cat_feats) in zip(f_tabs[:4], explanation_service.FEATURE_TAXONOMY.items()):
            with tab:
                cols = st.columns(2)
                for i, (f_key, f_label, f_desc, f_context) in enumerate(cat_feats):
                    c = cols[i % 2]
                    c.markdown(
                        f"""
                        <div style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 6px; padding: 0.5rem 0.75rem; margin-bottom: 0.5rem;">
                            <div style="display: flex; justify-content: space-between;">
                                <span style="font-weight: 600; font-size: 0.85rem; color: #f8fafc;">{f_label}</span>
                                <code style="color: #38bdf8;">{features.get(f_key, 'N/A')}</code>
                            </div>
                            <div style="font-size: 0.72rem; color: #94a3b8; margin-top: 0.2rem;">{f_context}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

        with f_tabs[4]:
            st.json(features)
