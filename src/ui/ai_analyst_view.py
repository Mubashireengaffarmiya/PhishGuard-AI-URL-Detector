"""
AI Security Analyst Console View for PhishGuard AI.
Conversational and prompt-driven explainability assistant.
Provides grounded cybersecurity analysis strictly tied to actual ML model predictions,
with a complete offline rule-based expert system fallback.
"""

from typing import Dict, Any, Optional
import streamlit as st

from src.services.ai_service import AISecurityAnalystService


def render_ai_analyst_view(ai_service: AISecurityAnalystService):
    """Renders the AI Security Analyst interactive console."""
    st.markdown("### 🤖 PhishGuard AI Security Analyst")
    st.caption("AI-assisted cybersecurity explanation assistant. All responses are grounded strictly in actual model predictions and extracted URL features.")

    # Provider Status Pill
    c_status, c_priv = st.columns([7, 3])
    with c_status:
        st.markdown(
            f"**Active AI Engine:** <span class='pg-badge pg-badge-ready'>&bull; {ai_service.provider}</span>",
            unsafe_allow_html=True
        )
    with c_priv:
        privacy_mode = st.selectbox(
            "Privacy Redaction Level",
            options=["MASK_PATH", "MASK_QUERY", "MASK_ALL", "SHOW_ALL"],
            index=0,
            help="Masks sensitive paths or query strings before sending context to external providers."
        )

    st.markdown("---")

    active_scan = st.session_state.get("active_scan")

    if active_scan:
        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem;">
                <span style="font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;">Actively Inspected URL Context:</span>
                <span style="font-family: 'JetBrains Mono'; font-size: 0.95rem; color: #f8fafc; margin-left: 0.5rem;">{active_scan['submitted_url']}</span>
                <span class="pg-badge {'pg-badge-ready' if active_scan['classification'] == 'SAFE' else 'pg-badge-error'}" style="margin-left: 0.5rem;">{active_scan['classification']}</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.info("💡 No URL is currently loaded in active session. You can ask general cybersecurity questions or scan a URL in the URL Scanner first.")

    # Pre-built Recommended Prompts
    st.markdown("#### ⚡ Recommended Inquiries")
    col1, col2, col3 = st.columns(3)

    preset_query = None
    if col1.button("🔍 Why was this URL flagged?", use_container_width=True):
        preset_query = "Why was this URL flagged and what features contributed most?"
    if col2.button("🎓 Explain for Faculty Viva", use_container_width=True):
        preset_query = "Explain this prediction and the ensemble architecture for a faculty presentation."
    if col3.button("⚖️ Why did models agree / disagree?", use_container_width=True):
        preset_query = "Explain the multi-model consensus and why individual models agree or disagree."

    col4, col5, col6 = st.columns(3)
    if col4.button("🚨 What should I do next?", use_container_width=True):
        preset_query = "What defensive actions should I take after receiving this link?"
    if col5.button("🔬 What are the technical limitations?", use_container_width=True):
        preset_query = "What are the technical limitations of URL-only machine learning detection?"
    if col6.button("🌲 Explain Ensemble Learning", use_container_width=True):
        preset_query = "Explain how Random Forest, Decision Tree, and Logistic Regression are weighted in this project."

    # Custom Query Input
    st.markdown("#### 💬 Custom Question")
    user_query = st.text_input(
        "Ask the AI Security Analyst a question about this URL or cyber defense:",
        placeholder="e.g., Explain the difference between heuristic indicators and machine-learning attribution.",
        label_visibility="collapsed"
    )

    query_to_run = preset_query or user_query

    if query_to_run:
        with st.spinner("Synthesizing grounded security rationale..."):
            ans = ai_service.answer_query(
                query=query_to_run,
                scan_result=active_scan,
                privacy_mode=privacy_mode
            )

        st.markdown("---")
        st.markdown(ans["response"])
        st.caption(f"Generated via: {ans.get('provider', ai_service.provider)}")
