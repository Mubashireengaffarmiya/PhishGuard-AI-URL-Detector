"""
Reusable UI Components for PhishGuard AI.
Headers, footers, status pills, model prediction cards, Plotly risk gauges,
pipeline animation steppers, and defensive security advice panels.
Elevated with glossy 3D glassmorphic styling and crisp SOC visual hierarchy.
"""

from typing import Dict, Any, Optional
import streamlit as st
import plotly.graph_objects as go


def render_header(current_page: str = "Dashboard"):
    """Renders the top branding banner with glossy 3D depth and live status indicators."""
    st.markdown(
        f"""
        <div class="pg-brand-banner">
            <div>
                <h1 class="pg-brand-title">
                    <span style="font-size: 1.85rem; filter: drop-shadow(0 0 10px rgba(0, 240, 255, 0.45));">🛡️</span>
                    PHISHGUARD AI
                </h1>
                <p class="pg-brand-tagline">
                    AI-Powered Phishing Detection & Explainable URL Security &bull; Security Operations Center Console
                </p>
            </div>
            <div style="display: flex; align-items: center; gap: 0.65rem;">
                <span class="pg-badge pg-badge-ready">&bull; v2.4.0 SOC Edition</span>
                <span class="pg-badge pg-badge-ready">&bull; ENGINES ACTIVE</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_footer():
    """Renders the standard security disclaimer and responsible use notice."""
    st.markdown("---")
    st.markdown(
        """
        <div style="text-align: center; color: #64748b; font-size: 0.78rem; padding: 1.25rem 0 1.75rem 0;">
            <p style="margin-bottom: 0.35rem;">
                <strong style="color: #94a3b8;">PhishGuard AI</strong> &bull; Explainable Machine-Learning Phishing URL Detection &amp; Threat Intelligence Platform
            </p>
            <p style="margin: 0; max-width: 820px; margin: 0 auto; line-height: 1.45;">
                <em>Responsible Use Notice:</em> PhishGuard AI provides automated machine-learning security assessments based on structural and lexical indicators.
                A <strong>SAFE</strong> classification does not guarantee that a website is trustworthy or free from server-side compromise.
                Results represent guidance rather than absolute verification. Never enter sensitive passwords or credentials without independent verification.
            </p>
            <p style="margin-top: 0.5rem; color: #475569; font-size: 0.72rem;">
                &copy; 2026 PhishGuard AI Security Platform &bull; Academic Viva &amp; Enterprise SOC Edition
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_status_badge(status: str) -> str:
    """Returns HTML for a colored status pill."""
    status_upper = status.upper()
    if status_upper in ("READY", "OPERATIONAL", "AVAILABLE", "SAFE"):
        return f'<span class="pg-badge pg-badge-ready">&bull; {status}</span>'
    elif status_upper in ("WARNING", "SUSPICIOUS", "DEGRADED"):
        return f'<span class="pg-badge pg-badge-warning">&bull; {status}</span>'
    elif status_upper in ("ERROR", "PHISHING", "CRITICAL"):
        return f'<span class="pg-badge pg-badge-error">&bull; {status}</span>'
    else:
        return f'<span class="pg-badge pg-badge-not-config">&bull; {status}</span>'


def render_scan_pipeline_stepper():
    """Renders the visual pipeline stages animation representation."""
    stages = [
        "URL RECEIVED", "VALIDATING", "NORMALIZING", "FEATURE EXTRACTION",
        "LOGISTIC REGRESSION", "DECISION TREE", "RANDOM FOREST",
        "ENSEMBLE CALCULATION", "MODEL AGREEMENT", "EXPLANATION", "SCAN COMPLETE"
    ]
    html_parts = []
    for i, s in enumerate(stages):
        html_parts.append(f'<span class="pg-pipeline-step">{s}</span>')
        if i < len(stages) - 1:
            html_parts.append('<span class="pg-pipeline-arrow">&rarr;</span>')

    st.markdown(
        f'<div class="pg-pipeline-container">{" ".join(html_parts)}</div>',
        unsafe_allow_html=True
    )


def render_risk_gauge(phishing_prob: float, risk_score: float, height: int = 250) -> go.Figure:
    """
    Renders a large, professional Plotly gauge labeled 'MODEL PHISHING PROBABILITY'.
    Clearly distinguished from calibrated real-world probabilities.
    """
    pct = round(phishing_prob * 100, 2)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=pct,
        number={'suffix': "%", 'font': {'size': 38, 'color': "#00f0ff", 'family': "JetBrains Mono"}},
        title={'text': "<b>MODEL PHISHING PROBABILITY</b><br><span style='font-size:0.75em;color:#94a3b8;'>Composite Risk Score: " + f"{risk_score}/100" + "</span>", 'font': {'size': 14, 'color': '#cbd5e1'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569", 'ticksuffix': "%"},
            'bar': {'color': "#38bdf8", 'thickness': 0.28},
            'bgcolor': "rgba(11, 18, 35, 0.75)",
            'borderwidth': 1,
            'bordercolor': "rgba(56, 189, 248, 0.3)",
            'steps': [
                {'range': [0, 30], 'color': "rgba(16, 185, 129, 0.22)"},
                {'range': [30, 70], 'color': "rgba(245, 158, 11, 0.22)"},
                {'range': [70, 100], 'color': "rgba(244, 63, 94, 0.28)"}
            ],
            'threshold': {
                'line': {'color': "#f43f5e" if pct >= 70 else ("#f59e0b" if pct >= 30 else "#10b981"), 'width': 3},
                'thickness': 0.85,
                'value': pct
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': "#f8fafc", 'family': "Inter"},
        height=height,
        margin=dict(l=25, r=25, t=45, b=15)
    )
    return fig


def render_model_breakdown_cards(individual_predictions: Dict[str, Any]):
    """Renders 3 side-by-side glossy 3D metric cards for LR, DT, and RF."""
    cols = st.columns(3)
    models_info = [
        ("Random Forest", "50% Weight (Primary Ensemble)", "🌲", "#38bdf8"),
        ("Decision Tree", "25% Weight (CART Split)", "🌿", "#34d399"),
        ("Logistic Regression", "25% Weight (Scaled Linear)", "📐", "#818cf8"),
    ]

    for col, (model_name, subtitle, icon, accent_col) in zip(cols, models_info):
        details = individual_predictions.get(model_name, {})
        label = details.get("label", "UNKNOWN")
        prob = details.get("phishing_probability", 0.0) * 100
        safe_prob = details.get("safe_probability", 0.0) * 100

        badge_class = "pg-badge-ready" if label == "SAFE" else "pg-badge-error"

        with col:
            st.markdown(
                f"""
                <div class="pg-card" style="text-align: center; border-top: 2px solid {accent_col};">
                    <div style="font-size: 1.6rem; margin-bottom: 0.25rem; filter: drop-shadow(0 2px 6px rgba(0,0,0,0.4));">{icon}</div>
                    <div style="font-weight: 700; font-size: 1.05rem; color: #f8fafc;">{model_name}</div>
                    <div style="font-size: 0.72rem; color: #94a3b8; margin-bottom: 0.75rem;">{subtitle}</div>
                    <div style="margin-bottom: 0.65rem;">
                        <span class="pg-badge {badge_class}">{label}</span>
                    </div>
                    <div style="display: flex; justify-content: space-around; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; margin-top: 0.5rem; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 0.65rem;">
                        <div>
                            <div style="font-size: 0.68rem; color: #64748b; font-weight: 600;">PHISHING</div>
                            <div style="font-weight: 700; color: #fb7185; font-size: 0.92rem;">{prob:.1f}%</div>
                        </div>
                        <div>
                            <div style="font-size: 0.68rem; color: #64748b; font-weight: 600;">SAFE</div>
                            <div style="font-weight: 700; color: #34d399; font-size: 0.92rem;">{safe_prob:.1f}%</div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )


def render_defensive_recommendations(classification: str):
    """Renders specific defensive guidance in glossy styled callout panels."""
    if classification == "PHISHING":
        st.markdown(
            """
            <div style="background: linear-gradient(135deg, rgba(244, 63, 94, 0.12) 0%, rgba(17, 24, 39, 0.8) 100%); border: 1.5px solid rgba(244, 63, 94, 0.35); border-radius: 12px; padding: 1.25rem; margin: 1.25rem 0; box-shadow: 0 8px 24px -4px rgba(244, 63, 94, 0.15);">
                <h4 style="color: #fb7185; margin: 0 0 0.65rem 0; font-size: 1rem; display: flex; align-items: center; gap: 0.4rem;">
                    🚨 Immediate Defensive Recommendations
                </h4>
                <ul style="margin: 0; padding-left: 1.35rem; font-size: 0.88rem; color: #e2e8f0; line-height: 1.6;">
                    <li><strong>Do NOT interact:</strong> Avoid clicking links, submitting forms, or downloading attachments from this sender.</li>
                    <li><strong>Zero Credentials:</strong> Do not enter passwords, credit card numbers, or MFA tokens.</li>
                    <li><strong>Verify via Official Channels:</strong> Navigate directly to the known official domain using a trusted bookmark or mobile app.</li>
                    <li><strong>Report Malicious Link:</strong> Forward the message to your organization's IT security team or clearinghouses (e.g. CISA, APWG).</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            """
            <div style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(17, 24, 39, 0.8) 100%); border: 1.5px solid rgba(16, 185, 129, 0.35); border-radius: 12px; padding: 1.25rem; margin: 1.25rem 0; box-shadow: 0 8px 24px -4px rgba(16, 185, 129, 0.15);">
                <h4 style="color: #34d399; margin: 0 0 0.65rem 0; font-size: 1rem; display: flex; align-items: center; gap: 0.4rem;">
                    🛡️ Safe Browsing Guidance
                </h4>
                <ul style="margin: 0; padding-left: 1.35rem; font-size: 0.88rem; color: #e2e8f0; line-height: 1.6;">
                    <li><strong>Standard Caution Applies:</strong> The URL structural indicators appear consistent with legitimate infrastructure.</li>
                    <li><strong>Confirm In-Context:</strong> If received unexpectedly via SMS or email, verify the sender's identity through trusted out-of-band channels.</li>
                    <li><strong>Always Check the Address Bar:</strong> Ensure the domain matches the expected institution before providing credentials.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )
