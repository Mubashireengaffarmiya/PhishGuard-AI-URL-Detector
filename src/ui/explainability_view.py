"""
Explainable AI (XAI) Console View for PhishGuard AI.
Transparent indicator breakdown, feature importance attribution,
model weight mechanics, and grounded technical rationales.
"""

from typing import Dict, Any, Optional
import streamlit as st
import plotly.express as px
import pandas as pd
import joblib

from src.services.explanation_service import ExplanationService
from src.config import EVALUATION_METRICS_PATH


def render_explainability_view(explanation_service: ExplanationService):
    """Renders the dedicated Explainable AI console."""
    st.markdown("### 🔬 Explainable AI (XAI) Security Console")
    st.caption("Deep technical inspection of URL feature indicators, tree split importance, and linear classifier coefficients.")

    # Check if there is an active scan in session
    active_scan = st.session_state.get("active_scan")

    if active_scan:
        url = active_scan["submitted_url"]
        classification = active_scan["classification"]
        features = active_scan["features"]

        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 1.25rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Actively Inspected URL</div>
                        <div style="font-family: 'JetBrains Mono'; font-weight: 600; color: #f8fafc; font-size: 1.05rem;">{url}</div>
                    </div>
                    <div>
                        <span class="pg-badge {'pg-badge-ready' if classification == 'SAFE' else 'pg-badge-error'}">{classification}</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 1. Feature Indicators Table
        st.markdown("#### 📑 Grounded Indicator Evaluation")
        indicators = explanation_service.get_indicator_breakdown(features, url)
        df_ind = pd.DataFrame(indicators)

        for _, row in df_ind.iterrows():
            c1, c2, c3, c4 = st.columns([3, 2, 4, 3])
            c1.markdown(f"**{row['indicator']}**")
            c2.markdown(f"`{row['observed_value']}`")
            c3.markdown(f"<span style='font-size:0.83rem; color:#cbd5e1;'>{row['why_it_matters']}</span>", unsafe_allow_html=True)
            c4.caption(f"⚠️ Limitation: {row['limitation']}")
            st.markdown("<hr style='margin: 0.35rem 0; opacity: 0.1;'>", unsafe_allow_html=True)

        st.markdown("---")

    else:
        st.info("💡 To view URL-specific indicators, run a scan in the **URL Scanner** first. Below is the global model feature importance across all trained models.")

    # 2. Global Model Feature Importance (Real saved metrics)
    st.markdown("#### 🌲 Machine-Learning Feature Importance & Attribution")
    st.caption("Extracted directly from trained model parameters: Gini feature importances for Random Forest and normalized L2 coefficients for Logistic Regression.")

    try:
        metrics_data = joblib.load(EVALUATION_METRICS_PATH)
        fa = metrics_data.get("feature_analysis", {})

        t1, t2, t3 = st.tabs(["Random Forest (Gini Importance)", "Decision Tree (Split Importance)", "Logistic Regression (Coefficients)"])

        with t1:
            rf_imp = fa.get("random_forest_importance", [])
            if rf_imp:
                df_rf = pd.DataFrame(rf_imp[:12])
                fig_rf = px.bar(
                    df_rf,
                    x="importance",
                    y="feature",
                    orientation="h",
                    title="Top 12 Most Informative Features in Random Forest Ensemble",
                    color="importance",
                    color_continuous_scale="Blues"
                )
                fig_rf.update_layout(
                    yaxis=dict(autorange="reversed"),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color="#cbd5e1"),
                    height=380
                )
                st.plotly_chart(fig_rf, use_container_width=True)

        with t2:
            dt_imp = fa.get("decision_tree_importance", [])
            if dt_imp:
                df_dt = pd.DataFrame(dt_imp[:12])
                fig_dt = px.bar(
                    df_dt,
                    x="importance",
                    y="feature",
                    orientation="h",
                    title="Top Decision Tree Partitioning Features",
                    color="importance",
                    color_continuous_scale="Teal"
                )
                fig_dt.update_layout(
                    yaxis=dict(autorange="reversed"),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color="#cbd5e1"),
                    height=380
                )
                st.plotly_chart(fig_dt, use_container_width=True)

        with t3:
            lr_coef = fa.get("logistic_regression_coefficients", [])
            if lr_coef:
                df_lr = pd.DataFrame(lr_coef[:15])
                fig_lr = px.bar(
                    df_lr,
                    x="coefficient",
                    y="feature",
                    orientation="h",
                    title="Logistic Regression Feature Weights (Sign indicates Phishing vs Safe direction)",
                    color="direction",
                    color_discrete_map={"Phishing": "#ef4444", "Safe": "#10b981"}
                )
                fig_lr.update_layout(
                    yaxis=dict(autorange="reversed"),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color="#cbd5e1"),
                    height=420
                )
                st.plotly_chart(fig_lr, use_container_width=True)

    except Exception as e:
        st.warning(f"Could not load saved model feature metadata: {e}")
