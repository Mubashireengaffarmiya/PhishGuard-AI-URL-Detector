"""
Model Analytics View for PhishGuard AI.
Visualizes actual test-set model evaluation metrics loaded directly from persisted
evaluation artifacts: Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrices.
"""

from typing import Dict, Any
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import joblib

from src.config import EVALUATION_METRICS_PATH


def render_analytics_view():
    """Renders the comprehensive model analytics and performance benchmark dashboard."""
    st.markdown("### 📈 Model Performance & Evaluation Analytics")
    st.caption("Empirical benchmarks evaluated on holdout test partition (20% split). No fabricated metrics.")

    try:
        data = joblib.load(EVALUATION_METRICS_PATH)
    except Exception as e:
        st.error(f"Failed to load evaluation metrics artifact from {EVALUATION_METRICS_PATH.name}: {e}")
        return

    eval_data = data.get("evaluation", {})
    summary_table = eval_data.get("summary_table", [])
    train_count = data.get("train_sample_count", 0)
    test_count = data.get("test_sample_count", 0)
    class_dist = data.get("class_distribution", {})

    # 1. Dataset Partition Statistics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Training Samples", f"{train_count:,}")
    c2.metric("Holdout Test Samples", f"{test_count:,}")
    c3.metric("Train Legitimate", f"{class_dist.get('train_legitimate', 0):,}")
    c4.metric("Train Phishing", f"{class_dist.get('train_phishing', 0):,}")

    st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)

    # 2. Comparative Performance Metrics Table
    st.markdown("#### 🏆 Multi-Model Benchmark Comparison")
    if summary_table:
        df_summary = pd.DataFrame(summary_table)
        st.dataframe(
            df_summary.style.format({
                "Accuracy": "{:.4f}",
                "Precision": "{:.4f}",
                "Recall": "{:.4f}",
                "F1-Score": "{:.4f}",
                "ROC-AUC": "{:.4f}"
            }),
            use_container_width=True
        )

        # Plotly comparison bar chart
        df_melt = df_summary.melt(id_vars=["Model"], var_name="Metric", value_name="Score")
        fig_comp = px.bar(
            df_melt,
            x="Metric",
            y="Score",
            color="Model",
            barmode="group",
            title="Algorithm Performance Comparison on Test Set",
            color_discrete_sequence=["#38bdf8", "#818cf8", "#34d399"],
            range_y=[0.9, 1.01]
        )
        fig_comp.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#cbd5e1"),
            height=360
        )
        st.plotly_chart(fig_comp, use_container_width=True)

    # 3. Confusion Matrix Visualizations
    st.markdown("#### 🧩 Confusion Matrices (Test Partition)")
    model_evals = eval_data.get("model_evaluations", {})
    cm_cols = st.columns(3)

    for col, (model_name, info) in zip(cm_cols, model_evals.items()):
        cm = info.get("confusion_matrix", {}).get("matrix", [[0, 0], [0, 0]])
        with col:
            st.markdown(f"**{model_name}**")
            fig_cm = px.imshow(
                cm,
                text_auto=True,
                labels=dict(x="Predicted Class", y="Actual Ground Truth", color="Count"),
                x=["Safe (0)", "Phish (1)"],
                y=["Safe (0)", "Phish (1)"],
                color_continuous_scale="Blues"
            )
            fig_cm.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#cbd5e1", size=10),
                height=260,
                margin=dict(l=10, r=10, t=25, b=10)
            )
            st.plotly_chart(fig_cm, use_container_width=True, key=f"plotly_cm_{model_name.lower().replace(' ', '_')}")

    # 4. Mandatory Evaluation Disclaimer
    st.markdown("---")
    st.markdown(
        """
        <div style="background: rgba(148, 163, 184, 0.08); border-left: 3px solid #38bdf8; padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.8rem; color: #94a3b8;">
            <strong>Academic Evaluation Note:</strong> Test metrics are calculated strictly on the held-out test split of the collected dataset.
            In real-world cybersecurity deployments, adversary tactics continually evolve (zero-day obfuscation, domain aging, homograph attacks).
            Therefore, high test-set accuracy does not guarantee 100% detection of unseen real-world zero-day campaigns.
        </div>
        """,
        unsafe_allow_html=True
    )
