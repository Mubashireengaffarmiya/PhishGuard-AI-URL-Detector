"""
Dashboard View for PhishGuard AI.
SOC Overview Console displaying live system health, session telemetry,
recent scan audit feed, and risk distribution visualizations.
Grounds all metrics strictly in real application data and SQLite scan records.
"""

from typing import Dict, Any, List
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

from src.services.health_service import HealthService
from src.services.history_service import HistoryService
from src.ui.components import render_status_badge


def render_dashboard_view(session_stats: Dict[str, Any], history_service: HistoryService):
    """Renders the main Security Operations Center dashboard with 3D glossy telemetry."""
    st.markdown("### 📊 Security Operations Center Overview")
    st.caption("Live system telemetry, multi-modal scan statistics, and threat distribution.")

    # Fetch real database metrics
    db_metrics = history_service.get_summary_metrics()
    total_db = db_metrics.get("total_scans", 0)

    # Seamless synchronization: ensure session stats reflect real database records
    if total_db > 0 and session_stats.get("total_scans", 0) < total_db:
        session_stats["total_scans"] = total_db
        session_stats["safe_count"] = db_metrics.get("safe_count", 0)
        session_stats["phishing_count"] = db_metrics.get("phishing_count", 0)
        session_stats["warning_count"] = db_metrics.get("suspicious_count", 0)
        session_stats["disagreement_count"] = db_metrics.get("disagreement_count", 0)
        session_stats["avg_phishing_prob"] = db_metrics.get("avg_phishing_prob", 0.0)

    # 1. System Health Status Grid
    with st.expander("🟢 System Component Status (11 Subsystems)", expanded=False):
        health = HealthService.check_all_subsystems()
        cols = st.columns(4)
        cols[0].metric("Overall Health", health["overall_health"])
        cols[1].metric("Ready Components", f"{health['ready_count']} / {health['total_components']}")
        cols[2].metric("Warnings", health["warning_count"])
        cols[3].metric("Python Runtime", f"v{health['python_version']}")

        st.markdown("<div style='margin-top: 0.5rem;'></div>", unsafe_allow_html=True)
        df_health = pd.DataFrame(health["subsystems"])
        for _, row in df_health.iterrows():
            c1, c2, c3 = st.columns([3, 2, 5])
            c1.markdown(f"**{row['name']}** ({row['component']})")
            c2.markdown(render_status_badge(row['status']), unsafe_allow_html=True)
            c3.caption(row['details'])

    # 2. Premium 3D Glossy Session Telemetry Grid
    st.markdown("#### ⚡ Real Session Telemetry")

    # Row 1: 4 Core Detection Metrics
    sc1, sc2, sc3, sc4 = st.columns(4)

    with sc1:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-url">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">🌐</span>
                    <span class="pg-metric-badge">REAL-TIME</span>
                </div>
                <div class="pg-metric-value">{session_stats['total_scans']}</div>
                <div class="pg-metric-label">URLs Scanned (Session)</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc2:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-safe">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">🛡️</span>
                    <span class="pg-metric-badge">VERIFIED</span>
                </div>
                <div class="pg-metric-value">{session_stats['safe_count']}</div>
                <div class="pg-metric-label">Safe Classifications</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc3:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-phish">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">🚨</span>
                    <span class="pg-metric-badge">THREAT</span>
                </div>
                <div class="pg-metric-value">{session_stats['phishing_count']}</div>
                <div class="pg-metric-label">Phishing Alerts</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc4:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-diverge">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">⚖️</span>
                    <span class="pg-metric-badge">CONSENSUS</span>
                </div>
                <div class="pg-metric-value">{session_stats['disagreement_count']}</div>
                <div class="pg-metric-label">Model Divergences</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='margin-top: 0.75rem;'></div>", unsafe_allow_html=True)

    # Row 2: 4 Multi-Modal and Quality Metrics
    sc5, sc6, sc7, sc8 = st.columns(4)

    avg_p = session_stats['avg_phishing_prob'] * 100 if session_stats['total_scans'] > 0 else 0.0

    with sc5:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-prob">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">🎯</span>
                    <span class="pg-metric-badge">ENSEMBLE</span>
                </div>
                <div class="pg-metric-value">{avg_p:.1f}%</div>
                <div class="pg-metric-label">Avg Phish Probability</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc6:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-ocr">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">📷</span>
                    <span class="pg-metric-badge">OCR VISION</span>
                </div>
                <div class="pg-metric-value">{session_stats.get('image_scans', 0)}</div>
                <div class="pg-metric-label">OCR / Image Scans</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc7:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-qr">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">📱</span>
                    <span class="pg-metric-badge">QR MATRIX</span>
                </div>
                <div class="pg-metric-value">{session_stats.get('qr_scans', 0)}</div>
                <div class="pg-metric-label">QR Decodings</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with sc8:
        st.markdown(
            f"""
            <div class="pg-metric-card-3d pg-metric-demo">
                <div class="pg-metric-top">
                    <span class="pg-metric-icon">🎓</span>
                    <span class="pg-metric-badge">ACADEMIC</span>
                </div>
                <div class="pg-metric-value">{session_stats.get('demo_scans', 0)}</div>
                <div class="pg-metric-label">Faculty Demos Loaded</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='margin-top: 1.5rem;'></div>", unsafe_allow_html=True)

    # 3. Visual Charts & Recent Scans
    c_chart, c_recent = st.columns([5, 5])

    with c_chart:
        st.markdown("#### 🎯 Classification Distribution")
        dist = db_metrics.get("classification_distribution", {})

        if total_db > 0:
            labels = list(dist.keys())
            values = list(dist.values())
            colors = ["#10b981", "#f59e0b", "#f43f5e"]

            fig = go.Figure(data=[go.Pie(
                labels=labels,
                values=values,
                hole=.52,
                marker=dict(colors=colors, line=dict(color='rgba(13, 21, 38, 0.8)', width=2)),
                textinfo='label+percent',
                insidetextorientation='radial'
            )])
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#cbd5e1", family="Inter"),
                showlegend=True,
                height=300,
                margin=dict(l=10, r=10, t=10, b=10),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                )
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No scans saved yet. Scan a URL in the URL Scanner to generate telemetry.")

    with c_recent:
        st.markdown("#### 🕒 Recent Scan Feed")
        recent_scans = history_service.get_history(limit=6)
        if recent_scans:
            for s in recent_scans:
                cls_upper = str(s["classification"]).upper()
                if cls_upper == "SAFE":
                    cls_color = "#34d399"
                    badge_style = "background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35);"
                    icon = "🛡️"
                elif cls_upper == "SUSPICIOUS":
                    cls_color = "#fbbf24"
                    badge_style = "background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35);"
                    icon = "⚠️"
                else:
                    cls_color = "#fb7185"
                    badge_style = "background: rgba(244, 63, 94, 0.18); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4);"
                    icon = "🚨"

                st.markdown(
                    f"""
                    <div class="pg-feed-row">
                        <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 270px;">
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.84rem; font-weight: 500; color: #f8fafc; overflow: hidden; text-overflow: ellipsis;">
                                {icon} {s['display_url']}
                            </div>
                            <div style="color: #64748b; font-size: 0.72rem; margin-top: 0.15rem;">{s.get('timestamp', '')}</div>
                        </div>
                        <div style="text-align: right; display: flex; flex-direction: column; align-items: flex-end; gap: 0.2rem;">
                            <span style="{badge_style}; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em;">
                                {s['classification']}
                            </span>
                            <div style="font-size: 0.72rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">
                                Risk: <strong style="color: {cls_color};">{s.get('risk_score', 0)}</strong>/100
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.caption("No historical records recorded.")
