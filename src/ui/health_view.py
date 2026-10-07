"""
System Health Diagnostics View for PhishGuard AI.
Complete operational integrity test matrix verifying model files,
scaler artifacts, OCR engines, QR detectors, database connectivity, and report generators.
"""

import streamlit as st
import pandas as pd
import sys
import platform

from src.services.health_service import HealthService
from src.ui.components import render_status_badge


def render_health_view():
    """Renders the system health diagnostics dashboard."""
    st.markdown("### 🏥 System Health & Integrity Diagnostics")
    st.caption("Real-time operational status tests across all platform layers. Non-fabricated diagnostic feedback.")

    health = HealthService.check_all_subsystems()

    # Top Status Summary
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Overall System State", health["overall_health"])
    c2.metric("Operational Components", f"{health['ready_count']} / {health['total_components']}")
    c3.metric("Warnings / Degradations", health["warning_count"])
    c4.metric("Errors Detected", health["error_count"])

    st.markdown("---")

    # Detailed Subsystems Table
    st.markdown("#### 🔬 Subsystem Health Matrix")
    for s in health["subsystems"]:
        c_name, c_status, c_details = st.columns([3, 2, 5])
        c_name.markdown(f"**{s['name']}**<br><span style='font-size:0.75rem;color:#64748b;'>{s['component']}</span>", unsafe_allow_html=True)
        c_status.markdown(render_status_badge(s['status']), unsafe_allow_html=True)
        c_details.caption(s['details'])
        st.markdown("<hr style='margin: 0.35rem 0; opacity: 0.1;'>", unsafe_allow_html=True)

    # Runtime Environment Telemetry
    st.markdown("#### 💻 Runtime Environment Diagnostics")
    ec1, ec2, ec3 = st.columns(3)
    ec1.write(f"**Python Version:** {sys.version.split()[0]}")
    ec2.write(f"**Platform OS:** {platform.system()} {platform.release()}")
    ec3.write(f"**Architecture:** {platform.machine()}")
