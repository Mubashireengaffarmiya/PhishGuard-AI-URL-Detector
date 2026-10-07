"""
Scan History View for PhishGuard AI.
Audit log console with search, classification filtering, privacy redaction modes,
detailed record inspection, and CSV/JSON dataset export.
"""

from typing import Dict, Any, List
import streamlit as st
import pandas as pd

from src.services.history_service import HistoryService
from src.services.report_service import ReportService
from src.ui.components import render_status_badge


def render_history_view(history_service: HistoryService, report_service: ReportService):
    """Renders the persistent audit log and scan history console."""
    st.markdown("### 📜 Scan Audit History & Telemetry Logs")
    st.caption("Inspect past URL evaluations, search by domain, filter by classification, and export audit records.")

    # Top Filter Bar
    c_search, c_filter, c_priv = st.columns([5, 3, 3])
    with c_search:
        search_query = st.text_input("🔍 Search by URL or Keyword", placeholder="e.g. paypal, chase.com", label_visibility="collapsed")
    with c_filter:
        class_filter = st.selectbox("Filter Classification", options=["ALL", "SAFE", "SUSPICIOUS", "PHISHING"], index=0, label_visibility="collapsed")
    with c_priv:
        privacy_mode = st.selectbox("Privacy Redaction", options=["SHOW_ALL", "MASK_PATH", "MASK_QUERY", "MASK_ALL"], index=0, label_visibility="collapsed")

    # Action buttons: Export CSV, Export JSON, Clear History
    b1, b2, b3, b_spacer = st.columns([2, 2, 2, 4])
    with b1:
        csv_data = history_service.export_csv(privacy_mode=privacy_mode)
        st.download_button(
            "⬇️ Export CSV",
            data=csv_data,
            file_name="phishguard_audit_history.csv",
            mime="text/csv",
            use_container_width=True
        )
    with b2:
        json_data = history_service.export_json(privacy_mode=privacy_mode)
        st.download_button(
            "⬇️ Export JSON",
            data=json_data,
            file_name="phishguard_audit_history.json",
            mime="application/json",
            use_container_width=True
        )
    with b3:
        if st.button("🗑️ Clear History", use_container_width=True):
            count = history_service.clear_all_history()
            from src.services.telemetry_service import get_telemetry_service
            get_telemetry_service().reset_session()
            st.success(f"Cleared {count} audit records.")
            st.rerun()

    st.markdown("---")

    # Fetch records
    scans = history_service.get_history(
        limit=100,
        classification_filter=class_filter,
        search_query=search_query,
        privacy_mode=privacy_mode
    )

    if not scans:
        st.info("No scan records match the current filter or search criteria.")
        return

    st.write(f"Showing **{len(scans)}** scan records:")

    # Render History Table
    for s in scans:
        with st.container():
            col1, col2, col3, col4 = st.columns([1, 6, 2, 2])
            col1.markdown(f"**#{s.get('id', '')}**")
            col2.markdown(f"`{s.get('display_url', '')}`<br><span style='font-size:0.72rem;color:#64748b;'>{s.get('timestamp', '')}</span>", unsafe_allow_html=True)
            col3.markdown(render_status_badge(s.get("classification", "")), unsafe_allow_html=True)
            col4.markdown(f"**Risk: {s.get('risk_score', 0)}/100**<br><span style='font-size:0.72rem;color:#94a3b8;'>Prob: {float(s.get('ensemble_prob', 0))*100:.1f}%</span>", unsafe_allow_html=True)

            with st.expander(f"Inspect Details for Scan #{s.get('id')}"):
                dc1, dc2 = st.columns(2)
                with dc1:
                    st.write("**Classification:**", s.get("classification"))
                    st.write("**Risk Score:**", f"{s.get('risk_score')}/100")
                    st.write("**Normalized URL:**", s.get("display_normalized_url"))
                    st.write("**Reason Summary:**", s.get("reason_summary"))
                with dc2:
                    st.write("**Random Forest Vote:**", s.get("rf_prediction"))
                    st.write("**Decision Tree Vote:**", s.get("dt_prediction"))
                    st.write("**Logistic Regression Vote:**", s.get("lr_prediction"))

                if st.button(f"Generate PDF for Scan #{s.get('id')}", key=f"pdf_btn_{s.get('id')}"):
                    pdf_path = report_service.generate_pdf_report(s)
                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            label=f"⬇️ Download PDF for Scan #{s.get('id')}",
                            data=f.read(),
                            file_name=pdf_path.name,
                            mime="application/pdf",
                            key=f"dl_pdf_{s.get('id')}"
                        )
            st.markdown("<hr style='margin: 0.35rem 0; opacity: 0.1;'>", unsafe_allow_html=True)
