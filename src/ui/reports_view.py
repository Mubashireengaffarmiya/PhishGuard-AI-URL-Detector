"""
Reports and Export Center View for PhishGuard AI.
Unified download hub for PDF security audits, JSON scan dumps,
CSV telemetry logs, and evaluation reports.
"""

from typing import Dict, Any, Optional
import streamlit as st
import pandas as pd

from src.services.report_service import ReportService
from src.services.history_service import HistoryService


def render_reports_view(report_service: ReportService, history_service: HistoryService):
    """Renders the comprehensive security reports and export center."""
    st.markdown("### 📑 Security Reports & Data Export Center")
    st.caption("Generate formal PDF cybersecurity audit reports, export raw telemetry logs, and download historical datasets.")

    active_scan = st.session_state.get("active_scan")

    # Section 1: Active Scan Report Generation
    st.markdown("#### 🛡️ Active Scan Audit Report")
    if active_scan:
        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-weight: 600; font-size: 1rem; color: #f8fafc;">{active_scan['submitted_url']}</div>
                        <div style="font-size: 0.75rem; color: #94a3b8;">Classification: <strong>{active_scan['classification']}</strong> &bull; Risk Score: {active_scan['risk_score']}/100</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("📄 Compile PDF Security Audit", use_container_width=True):
                with st.spinner("Generating formal PDF document with ReportLab..."):
                    pdf_path = report_service.generate_pdf_report(active_scan)
                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            label="⬇️ Download PDF File",
                            data=f.read(),
                            file_name=pdf_path.name,
                            mime="application/pdf",
                            use_container_width=True
                        )

        with c2:
            json_str = report_service.generate_json_report(active_scan)
            st.download_button(
                "💾 Download Scan JSON",
                data=json_str,
                file_name=f"scan_{active_scan.get('scan_id', 'telemetry')}.json",
                mime="application/json",
                use_container_width=True
            )

        with c3:
            csv_str = report_service.generate_csv_report(active_scan)
            st.download_button(
                "📊 Download Scan Summary CSV",
                data=csv_str,
                file_name=f"scan_{active_scan.get('scan_id', 'summary')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    else:
        st.info("💡 No active scan is currently loaded. Scan a URL in the URL Scanner or select a scan from History to generate a single-scan report.")

    st.markdown("---")

    # Section 2: Bulk Historical Data Export
    st.markdown("#### 🗄️ Bulk Historical Telemetry Export")
    st.caption("Download all historical scan records from the persistent SQLite database.")

    bc1, bc2 = st.columns(2)
    with bc1:
        st.markdown("**Complete Audit Log (CSV Format)**")
        st.caption("Includes timestamps, normalized URLs, individual model votes, ensemble probabilities, and risk classifications.")
        csv_bulk = history_service.export_csv(privacy_mode="SHOW_ALL")
        st.download_button(
            "⬇️ Download Full History CSV",
            data=csv_bulk,
            file_name="phishguard_complete_history.csv",
            mime="text/csv",
            use_container_width=True
        )

    with bc2:
        st.markdown("**Structured Audit Log (JSON Format)**")
        st.caption("Complete JSON database dump including full 42 extracted feature dictionaries and reason summaries.")
        json_bulk = history_service.export_json(privacy_mode="SHOW_ALL")
        st.download_button(
            "⬇️ Download Full History JSON",
            data=json_bulk,
            file_name="phishguard_complete_history.json",
            mime="application/json",
            use_container_width=True
        )
