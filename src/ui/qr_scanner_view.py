"""
QR Code Scanner View for PhishGuard AI.
Safely decodes QR matrix payloads using OpenCV, prevents automatic client execution,
validates structure, and routes confirmed URLs into the core ML prediction engine.
"""

from typing import Dict, Any, Optional
import streamlit as st
from PIL import Image
import io

import hashlib

from src.services.qr_service import QRService
from src.services.prediction_service import PredictionService
from src.services.explanation_service import ExplanationService
from src.services.report_service import ReportService
from src.services.demo_service import DemoService
from src.services.telemetry_service import get_telemetry_service
from src.ui.scanner_view import _display_scan_result


def render_qr_scanner_view(
    qr_service: QRService,
    prediction_service: PredictionService,
    explanation_service: ExplanationService,
    report_service: ReportService,
    telemetry_service: Optional[Any] = None,
    **kwargs
):
    """Renders the QR code scanner console."""
    st.markdown("### 📱 QR Code (Quishing) Scanner")
    st.caption("Safely decode and evaluate QR matrix codes without client-side browser navigation.")

    c_upload, c_demo = st.columns([7, 3])

    with c_upload:
        uploaded_qr = st.file_uploader(
            "Upload QR Code Image",
            type=["png", "jpg", "jpeg", "webp"],
            help="Supported formats: PNG, JPG, JPEG, WEBP."
        )

    with c_demo:
        st.markdown("**Quick Demo QR**")
        st.caption("Load a pre-generated sample QR code for testing.")
        if st.button("Generate & Test Demo QR", use_container_width=True):
            demo_qr_path = DemoService.ensure_demo_qr_exists()
            with open(demo_qr_path, "rb") as f:
                st.session_state["qr_demo_bytes"] = f.read()

    qr_bytes = None
    if uploaded_qr is not None:
        qr_bytes = uploaded_qr.getvalue()
    elif "qr_demo_bytes" in st.session_state and st.session_state["qr_demo_bytes"]:
        qr_bytes = st.session_state["qr_demo_bytes"]

    if qr_bytes:
        pil_qr = Image.open(io.BytesIO(qr_bytes))
        c_prev, c_decode = st.columns([4, 6])

        with c_prev:
            st.image(pil_qr, caption="Loaded QR Image", use_container_width=True)

        with c_decode:
            qr_sig = hashlib.sha256(qr_bytes).hexdigest()

            if st.session_state.get("last_decoded_qr_sig") != qr_sig:
                with st.spinner("Decoding QR matrix using OpenCV..."):
                    decode_res = qr_service.decode_qr(qr_bytes)
                    st.session_state["last_qr_decode_res"] = decode_res
                    st.session_state["last_decoded_qr_sig"] = qr_sig

                    if decode_res.get("success"):
                        tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                        tele.record_qr_scan()
            else:
                decode_res = st.session_state.get("last_qr_decode_res", {})

            if decode_res.get("success"):
                st.success("✅ QR Matrix Successfully Decoded")
                st.markdown(f"**Embedded Payload:** `{decode_res['payload']}`")

                if decode_res.get("is_url"):
                    st.markdown(f"**Normalized URL:** `{decode_res['normalized_url']}`")
                    if decode_res.get("scheme_added"):
                        st.info("ℹ️ Web protocol 'https://' was added automatically.")

                    st.markdown("---")
                    if st.button("🛡️ Analyze Extracted QR URL with PhishGuard AI", type="primary", use_container_width=True):
                        with st.spinner("Executing multi-model prediction pipeline..."):
                            qr_scan_res = prediction_service.analyze_url(
                                raw_url=decode_res["normalized_url"],
                                input_source="QR_CODE",
                                persist=True
                            )
                            tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                            tele.record_url_scan(qr_scan_res)

                            st.session_state["qr_active_scan"] = qr_scan_res
                else:
                    st.warning(f"⚠️ Decoded text is not a valid web URL: {decode_res.get('message', '')}")
            else:
                st.error(f"❌ {decode_res.get('message', 'Failed to decode QR code.')}")
    else:
        st.session_state["last_decoded_qr_sig"] = None
        st.session_state["last_qr_decode_res"] = None

    # If QR URL was analyzed, display full results
    if "qr_active_scan" in st.session_state and st.session_state["qr_active_scan"]:
        st.markdown("### 📋 Analysis Results for Decoded QR Code")
        _display_scan_result(st.session_state["qr_active_scan"], explanation_service, report_service)
