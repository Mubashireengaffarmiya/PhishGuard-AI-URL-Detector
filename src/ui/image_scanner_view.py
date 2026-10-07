"""
Image & Screenshot URL Scanner View for PhishGuard AI.
Multi-modal image intake: analyzes uploaded screenshots for embedded URLs using
local Tesseract OCR, detects QR codes via OpenCV, assesses image quality (blur/resolution),
suggests conservative OCR character corrections, displays bounding-box highlights,
and feeds confirmed candidates directly into the unified ML prediction engine.
"""

from typing import Dict, Any, List, Optional
import streamlit as st
from PIL import Image
import io

import hashlib

from src.services.image_service import ImageScanService
from src.services.prediction_service import PredictionService
from src.services.explanation_service import ExplanationService
from src.services.report_service import ReportService
from src.services.telemetry_service import get_telemetry_service
from src.ui.scanner_view import _display_scan_result


def render_image_scanner_view(
    image_service: ImageScanService,
    prediction_service: PredictionService,
    explanation_service: ExplanationService,
    report_service: ReportService,
    telemetry_service: Optional[Any] = None,
    **kwargs
):
    """Renders the screenshot and OCR multi-modal URL scanner."""
    st.markdown("### 🖼️ Screenshot & Image URL Scanner")
    st.caption(
        "Upload email screenshots, SMS notifications, social media messages, or invoice images. "
        "PhishGuard extracts text URLs via local OCR and embedded QR codes simultaneously."
    )

    # File Uploader
    uploaded_file = st.file_uploader(
        "Upload screenshot or image containing URLs / QR codes",
        type=["png", "jpg", "jpeg", "webp"],
        help="Supported formats: PNG, JPG, JPEG, WEBP. Local OCR extraction with privacy preservation."
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        pil_img = Image.open(io.BytesIO(file_bytes))

        # Check unique file signature to safely prevent rerun duplicate execution and telemetry increments
        file_sig = hashlib.sha256(file_bytes).hexdigest()

        if st.session_state.get("last_processed_image_sig") != file_sig:
            # Run multi-modal scan
            with st.spinner("Processing image: running OCR text detection and QR matrix decoding..."):
                scan_data = image_service.process_image(file_bytes, filename=uploaded_file.name)
                st.session_state["last_image_scan_data"] = scan_data
                st.session_state["last_processed_image_sig"] = file_sig

                # Increment OCR / Image Scans counter if completed successfully without fatal error
                if scan_data.get("ocr_status") != "error":
                    tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                    tele.record_image_scan()
        else:
            scan_data = st.session_state.get("last_image_scan_data", {})

        quality = scan_data.get("quality", {})
        candidates = scan_data.get("candidates", [])

        # Display Top Summary Tabs
        img_col, info_col = st.columns([5, 5])

        with img_col:
            st.markdown("#### 📷 Image Preview")
            if scan_data.get("annotated_image") is not None:
                st.image(scan_data["annotated_image"], caption="Annotated Image (Detected URL Bounding Boxes Highlighted)", use_container_width=True)
            else:
                st.image(pil_img, caption=f"{uploaded_file.name} ({pil_img.width}x{pil_img.height}px)", use_container_width=True)

        with info_col:
            st.markdown("#### 🔍 Multi-Modal Extraction Report")
            c1, c2 = st.columns(2)
            c1.metric("OCR Confidence", f"{scan_data.get('ocr_confidence', 0.0):.1f}%")
            c2.metric("Detected URLs", len(candidates))

            # Quality Check Notice
            if quality.get("warnings"):
                for w in quality["warnings"]:
                    st.warning(f"⚠️ {w}")
            else:
                st.success("✅ Image resolution and sharpness are optimal for OCR.")

            # QR Code Detection Indicator
            if scan_data.get("qr_detected"):
                st.info(f"📱 **QR Code Detected**: `{scan_data.get('qr_payload')}`")

            # OCR Raw Text Expander
            with st.expander("📝 View Raw OCR Extracted Text"):
                st.text(scan_data.get("raw_ocr_text") or "(No readable text detected)")

        st.markdown("---")

        # Candidate Review & Confirmation Section
        st.markdown("#### 🎯 Detected URL Candidates for Security Analysis")

        if not candidates:
            st.warning("No valid web URLs or QR codes were detected in the uploaded image. Ensure the image text is clear and legible.")
            return

        st.info("💡 **Mandatory Confirmation**: Review extracted URLs below before submitting to the machine-learning prediction engine.")

        # Candidate selection or batch
        for idx, cand in enumerate(candidates):
            with st.container():
                st.markdown(
                    f"""
                    <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.85rem 1.25rem; margin-bottom: 0.75rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <span style="font-size: 0.72rem; color: #38bdf8; font-weight: 600; text-transform: uppercase;">Candidate #{idx+1} &bull; Source: {cand['source']} &bull; Confidence: {cand['confidence']}</span>
                                <div style="font-family: 'JetBrains Mono'; font-size: 0.95rem; font-weight: 600; color: #f8fafc; margin-top: 0.2rem;">
                                    {cand['url']}
                                </div>
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Show OCR Error Correction candidates if available
                if cand.get("corrections"):
                    st.caption("🔧 Conservative OCR Error Correction Suggestions (Review before analyzing):")
                    for corr in cand["corrections"]:
                        c_col1, c_col2 = st.columns([8, 2])
                        c_col1.markdown(f"&bull; Candidate: `{corr['corrected_candidate']}` *(Rule: {corr['rule']})*")
                        if c_col2.button(f"Use Correction #{idx+1}", key=f"btn_corr_{idx}"):
                            cand["url"] = corr["corrected_candidate"]
                            st.rerun()

                # Action button to analyze this specific URL
                btn_key = f"btn_analyze_cand_{idx}"
                if st.button(f"🛡️ Analyze Candidate #{idx+1} with ML Engine", key=btn_key, type="primary"):
                    with st.spinner(f"Evaluating URL: {cand['url']}..."):
                        ml_res = prediction_service.analyze_url(
                            raw_url=cand["url"],
                            input_source=f"IMAGE_OCR ({cand['source']})",
                            persist=True
                        )
                        tele = telemetry_service or kwargs.get("telemetry_service") or get_telemetry_service()
                        tele.record_url_scan(ml_res)
                        st.session_state["image_active_scan"] = ml_res

        # If a candidate was analyzed, display its full security result
        if "image_active_scan" in st.session_state and st.session_state["image_active_scan"]:
            st.markdown("### 📋 Analysis Results for Selected Image URL")
            _display_scan_result(st.session_state["image_active_scan"], explanation_service, report_service)
    else:
        st.session_state["last_processed_image_sig"] = None
        st.session_state["last_image_scan_data"] = None
        st.session_state["image_active_scan"] = None
