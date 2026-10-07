"""
Project Architecture View for PhishGuard AI.
Visual architecture diagram illustrating data flows from multi-modal intake
through normalization, 42-feature extraction, ML ensemble, explainability,
AI analysis, and persistent audit reporting.
"""

import streamlit as st


def render_architecture_view():
    """Renders the visual architecture and dataflow diagram."""
    st.markdown("### 🏛️ PhishGuard AI Core System Architecture")
    st.caption("End-to-end dataflow pipeline from multi-modal intake to multi-model ensemble consensus and explainable reporting.")

    # High-level Flowchart using custom HTML/CSS
    st.markdown(
        """
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;">
            <div style="text-align: center; margin-bottom: 1rem;">
                <span class="pg-badge pg-badge-ready" style="font-size: 0.85rem; padding: 0.35rem 0.85rem;">MULTI-CHANNEL INTAKE LAYER</span>
            </div>
            
            <div style="display: flex; justify-content: space-around; text-align: center; gap: 1rem; margin-bottom: 1rem;">
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <div style="font-size: 1.25rem;">⌨️</div>
                    <strong style="color: #38bdf8; font-size: 0.85rem;">Manual URL Input</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">User text entry</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <div style="font-size: 1.25rem;">📱</div>
                    <strong style="color: #38bdf8; font-size: 0.85rem;">QR Code Scanner</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">OpenCV Matrix Decoder</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <div style="font-size: 1.25rem;">🖼️</div>
                    <strong style="color: #38bdf8; font-size: 0.85rem;">Screenshot OCR</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">Tesseract Engine</div>
                </div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.75rem; text-align: center; margin-bottom: 1rem;">
                <strong style="color: #f8fafc; font-size: 0.9rem;">Sanitization, Validation &amp; Normalization</strong>
                <div style="font-size: 0.75rem; color: #94a3b8;">RFC 3986 Parsing &bull; Scheme Insertion &bull; Delimiter Stripping &bull; Injection Prevention</div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(129, 140, 248, 0.3); border-radius: 8px; padding: 0.75rem; text-align: center; margin-bottom: 1rem;">
                <strong style="color: #a78bfa; font-size: 0.9rem;">Deterministic Feature Engineering (42 Features)</strong>
                <div style="font-size: 0.75rem; color: #cbd5e1;">URL Length &bull; Shannon Entropy &bull; Subdomain Depth &bull; Lexical Keywords &bull; Ratios &bull; Heuristic Flags</div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="text-align: center; margin-bottom: 0.5rem;">
                <span class="pg-badge pg-badge-ready" style="font-size: 0.85rem; padding: 0.35rem 0.85rem;">HETEROGENEOUS ML ENSEMBLE CORE</span>
            </div>

            <div style="display: flex; justify-content: space-around; text-align: center; gap: 1rem; margin-bottom: 1rem;">
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #38bdf8;">Random Forest</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">100 Trees &bull; Depth 15</div>
                    <div style="font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #00f0ff; margin-top: 0.25rem;">Weight: 50%</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #38bdf8;">Decision Tree</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">CART Splits &bull; Depth 10</div>
                    <div style="font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #00f0ff; margin-top: 0.25rem;">Weight: 25%</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #38bdf8;">Logistic Regression</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">StandardScaled &bull; L2</div>
                    <div style="font-family: 'JetBrains Mono'; font-size: 0.75rem; color: #00f0ff; margin-top: 0.25rem;">Weight: 25%</div>
                </div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 0.75rem; text-align: center; margin-bottom: 1rem;">
                <strong style="color: #f8fafc; font-size: 0.9rem;">Consensus &amp; Disagreement Detection Engine</strong>
                <div style="font-size: 0.75rem; color: #94a3b8;">Weighted Probability Synthesis &bull; Disagreement Alert &bull; 0-100 Composite Risk Scoring</div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="display: flex; justify-content: space-around; text-align: center; gap: 1rem;">
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #34d399; font-size: 0.85rem;">Explainable AI</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">Indicator Rationale &bull; Gini Attribution</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(129, 140, 248, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #a78bfa; font-size: 0.85rem;">AI Security Analyst</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">Offline Rule-Based Expert System</div>
                </div>
                <div style="background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 0.75rem; flex: 1;">
                    <strong style="color: #38bdf8; font-size: 0.85rem;">Passive Threat Intel</strong>
                    <div style="font-size: 0.72rem; color: #94a3b8;">DNS &bull; SSL TLS &bull; WHOIS Age</div>
                </div>
            </div>

            <div style="text-align: center; color: #38bdf8; font-size: 1.25rem; margin: 0.5rem 0;">&darr;</div>

            <div style="background: rgba(15, 23, 42, 0.95); border: 1.5px solid #00f0ff; border-radius: 8px; padding: 0.85rem; text-align: center;">
                <strong style="color: #00f0ff; font-size: 0.95rem;">SOC Console &bull; Persistent SQLite History &bull; PDF Audit Export</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
