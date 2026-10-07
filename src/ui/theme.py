"""
Theme and custom CSS styling for PhishGuard AI.
Implements the 'Cyber Dark' SOC dashboard theme and 'Clean Light' accessible theme.
Includes premium glossy glassmorphism, 3D layered elevation, realistic cyber glows,
modern typography, animated indicators, and responsive SOC console layouts.
"""

def get_theme_css(theme: str = "Cyber Dark", animations_enabled: bool = True) -> str:
    """
    Returns custom CSS injecting the state-of-the-art 3D SOC cybersecurity aesthetic.
    """
    is_dark = (theme == "Cyber Dark")

    # Color Palette definitions
    bg_main = "#060a12" if is_dark else "#f8fafc"
    bg_surface = "rgba(13, 21, 38, 0.72)" if is_dark else "rgba(255, 255, 255, 0.9)"
    bg_surface_alt = "rgba(18, 29, 51, 0.65)" if is_dark else "rgba(241, 245, 249, 0.9)"
    border_color = "rgba(56, 189, 248, 0.18)" if is_dark else "rgba(203, 213, 225, 0.8)"
    border_hover = "rgba(0, 240, 255, 0.45)" if is_dark else "rgba(148, 163, 184, 0.8)"
    text_primary = "#f8fafc" if is_dark else "#0f172a"
    text_secondary = "#94a3b8" if is_dark else "#475569"
    text_muted = "#64748b" if is_dark else "#94a3b8"
    accent_cyan = "#00f0ff" if is_dark else "#0284c7"
    accent_blue = "#38bdf8" if is_dark else "#2563eb"
    accent_violet = "#818cf8" if is_dark else "#6366f1"
    glow_color = "rgba(0, 240, 255, 0.18)" if is_dark else "rgba(37, 99, 235, 0.08)"

    # Animation control
    anim_pulse = "animation: pulse-glow 3s infinite ease-in-out;" if animations_enabled else "animation: none;"
    anim_transition = "transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1);" if animations_enabled else "transition: none;"

    return f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }}

    code, pre, .mono {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    /* Global App Container with subtle radial vignette */
    .stApp {{
        background: radial-gradient(circle at 50% 0%, #0d1a33 0%, #060a12 65%, #04060b 100%);
        background-attachment: fixed;
        color: {text_primary};
    }}

    /* Subtle custom scrollbar */
    ::-webkit-scrollbar {{
        width: 7px;
        height: 7px;
    }}
    ::-webkit-scrollbar-track {{
        background: rgba(6, 10, 18, 0.6);
    }}
    ::-webkit-scrollbar-thumb {{
        background: rgba(56, 189, 248, 0.25);
        border-radius: 999px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: rgba(0, 240, 255, 0.5);
    }}

    /* Top Brand Banner - Glossy 3D Glass Surface */
    .pg-brand-banner {{
        background: linear-gradient(135deg, rgba(17, 27, 49, 0.85) 0%, rgba(10, 17, 32, 0.9) 100%);
        border: 1px solid rgba(56, 189, 248, 0.22);
        border-top: 1px solid rgba(255, 255, 255, 0.16);
        border-radius: 14px;
        padding: 1.25rem 1.75rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.55), 0 0 20px rgba(0, 240, 255, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.12);
        display: flex;
        align-items: center;
        justify-content: space-between;
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
    }}

    .pg-brand-title {{
        font-size: 1.75rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        background: linear-gradient(90deg, #38bdf8 0%, #a78bfa 50%, #00f0ff 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        text-shadow: 0 0 30px rgba(56, 189, 248, 0.25);
    }}

    .pg-brand-tagline {{
        font-size: 0.86rem;
        color: {text_secondary};
        margin: 0.25rem 0 0 0;
        font-weight: 400;
    }}

    /* Status Pills */
    .pg-badge {{
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        backdrop-filter: blur(8px);
    }}

    .pg-badge-ready {{
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(5, 150, 105, 0.1) 100%);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.15);
    }}

    .pg-badge-warning {{
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.18) 0%, rgba(217, 119, 6, 0.1) 100%);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.4);
        box-shadow: 0 0 10px rgba(245, 158, 11, 0.15);
    }}

    .pg-badge-error {{
        background: linear-gradient(135deg, rgba(244, 63, 94, 0.2) 0%, rgba(225, 29, 72, 0.1) 100%);
        color: #fb7185;
        border: 1px solid rgba(244, 63, 94, 0.45);
        box-shadow: 0 0 12px rgba(244, 63, 94, 0.2);
    }}

    .pg-badge-not-config {{
        background: rgba(148, 163, 184, 0.15);
        color: #94a3b8;
        border: 1px solid rgba(148, 163, 184, 0.3);
    }}

    /* Premium 3D Cyber Cards */
    .pg-card {{
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(10, 16, 30, 0.85) 100%);
        border: 1px solid {border_color};
        border-top: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 14px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(14px);
        {anim_transition}
    }}

    .pg-card:hover {{
        border-color: {border_hover};
        box-shadow: 0 14px 35px -5px rgba(0, 240, 255, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.15);
        transform: translateY(-2px);
    }}

    /* ==========================================================
       PREMIUM 3D GLOSSY TELEMETRY CARDS
       ========================================================== */
    .pg-metric-card-3d {{
        background: linear-gradient(145deg, rgba(17, 27, 49, 0.85) 0%, rgba(11, 18, 35, 0.92) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-top: 1px solid rgba(255, 255, 255, 0.16);
        border-radius: 14px;
        padding: 1.15rem 1.25rem;
        position: relative;
        overflow: hidden;
        box-shadow: 0 12px 28px -6px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        {anim_transition}
    }}

    .pg-metric-card-3d::after {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 40%;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.05) 0%, rgba(255, 255, 255, 0) 100%);
        pointer-events: none;
    }}

    .pg-metric-card-3d:hover {{
        transform: translateY(-4px);
        box-shadow: 0 18px 36px -6px rgba(0, 0, 0, 0.75), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-top {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.6rem;
    }}

    .pg-metric-icon {{
        font-size: 1.35rem;
        line-height: 1;
        filter: drop-shadow(0 2px 6px rgba(0, 0, 0, 0.4));
    }}

    .pg-metric-badge {{
        font-size: 0.62rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        padding: 0.15rem 0.45rem;
        border-radius: 4px;
        background: rgba(255, 255, 255, 0.06);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #94a3b8;
    }}

    .pg-metric-value {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 2.15rem;
        font-weight: 800;
        line-height: 1.1;
        letter-spacing: -0.02em;
        margin-bottom: 0.35rem;
    }}

    .pg-metric-label {{
        font-size: 0.74rem;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }}

    /* Semantic Accent Glows for Telemetry Cards */
    .pg-metric-url {{
        border-left: 3px solid #0ea5e9;
    }}
    .pg-metric-url .pg-metric-value {{
        color: #38bdf8;
        text-shadow: 0 0 20px rgba(56, 189, 248, 0.35);
    }}
    .pg-metric-url:hover {{
        border-color: rgba(56, 189, 248, 0.5);
        box-shadow: 0 16px 35px -5px rgba(14, 165, 233, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-safe {{
        border-left: 3px solid #10b981;
    }}
    .pg-metric-safe .pg-metric-value {{
        color: #34d399;
        text-shadow: 0 0 20px rgba(52, 211, 153, 0.35);
    }}
    .pg-metric-safe:hover {{
        border-color: rgba(16, 185, 129, 0.5);
        box-shadow: 0 16px 35px -5px rgba(16, 185, 129, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-phish {{
        border-left: 3px solid #f43f5e;
    }}
    .pg-metric-phish .pg-metric-value {{
        color: #fb7185;
        text-shadow: 0 0 20px rgba(244, 63, 94, 0.4);
    }}
    .pg-metric-phish:hover {{
        border-color: rgba(244, 63, 94, 0.5);
        box-shadow: 0 16px 35px -5px rgba(244, 63, 94, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-diverge {{
        border-left: 3px solid #f59e0b;
    }}
    .pg-metric-diverge .pg-metric-value {{
        color: #fbbf24;
        text-shadow: 0 0 20px rgba(245, 158, 11, 0.35);
    }}
    .pg-metric-diverge:hover {{
        border-color: rgba(245, 158, 11, 0.5);
        box-shadow: 0 16px 35px -5px rgba(245, 158, 11, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-prob {{
        border-left: 3px solid #06b6d4;
    }}
    .pg-metric-prob .pg-metric-value {{
        color: #22d3ee;
        text-shadow: 0 0 20px rgba(34, 211, 238, 0.35);
    }}
    .pg-metric-prob:hover {{
        border-color: rgba(6, 182, 212, 0.5);
        box-shadow: 0 16px 35px -5px rgba(6, 182, 212, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-ocr {{
        border-left: 3px solid #3b82f6;
    }}
    .pg-metric-ocr .pg-metric-value {{
        color: #60a5fa;
        text-shadow: 0 0 20px rgba(96, 165, 250, 0.35);
    }}
    .pg-metric-ocr:hover {{
        border-color: rgba(59, 130, 246, 0.5);
        box-shadow: 0 16px 35px -5px rgba(59, 130, 246, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-qr {{
        border-left: 3px solid #8b5cf6;
    }}
    .pg-metric-qr .pg-metric-value {{
        color: #a78bfa;
        text-shadow: 0 0 20px rgba(167, 139, 250, 0.35);
    }}
    .pg-metric-qr:hover {{
        border-color: rgba(139, 92, 246, 0.5);
        box-shadow: 0 16px 35px -5px rgba(139, 92, 246, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    .pg-metric-demo {{
        border-left: 3px solid #c084fc;
    }}
    .pg-metric-demo .pg-metric-value {{
        color: #e879f9;
        text-shadow: 0 0 20px rgba(232, 121, 249, 0.35);
    }}
    .pg-metric-demo:hover {{
        border-color: rgba(192, 132, 252, 0.5);
        box-shadow: 0 16px 35px -5px rgba(192, 132, 252, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }}

    /* Legacy metric box fallback */
    .pg-metric-box {{
        background: {bg_surface_alt};
        border: 1px solid {border_color};
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 8px 20px -4px rgba(0, 0, 0, 0.4);
        {anim_transition}
    }}

    .pg-metric-box:hover {{
        transform: translateY(-2px);
        border-color: {border_hover};
    }}

    /* Recent Scan Feed Rows */
    .pg-feed-row {{
        background: rgba(15, 23, 42, 0.55);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        padding: 0.65rem 0.85rem;
        margin-bottom: 0.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        {anim_transition}
    }}
    .pg-feed-row:hover {{
        background: rgba(26, 38, 66, 0.7);
        border-color: rgba(56, 189, 248, 0.25);
        transform: translateX(3px);
    }}

    /* Pipeline Stepper Container */
    .pg-pipeline-container {{
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: center;
        gap: 0.4rem;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(10, 16, 32, 0.9) 100%);
        border: 1px solid {border_color};
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 0.85rem 1.15rem;
        margin: 1.25rem 0;
        box-shadow: 0 8px 24px -4px rgba(0, 0, 0, 0.5);
    }}

    .pg-pipeline-step {{
        font-size: 0.72rem;
        font-weight: 600;
        padding: 0.25rem 0.55rem;
        border-radius: 6px;
        background: rgba(56, 189, 248, 0.12);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.3);
    }}

    .pg-pipeline-arrow {{
        color: {text_muted};
        font-size: 0.8rem;
    }}

    /* Result Card Styles - 3D Glow Surfaces */
    .pg-result-safe {{
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.14) 0%, rgba(10, 20, 36, 0.95) 100%);
        border: 1.5px solid #10b981;
        border-top: 1.5px solid rgba(16, 185, 129, 0.8);
        border-radius: 14px;
        padding: 1.75rem;
        box-shadow: 0 15px 40px -5px rgba(16, 185, 129, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }}

    .pg-result-suspicious {{
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.14) 0%, rgba(10, 20, 36, 0.95) 100%);
        border: 1.5px solid #f59e0b;
        border-top: 1.5px solid rgba(245, 158, 11, 0.8);
        border-radius: 14px;
        padding: 1.75rem;
        box-shadow: 0 15px 40px -5px rgba(245, 158, 11, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }}

    .pg-result-phishing {{
        background: linear-gradient(135deg, rgba(244, 63, 94, 0.18) 0%, rgba(15, 10, 24, 0.96) 100%);
        border: 1.5px solid #f43f5e;
        border-top: 1.5px solid rgba(244, 63, 94, 0.85);
        border-radius: 14px;
        padding: 1.75rem;
        box-shadow: 0 15px 45px -5px rgba(244, 63, 94, 0.32), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }}

    /* Pulsing animations */
    @keyframes pulse-glow {{
        0% {{ box-shadow: 0 0 12px rgba(56, 189, 248, 0.15); }}
        50% {{ box-shadow: 0 0 30px rgba(0, 240, 255, 0.35); }}
        100% {{ box-shadow: 0 0 12px rgba(56, 189, 248, 0.15); }}
    }}

    .pg-glow {{
        {anim_pulse}
    }}

    /* Streamlit Sidebar Overrides */
    div[data-testid="stSidebarNav"] {{
        display: none !important;
    }}

    section[data-testid="stSidebar"] {{
        background: linear-gradient(180deg, #090e1a 0%, #050811 100%) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.15) !important;
        box-shadow: 4px 0 25px rgba(0, 0, 0, 0.5) !important;
    }}

    /* Dimensional Navigation Radio Buttons */
    div[data-testid="stRadio"] > div[role="radiogroup"] > label {{
        background: rgba(15, 23, 42, 0.55);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 8px;
        padding: 0.45rem 0.75rem;
        margin-bottom: 0.3rem;
        {anim_transition}
    }}
    div[data-testid="stRadio"] > div[role="radiogroup"] > label:hover {{
        background: rgba(28, 41, 71, 0.7);
        border-color: rgba(56, 189, 248, 0.35);
        transform: translateX(3px);
    }}

    /* Metrics override */
    div[data-testid="stMetricValue"] {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1.6rem !important;
    }}

    /* Streamlit Button Styling - 3D Glossy Cyber Action */
    .stButton>button {{
        border-radius: 9px;
        font-weight: 600;
        letter-spacing: 0.02em;
        background: linear-gradient(135deg, rgba(20, 32, 58, 0.9) 0%, rgba(13, 22, 42, 0.9) 100%);
        border: 1px solid rgba(56, 189, 248, 0.28);
        border-top: 1px solid rgba(255, 255, 255, 0.18);
        color: #f8fafc;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        {anim_transition}
    }}

    .stButton>button:hover {{
        border-color: {accent_cyan};
        box-shadow: 0 6px 20px rgba(0, 240, 255, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        transform: translateY(-2px);
        color: #ffffff;
    }}

    .stButton>button:active {{
        transform: translateY(1px);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
    }}

    /* Primary Scan Buttons */
    .stButton>button[kind="primary"] {{
        background: linear-gradient(135deg, #0284c7 0%, #2563eb 50%, #4f46e5 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.6) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.35) !important;
        color: #ffffff !important;
        box-shadow: 0 6px 22px rgba(14, 165, 233, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
    }}

    .stButton>button[kind="primary"]:hover {{
        box-shadow: 0 8px 30px rgba(0, 240, 255, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.35) !important;
        transform: translateY(-2px);
    }}

    /* Expanders styling */
    div[data-testid="stExpander"] {{
        background: rgba(13, 21, 38, 0.55) !important;
        border: 1px solid rgba(56, 189, 248, 0.16) !important;
        border-radius: 10px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3) !important;
    }}

    /* Text Inputs styling */
    div[data-testid="stTextInput"] input {{
        background: rgba(11, 18, 35, 0.8) !important;
        border: 1px solid rgba(56, 189, 248, 0.25) !important;
        border-radius: 8px !important;
        color: #f8fafc !important;
        font-family: 'JetBrains Mono', monospace !important;
        box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.4) !important;
        {anim_transition}
    }}

    div[data-testid="stTextInput"] input:focus {{
        border-color: {accent_cyan} !important;
        box-shadow: 0 0 15px rgba(0, 240, 255, 0.35), inset 0 2px 6px rgba(0, 0, 0, 0.4) !important;
    }}
    </style>
    """
