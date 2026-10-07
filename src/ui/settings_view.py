"""
Settings & Privacy Configuration View for PhishGuard AI.
User-customizable options for UI themes, animation preferences,
privacy redaction defaults, AI providers, and network threat intelligence.
"""

from typing import Dict, Any
import streamlit as st
import os


def render_settings_view():
    """Renders the settings and privacy configuration console."""
    st.markdown("### ⚙️ System Settings & Privacy Controls")
    st.caption("Manage application themes, privacy redaction rules, AI assistant providers, and network probing preferences.")

    # 1. Appearance & Aesthetics
    st.markdown("#### 🎨 Appearance & UI Theme")
    c_theme, c_anim = st.columns(2)

    with c_theme:
        current_theme = st.session_state.get("theme", "Cyber Dark")
        theme_choice = st.radio(
            "Select Dashboard Visual Theme",
            options=["Cyber Dark", "Clean Light"],
            index=0 if current_theme == "Cyber Dark" else 1,
            help="Cyber Dark provides the SOC console aesthetic; Clean Light provides high-contrast daylight visibility."
        )
        if theme_choice != current_theme:
            st.session_state["theme"] = theme_choice
            st.rerun()

    with c_anim:
        current_anim = st.session_state.get("animations_enabled", True)
        anim_choice = st.checkbox(
            "Enable Cyber UI Animations & Glowing Effects",
            value=current_anim,
            help="Disable if working on low-power devices or when reduced-motion accessibility is preferred."
        )
        if anim_choice != current_anim:
            st.session_state["animations_enabled"] = anim_choice
            st.rerun()

    st.markdown("---")

    # 2. Privacy & Redaction Settings
    st.markdown("#### 🛡️ Privacy & URL Redaction Policy")
    current_priv = st.session_state.get("privacy_mode", "SHOW_ALL")
    priv_choice = st.selectbox(
        "Default URL Redaction Level for History & Reports",
        options=[
            ("SHOW_ALL", "Show Full URL (No redaction)"),
            ("MASK_PATH", "Mask Destination Path (e.g., https://example.com/***)"),
            ("MASK_QUERY", "Mask Query Parameters (e.g., https://example.com/login?***)"),
            ("MASK_ALL", "Mask Host & Path (e.g., https://ex***le.com/***)")
        ],
        format_func=lambda x: x[1],
        index=0 if current_priv == "SHOW_ALL" else (1 if current_priv == "MASK_PATH" else (2 if current_priv == "MASK_QUERY" else 3))
    )
    if priv_choice[0] != current_priv:
        st.session_state["privacy_mode"] = priv_choice[0]
        st.success(f"Default privacy mode updated to: {priv_choice[1]}")

    st.markdown("---")

    # 3. AI Assistant Configuration
    st.markdown("#### 🤖 AI Security Analyst Provider")
    st.caption("Select your preferred AI explanation engine. The Rule-Based Expert System is enabled by default and requires zero internet connection or API keys.")

    current_provider = os.getenv("AI_PROVIDER", "Rule-Based Expert Fallback")
    ai_choice = st.selectbox(
        "Active AI Provider",
        options=["Rule-Based Expert Fallback", "OpenAI", "Anthropic Claude", "Google Gemini", "Ollama Local"],
        index=0
    )

    if ai_choice != "Rule-Based Expert Fallback":
        st.info(f"To configure {ai_choice}, ensure the appropriate API key environment variable is populated in `.env`.")
        key_name = f"{ai_choice.upper().replace(' ', '_')}_API_KEY"
        key_val = st.text_input(f"{key_name} (Session Value)", type="password", placeholder="Paste API key here")
        if key_val:
            os.environ[key_name] = key_val
            st.success(f"{key_name} configured for this session.")
    else:
        st.success("✅ Rule-Based Expert System Active (100% offline, deterministic, zero third-party data transmission).")

    st.markdown("---")

    # 4. Network Threat Intelligence Controls
    st.markdown("#### 🌐 Network Threat Intelligence Settings")
    st.caption("Enable or disable active network probing during URL evaluations.")

    dns_val = st.checkbox("Enable Passive DNS Resolution", value=True)
    ssl_val = st.checkbox("Enable SSL/TLS Certificate Probing", value=True)
    whois_val = st.checkbox("Enable WHOIS Domain Registration Queries", value=True)

    vt_key = st.text_input("VirusTotal API Key (Optional)", type="password", placeholder="Leave blank if not using reputation API")
    if vt_key:
        os.environ["REPUTATION_API_KEY"] = vt_key
        os.environ["THREAT_INTEL_ENABLED"] = "true"
        st.success("VirusTotal API key configured.")
