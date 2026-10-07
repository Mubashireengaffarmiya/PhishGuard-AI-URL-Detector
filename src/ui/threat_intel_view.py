"""
Threat Intelligence Console View for PhishGuard AI.
Provides passive network reconnaissance: DNS resolution, SSL/TLS certificate
inspection, WHOIS registration timeline, and VirusTotal reputation API querying.
Never fabricates results; reports configuration states with technical honesty.
"""

from typing import Dict, Any, Optional
import streamlit as st

from src.services.threat_intelligence_service import ThreatIntelService
from src.ui.components import render_status_badge


def render_threat_intel_view(threat_intel_service: ThreatIntelService):
    """Renders the passive threat intelligence console."""
    st.markdown("### 🌐 Passive Threat Intelligence Console")
    st.caption("Perform passive domain reconnaissance without downloading HTML payloads or executing client scripts.")

    status = threat_intel_service.get_service_status()

    # Status Overview Header
    st.markdown("#### 📡 Reconnaissance Subsystems")
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"**Overall**: {render_status_badge(status['overall_status'])}", unsafe_allow_html=True)
    c2.markdown(f"**DNS Probing**: {render_status_badge(status['dns_probing'])}", unsafe_allow_html=True)
    c3.markdown(f"**SSL/TLS Check**: {render_status_badge(status['ssl_inspection'])}", unsafe_allow_html=True)
    c4.markdown(f"**Reputation API**: {render_status_badge(status['reputation_api'])}", unsafe_allow_html=True)

    st.markdown("---")

    # Domain Probing Form
    st.markdown("#### 🔎 Query Domain Intelligence")
    with st.container():
        tc1, tc2 = st.columns([8, 2])
        domain_input = tc1.text_input(
            "Target Domain or URL",
            placeholder="e.g. google.com or https://paypal.com/signin",
            label_visibility="collapsed"
        )
        run_intel = tc2.button("Run Recon", type="primary", use_container_width=True)

    if run_intel and domain_input.strip():
        with st.spinner("Querying DNS records, inspecting SSL certificate, and checking registration..."):
            intel_res = threat_intel_service.inspect_url(domain_input.strip())
            st.session_state["active_intel_res"] = intel_res

    if "active_intel_res" in st.session_state and st.session_state["active_intel_res"]:
        res = st.session_state["active_intel_res"]
        st.markdown(f"### Results for: `{res.get('domain')}`")

        c_dns, c_ssl = st.columns(2)
        with c_dns:
            st.markdown("##### 📍 DNS Resolution")
            dns = res.get("dns", {})
            if dns.get("status") == "available":
                st.write("**Resolved IP Addresses:**", ", ".join(dns.get("ip_addresses", [])) or "None")
                if dns.get("mx_records"):
                    st.write("**MX Mail Servers:**", ", ".join(dns.get("mx_records", [])))
            elif dns.get("status") == "unresolved":
                st.warning(f"NXDOMAIN / Unresolved: {dns.get('error')}")
            else:
                st.caption(f"Status: {dns.get('status')} &bull; {dns.get('error', dns.get('message'))}")

        with c_ssl:
            st.markdown("##### 🔒 SSL/TLS Certificate")
            ssl_info = res.get("ssl", {})
            if ssl_info.get("status") == "available":
                st.write("**Issuer Organization:**", ssl_info.get("issuer"))
                st.write("**Common Name Subject:**", ssl_info.get("subject"))
                st.write("**Valid Until:**", ssl_info.get("valid_until"))
                days = ssl_info.get("days_until_expiry")
                if days is not None:
                    if days < 0:
                        st.error(f"🔴 Certificate Expired ({abs(days)} days ago)")
                    elif days < 30:
                        st.warning(f"🟠 Expiring Soon ({days} days remaining)")
                    else:
                        st.success(f"🟢 Certificate Valid ({days} days remaining)")
            else:
                st.caption(f"Status: {ssl_info.get('status')} &bull; {ssl_info.get('error', ssl_info.get('message'))}")

        c_whois, c_rep = st.columns(2)
        with c_whois:
            st.markdown("##### 📜 WHOIS Registration")
            whois_info = res.get("whois", {})
            if whois_info.get("status") == "available":
                st.write("**Registrar:**", whois_info.get("registrar") or "Unknown")
                st.write("**Country:**", whois_info.get("country") or "Unknown")
                st.write("**Creation Date:**", whois_info.get("creation_date") or "Unknown")
                age = whois_info.get("domain_age_days")
                if age is not None:
                    st.write(f"**Domain Age:** {age:,} days ({age // 365} years)")
            else:
                st.caption(f"Status: {whois_info.get('status')} &bull; {whois_info.get('error', whois_info.get('message'))}")

        with c_rep:
            st.markdown("##### 🛡️ Reputation Threat Database")
            rep = res.get("reputation", {})
            if rep.get("status") == "available":
                pos = rep.get("positives", 0)
                tot = rep.get("total_engines", 0)
                if pos > 0:
                    st.error(f"🚨 {pos} / {tot} Security Engines Flagged This URL as Malicious")
                else:
                    st.success(f"✅ Clean: 0 / {tot} Security Engines Flagged This URL")
            else:
                st.info(f"ℹ️ {rep.get('message', 'Reputation lookup not configured.')}")
