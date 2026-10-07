"""
Threat Intelligence Service for PhishGuard AI.
Wraps passive network reconnaissance: DNS resolution, SSL/TLS certificate inspection,
WHOIS domain age, and optional VirusTotal reputation queries.
Transparently communicates module availability without fabricating live results.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlparse
from src.threat_intelligence import (
    collect_threat_intelligence,
    get_dns_records,
    get_ssl_info,
    get_whois_info,
    query_reputation_api,
)
from src.config import (
    THREAT_INTEL_ENABLED,
    REPUTATION_API_KEY,
    DNS_ENABLED,
    WHOIS_ENABLED,
    SSL_ENABLED,
)
from src.utils import setup_logger

logger = setup_logger("ThreatIntelService")


class ThreatIntelService:
    """
    Manages passive network threat intelligence collection.
    Reports operational status honestly without fabricating findings.
    """

    def __init__(self):
        pass

    def get_service_status(self) -> Dict[str, Any]:
        """
        Reports live availability status for passive reconnaissance channels.
        """
        rep_status = "READY" if (THREAT_INTEL_ENABLED and REPUTATION_API_KEY) else "NOT CONFIGURED"
        dns_status = "READY" if DNS_ENABLED else "DISABLED"
        ssl_status = "READY" if SSL_ENABLED else "DISABLED"
        whois_status = "READY" if WHOIS_ENABLED else "DISABLED"

        overall = "AVAILABLE" if (DNS_ENABLED or SSL_ENABLED or WHOIS_ENABLED or rep_status == "READY") else "NOT CONFIGURED"

        return {
            "overall_status": overall,
            "reputation_api": rep_status,
            "dns_probing": dns_status,
            "ssl_inspection": ssl_status,
            "whois_lookup": whois_status,
            "api_key_configured": bool(REPUTATION_API_KEY),
        }

    def inspect_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Gathers passive network intelligence for a candidate URL.
        Guarantees zero crashes and graceful degradation.
        """
        status = self.get_service_status()
        if status["overall_status"] == "NOT CONFIGURED":
            return {
                "status": "not_configured",
                "message": "Threat intelligence services are not configured or disabled.",
                "domain": urlparse(raw_url).hostname or "",
                "dns": {"status": "disabled"},
                "ssl": {"status": "disabled"},
                "whois": {"status": "disabled"},
                "reputation": {"status": "not_configured"},
                "reputation_positives": 0
            }

        try:
            return collect_threat_intelligence(raw_url)
        except Exception as e:
            logger.error(f"Threat intelligence query error: {e}")
            return {
                "status": "error",
                "message": f"Threat intelligence lookup encountered an error: {str(e)}",
                "domain": urlparse(raw_url).hostname or "",
                "dns": {"status": "error", "error": str(e)},
                "ssl": {"status": "error", "error": str(e)},
                "whois": {"status": "error", "error": str(e)},
                "reputation": {"status": "error", "message": str(e)},
                "reputation_positives": 0
            }
