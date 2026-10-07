"""
Threat Intelligence module for PhishGuard AI.
Performs passive domain network reconnaissance: DNS resolution, WHOIS registration,
SSL/TLS certificate inspection, and optional reputation API query.
Designed with strict timeouts, zero arbitrary navigation, and graceful failure handling.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import requests

from src.config import (
    DNS_ENABLED,
    WHOIS_ENABLED,
    SSL_ENABLED,
    THREAT_INTEL_ENABLED,
    REPUTATION_API_KEY,
    NETWORK_TIMEOUT_SECONDS,
)
from src.utils import setup_logger, normalize_url

logger = setup_logger("ThreatIntelligence")


def get_dns_records(domain: str, timeout: int = NETWORK_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Performs passive DNS lookups for IP addresses (A/AAAA) and MX records.
    """
    if not DNS_ENABLED:
        return {"status": "disabled", "message": "DNS queries disabled by configuration."}

    results = {
        "status": "unavailable",
        "ip_addresses": [],
        "mx_records": [],
        "error": None
    }

    try:
        # Standard socket getaddrinfo
        socket.setdefaulttimeout(timeout)
        addr_info = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set([item[4][0] for item in addr_info]))
        results["ip_addresses"] = ips
        results["status"] = "available" if ips else "empty"
    except socket.gaierror as e:
        results["error"] = f"Domain could not be resolved (NXDOMAIN or DNS error): {e}"
        results["status"] = "unresolved"
    except Exception as e:
        results["error"] = f"DNS lookup timed out or failed: {e}"
        results["status"] = "error"

    # Optional MX records using dnspython if installed
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        mx_answers = resolver.resolve(domain, "MX")
        results["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        pass  # Graceful fallback if dnspython resolution is absent or times out

    return results


def get_ssl_info(domain: str, port: int = 443, timeout: int = NETWORK_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Connects to the TLS port and inspects the peer certificate without downloading web content.
    """
    if not SSL_ENABLED:
        return {"status": "disabled", "message": "SSL verification disabled by configuration."}

    results = {
        "status": "unavailable",
        "issuer": None,
        "subject": None,
        "version": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "is_expired": None,
        "error": None
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    results["error"] = "No certificate returned by peer."
                    return results

                # Extract Issuer and Subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                subject_dict = dict(x[0] for x in cert.get("subject", []))

                results["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
                results["subject"] = subject_dict.get("commonName") or "Unknown"
                results["version"] = cert.get("version")

                # Expiration calculation
                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")

                if not_after_str:
                    # e.g. 'May 15 12:00:00 2025 GMT'
                    expiry_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    results["valid_until"] = expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                    now = datetime.now(timezone.utc)
                    days_left = (expiry_date - now).days
                    results["days_until_expiry"] = days_left
                    results["is_expired"] = days_left < 0

                if not_before_str:
                    start_date = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    results["valid_from"] = start_date.strftime("%Y-%m-%d %H:%M:%S UTC")

                results["status"] = "available"

    except ssl.SSLCertVerificationError as e:
        results["status"] = "invalid_cert"
        results["error"] = f"SSL Certificate Verification Failed: {e}"
        results["is_expired"] = True
    except Exception as e:
        results["status"] = "error"
        results["error"] = f"SSL probe failed or connection timed out: {e}"

    return results


def get_whois_info(domain: str, timeout: int = NETWORK_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Extracts registration dates, registrar, and calculated domain age.
    """
    if not WHOIS_ENABLED:
        return {"status": "disabled", "message": "WHOIS disabled by configuration."}

    results = {
        "status": "unavailable",
        "registrar": None,
        "creation_date": None,
        "domain_age_days": None,
        "country": None,
        "error": None
    }

    try:
        import whois
        w = whois.whois(domain)

        if not w:
            results["status"] = "not_found"
            return results

        results["registrar"] = getattr(w, "registrar", None)
        results["country"] = getattr(w, "country", None)

        cdate = getattr(w, "creation_date", None)
        if isinstance(cdate, list):
            cdate = cdate[0] if cdate else None

        if isinstance(cdate, datetime):
            now = datetime.now(timezone.utc) if cdate.tzinfo else datetime.now()
            age_days = (now - cdate).days
            results["creation_date"] = cdate.strftime("%Y-%m-%d")
            results["domain_age_days"] = max(0, age_days)

        results["status"] = "available" if (results["registrar"] or results["creation_date"]) else "unavailable"

    except Exception as e:
        results["status"] = "error"
        results["error"] = f"WHOIS query failed or timed out: {e}"

    return results


def query_reputation_api(domain_or_url: str, timeout: int = NETWORK_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Queries VirusTotal API v3 if API key is configured.
    Falls back gracefully if not configured or offline.
    """
    if not THREAT_INTEL_ENABLED or not REPUTATION_API_KEY:
        return {
            "status": "not_configured",
            "message": "Reputation API not configured. Set REPUTATION_API_KEY and THREAT_INTEL_ENABLED=true in .env to enable.",
            "positives": 0,
            "total_engines": 0
        }

    try:
        import base64
        # Format URL ID according to VirusTotal API v3 specification
        url_id = base64.urlsafe_b64encode(domain_or_url.encode()).decode().strip("=")
        headers = {"x-apikey": REPUTATION_API_KEY}
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(endpoint, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "status": "available",
                "positives": positives,
                "total_engines": total,
                "stats": stats
            }
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "message": "URL not found in threat intelligence database.",
                "positives": 0
            }
        else:
            return {
                "status": "error",
                "message": f"API returned HTTP status {response.status_code}",
                "positives": 0
            }
    except Exception as e:
        logger.warning(f"Reputation API lookup error: {e}")
        return {
            "status": "error",
            "message": f"Reputation service query failed: {e}",
            "positives": 0
        }


def collect_threat_intelligence(raw_url: str) -> Dict[str, Any]:
    """
    Consolidated helper collecting all available passive domain intelligence signals.
    """
    normalized, _, _ = normalize_url(raw_url)
    parsed = urlparse(normalized)
    domain = parsed.hostname or ""

    if not domain:
        return {"status": "error", "message": "No valid domain extracted."}

    dns_res = get_dns_records(domain)
    ssl_res = get_ssl_info(domain, port=parsed.port or 443)
    whois_res = get_whois_info(domain)
    rep_res = query_reputation_api(normalized)

    return {
        "status": "success",
        "domain": domain,
        "dns": dns_res,
        "ssl": ssl_res,
        "whois": whois_res,
        "reputation": rep_res,
        "reputation_positives": rep_res.get("positives", 0)
    }
