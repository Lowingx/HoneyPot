"""
detection.py — Classification & Enrichment Engine
====================================================
Handles:
  - attack_type classification
  - tool fingerprinting
  - severity scoring
  - GeoIP / ASN enrichment (optional, requires MaxMind GeoLite2)
  - multi-service correlation

This module has zero required external dependencies.
GeoIP enrichment activates automatically if 'geoip2' is installed
and the .mmdb database files are present.
"""

from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────
#  Optional GeoIP support
# ─────────────────────────────────────────────

try:
    import geoip2.database  # type: ignore
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


# ─────────────────────────────────────────────
#  Attack type classification
# ─────────────────────────────────────────────

# Attack types in order of specificity (most specific first)
ATTACK_TYPES = (
    "brute_force",        # repeated credential attempts
    "credential_attempt", # single credential attempt
    "vuln_scan",          # probing for known vulnerabilities
    "recon",              # passive enumeration / discovery
    "automation_tool",    # automated tool detected (generic)
)

# HTTP paths that indicate vulnerability scanning
VULN_SCAN_PATHS = {
    "/.env", "/.git/config", "/.git/HEAD", "/config.php", "/wp-config.php",
    "/phpmyadmin", "/myadmin", "/pma", "/xmlrpc.php", "/wp-login.php",
    "/adminer.php", "/server-status", "/server-info", "/.htaccess",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/shell.php", "/cmd.php", "/webshell.php", "/c99.php", "/r57.php",
    "/cgi-bin/test.cgi", "/cgi-bin/env.cgi",
}

# HTTP paths that indicate directory recon
RECON_PATHS = {
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
}


def classify_attack(event: dict, ip_history: dict) -> str:
    """
    Determine the attack_type for a single event given the IP's history.

    Parameters
    ----------
    event       : the current event dict
    ip_history  : dict mapping src_ip -> list of past events for that IP

    Returns
    -------
    One of: brute_force | credential_attempt | vuln_scan | recon | automation_tool
    """
    service    = event.get("service", "")
    event_type = event.get("event_type", "")
    src_ip     = event.get("src_ip", "")
    path       = event.get("path", "")
    username   = event.get("username", "")

    past = ip_history.get(src_ip, [])
    past_auth_attempts = sum(
        1 for e in past
        if e.get("event_type") in ("auth_attempt", "http_request")
        and (e.get("username") or e.get("password"))
    )

    # SSH auth attempts
    if service == "ssh" and event_type == "auth_attempt":
        if past_auth_attempts >= 3:
            return "brute_force"
        return "credential_attempt"

    # HTTP requests
    if service == "http" and event_type == "http_request":
        method = event.get("method", "")

        if username:  # POST with credentials
            if past_auth_attempts >= 3:
                return "brute_force"
            return "credential_attempt"

        if path in VULN_SCAN_PATHS:
            return "vuln_scan"

        if path in RECON_PATHS:
            return "recon"

        # Many 404s from same IP = directory scanning (recon)
        past_404s = sum(1 for e in past if e.get("event_type") == "http_request")
        if past_404s >= 5:
            return "recon"

        # Unusual HTTP methods
        if method in ("PUT", "DELETE", "TRACE", "CONNECT", "OPTIONS"):
            return "vuln_scan"

    return "automation_tool"


# ─────────────────────────────────────────────
#  Tool fingerprinting
# ─────────────────────────────────────────────

@dataclass
class ToolSignature:
    name: str
    category: str   # scanner | exploit_framework | bruteforce | crawler | unknown
    risk: str       # low | medium | high

# Ordered: more specific patterns first
TOOL_SIGNATURES: list[tuple[re.Pattern, ToolSignature]] = [
    # Security scanners
    (re.compile(r"Nuclei", re.I),
        ToolSignature("Nuclei", "scanner", "high")),
    (re.compile(r"Nikto", re.I),
        ToolSignature("Nikto", "scanner", "high")),
    (re.compile(r"sqlmap", re.I),
        ToolSignature("sqlmap", "exploit_framework", "high")),
    (re.compile(r"WPScan", re.I),
        ToolSignature("WPScan", "scanner", "medium")),
    (re.compile(r"dirsearch", re.I),
        ToolSignature("dirsearch", "scanner", "medium")),
    (re.compile(r"gobuster", re.I),
        ToolSignature("gobuster", "scanner", "medium")),
    (re.compile(r"masscan", re.I),
        ToolSignature("masscan", "scanner", "high")),
    (re.compile(r"nmap", re.I),
        ToolSignature("nmap", "scanner", "medium")),
    (re.compile(r"ZmEu", re.I),
        ToolSignature("ZmEu", "exploit_framework", "high")),
    (re.compile(r"Metasploit", re.I),
        ToolSignature("Metasploit", "exploit_framework", "high")),
    (re.compile(r"zgrab", re.I),
        ToolSignature("zgrab", "scanner", "medium")),
    (re.compile(r"Shodan", re.I),
        ToolSignature("Shodan", "scanner", "low")),
    (re.compile(r"censys", re.I),
        ToolSignature("Censys", "scanner", "low")),
    # SSH client libraries (seen in brute force tools)
    (re.compile(r"libssh[_/](\S+)", re.I),
        ToolSignature("libssh", "bruteforce", "high")),
    (re.compile(r"Paramiko[_/](\S+)", re.I),
        ToolSignature("Paramiko", "bruteforce", "medium")),
    (re.compile(r"SSH-2\.0-Go\b", re.I),
        ToolSignature("Go SSH client", "bruteforce", "medium")),
    (re.compile(r"SSH-2\.0-JSCH", re.I),
        ToolSignature("JSch (Java)", "bruteforce", "medium")),
    (re.compile(r"SSH-2\.0-AsyncSSH", re.I),
        ToolSignature("AsyncSSH (Python)", "bruteforce", "medium")),
    # Generic automation
    (re.compile(r"python-requests/(\S+)", re.I),
        ToolSignature("python-requests", "crawler", "medium")),
    (re.compile(r"curl/(\S+)", re.I),
        ToolSignature("curl", "crawler", "low")),
    (re.compile(r"Go-http-client", re.I),
        ToolSignature("Go HTTP client", "crawler", "medium")),
    (re.compile(r"axios", re.I),
        ToolSignature("axios (Node.js)", "crawler", "low")),
    (re.compile(r"Wget/(\S+)", re.I),
        ToolSignature("wget", "crawler", "low")),
]


def fingerprint_tool(event: dict) -> Optional[ToolSignature]:
    """
    Identify the tool used based on User-Agent (HTTP) or client_banner (SSH).
    Returns a ToolSignature or None.
    """
    candidates = [
        event.get("user_agent", ""),
        event.get("client_banner", ""),
    ]
    for text in candidates:
        if not text:
            continue
        for pattern, sig in TOOL_SIGNATURES:
            if pattern.search(text):
                return sig
    return None


# ─────────────────────────────────────────────
#  Severity scoring
# ─────────────────────────────────────────────

# (attack_type, tool_risk, multi_service) -> severity
_SEVERITY_MATRIX = {
    # brute_force with any multi-service = CRITICAL
    ("brute_force",        "high",   True):  "CRITICAL",
    ("brute_force",        "high",   False): "CRITICAL",
    ("brute_force",        "medium", True):  "CRITICAL",
    ("brute_force",        "medium", False): "HIGH",
    ("brute_force",        "low",    True):  "HIGH",
    ("brute_force",        "low",    False): "HIGH",
    ("brute_force",        None,     True):  "HIGH",
    ("brute_force",        None,     False): "HIGH",
    # credential_attempt
    ("credential_attempt", "high",   True):  "HIGH",
    ("credential_attempt", "high",   False): "HIGH",
    ("credential_attempt", "medium", True):  "HIGH",
    ("credential_attempt", "medium", False): "MEDIUM",
    ("credential_attempt", "low",    True):  "MEDIUM",
    ("credential_attempt", "low",    False): "MEDIUM",
    ("credential_attempt", None,     True):  "MEDIUM",
    ("credential_attempt", None,     False): "MEDIUM",
    # vuln_scan
    ("vuln_scan",          "high",   True):  "HIGH",
    ("vuln_scan",          "high",   False): "HIGH",
    ("vuln_scan",          "medium", True):  "HIGH",
    ("vuln_scan",          "medium", False): "MEDIUM",
    ("vuln_scan",          "low",    True):  "MEDIUM",
    ("vuln_scan",          "low",    False): "LOW",
    ("vuln_scan",          None,     True):  "MEDIUM",
    ("vuln_scan",          None,     False): "LOW",
    # recon
    ("recon",              "high",   True):  "MEDIUM",
    ("recon",              "high",   False): "LOW",
    ("recon",              "medium", True):  "LOW",
    ("recon",              "medium", False): "LOW",
    ("recon",              "low",    True):  "LOW",
    ("recon",              "low",    False): "INFO",
    ("recon",              None,     True):  "LOW",
    ("recon",              None,     False): "INFO",
    # automation_tool (fallback)
    ("automation_tool",    "high",   True):  "MEDIUM",
    ("automation_tool",    "high",   False): "LOW",
    ("automation_tool",    "medium", True):  "LOW",
    ("automation_tool",    "medium", False): "INFO",
    ("automation_tool",    "low",    True):  "INFO",
    ("automation_tool",    "low",    False): "INFO",
    ("automation_tool",    None,     True):  "INFO",
    ("automation_tool",    None,     False): "INFO",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def score_severity(
    attack_type: str,
    tool_sig: Optional[ToolSignature],
    multi_service: bool,
) -> str:
    """
    Determine severity from attack_type + tool risk + multi-service flag.
    Falls back to INFO for unknown combinations.
    """
    tool_risk = tool_sig.risk if tool_sig else None
    return _SEVERITY_MATRIX.get(
        (attack_type, tool_risk, multi_service),
        "INFO"
    )


# ─────────────────────────────────────────────
#  GeoIP enrichment
# ─────────────────────────────────────────────

@dataclass
class GeoInfo:
    country:          str = "Unknown"
    country_code:     str = "??"
    city:             str = "Unknown"
    asn:              str = "Unknown"
    org:              str = "Unknown"
    is_private:       bool = False


def _is_private(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


class GeoIPEnricher:
    """
    Optional GeoIP enrichment using MaxMind GeoLite2.

    Setup (free):
      1. Register at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
      2. Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb
      3. Place them in the 'geoip/' directory or set GEOIP_DIR env var

    If geoip2 is not installed or files are missing, returns GeoInfo defaults.
    """

    def __init__(self, city_db: Optional[str] = None, asn_db: Optional[str] = None):
        self._city_reader = None
        self._asn_reader  = None

        if not _GEOIP2_AVAILABLE:
            return

        try:
            if city_db:
                self._city_reader = geoip2.database.Reader(city_db)
        except Exception:
            pass

        try:
            if asn_db:
                self._asn_reader = geoip2.database.Reader(asn_db)
        except Exception:
            pass

    @property
    def available(self) -> bool:
        return self._city_reader is not None or self._asn_reader is not None

    def lookup(self, ip_str: str) -> GeoInfo:
        info = GeoInfo()

        if _is_private(ip_str):
            info.is_private = True
            info.country    = "Private"
            info.org        = "Private Network"
            return info

        if self._city_reader:
            try:
                r = self._city_reader.city(ip_str)
                info.country      = r.country.name or "Unknown"
                info.country_code = r.country.iso_code or "??"
                info.city         = (r.city.name or "Unknown")
            except Exception:
                pass

        if self._asn_reader:
            try:
                r = self._asn_reader.asn(ip_str)
                info.asn = f"AS{r.autonomous_system_number}"
                info.org = r.autonomous_system_organization or "Unknown"
            except Exception:
                pass

        return info

    def close(self):
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
