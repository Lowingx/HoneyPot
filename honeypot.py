#!/usr/bin/env python3
"""
Honeypot v2 — Threat Detection & Analysis System
==================================================
Simulates SSH and HTTP services to capture attacker behavior.
Every event is enriched with:
  - attack_type classification
  - tool fingerprinting
  - severity scoring
  - GeoIP / ASN data (optional)
  - multi-service correlation

Output: structured JSONL (one JSON object per line).

Blue Team Portfolio — Project 2 (Enhanced)
Author  : Blue Team Portfolio
License : MIT
"""

from __future__ import annotations

import asyncio
import json
import argparse
import signal
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from typing import Optional

from detection import (
    classify_attack,
    fingerprint_tool,
    score_severity,
    GeoIPEnricher,
    GeoInfo,
    SEVERITY_ORDER,
)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

HTTP_FAKE_LOGIN_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Admin Panel — Login</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#0057b7;color:#fff;border:none;cursor:pointer}</style>
</head>
<body>
<h2>Administration Login</h2>
<form method="POST" action="/login">
  <input type="text"     name="username" placeholder="Username" required>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit">Login</button>
</form>
</body>
</html>"""

HTTP_404 = ("<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
            "<body><h1>404 Not Found</h1></body></html>")

HTTP_401 = ("<!DOCTYPE html><html><head><title>401 Unauthorized</title></head>"
            "<body><h1>401 Unauthorized</h1><p>Invalid credentials.</p></body></html>")

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[37m",
}
RESET = "\033[0m"


# ─────────────────────────────────────────────
#  Event store (in-memory, for correlation)
# ─────────────────────────────────────────────

class EventStore:
    """
    Tracks recent events per IP for correlation purposes.
    Keeps only the last 200 events per IP to bound memory.
    """
    MAX_PER_IP = 200

    def __init__(self):
        self._history: dict[str, list] = defaultdict(list)
        self._services: dict[str, set] = defaultdict(set)   # ip -> {services seen}

    def add(self, event: dict) -> None:
        ip  = event.get("src_ip", "")
        svc = event.get("service", "")
        if ip:
            buf = self._history[ip]
            buf.append(event)
            if len(buf) > self.MAX_PER_IP:
                self._history[ip] = buf[-self.MAX_PER_IP:]
            if svc:
                self._services[ip].add(svc)

    def history(self, ip: str) -> list:
        return self._history.get(ip, [])

    def is_multi_service(self, ip: str) -> bool:
        """True if this IP has hit more than one honeypot service."""
        return len(self._services.get(ip, set())) > 1

    def services_seen(self, ip: str) -> list:
        return list(self._services.get(ip, set()))


# ─────────────────────────────────────────────
#  Structured JSONL logger
# ─────────────────────────────────────────────

class HoneypotLogger:
    """
    Writes enriched events to a .jsonl file (one JSON object per line).
    Optionally prints colored output to stdout.
    """

    def __init__(self, log_path: Path, verbose: bool = False):
        self.log_path = log_path
        self.verbose  = verbose
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(log_path, "a", encoding="utf-8", buffering=1)

    def write(self, event: dict) -> None:
        self._file.write(json.dumps(event, ensure_ascii=False) + "\n")

        if self.verbose:
            self._print_event(event)

    def _print_event(self, event: dict) -> None:
        sev   = event.get("severity", "INFO")
        color = SEVERITY_COLORS.get(sev, "")
        ts    = event.get("timestamp", "")[-14:-5]  # HH:MM:SS
        svc   = event.get("service", "?").upper()
        etype = event.get("event_type", "?")
        ip    = event.get("src_ip", "?")
        atype = event.get("attack_type", "")
        tool  = event.get("tool", "")
        geo   = event.get("geo", {})

        geo_str = ""
        if geo and geo.get("country") not in ("Unknown", "Private", None):
            geo_str = f" [{geo['country']} / {geo.get('asn', '?')}]"

        extra = ""
        if event.get("username"):
            extra += f" user={event['username']}"
        if event.get("password"):
            extra += f" pass={event['password'][:20]}"
        if event.get("method"):
            extra += f" {event['method']} {event.get('path', '')}"
        if tool:
            extra += f" tool={tool}"

        multi = " \033[95m[MULTI-SERVICE]\033[0m" if event.get("multi_service") else ""

        print(
            f"{color}[{ts}][{sev}][{svc}][{etype}]{RESET} "
            f"{ip}{geo_str}{extra}"
            f"{(' → ' + atype) if atype else ''}{multi}"
        )

    def close(self):
        self._file.close()


# ─────────────────────────────────────────────
#  Event builder
# ─────────────────────────────────────────────

def build_event(
    service: str,
    event_type: str,
    src_ip: str,
    src_port: int,
    store: EventStore,
    geo_enricher: GeoIPEnricher,
    **extra,
) -> dict:
    """
    Construct a fully enriched event dict.
    Classification and scoring happen here, after the raw data is collected.
    """
    event = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "service":    service,
        "event_type": event_type,
        "src_ip":     src_ip,
        "src_port":   src_port,
        **extra,
    }

    # Only classify meaningful events (not connect/disconnect)
    if event_type in ("auth_attempt", "http_request"):
        ip_history    = {src_ip: store.history(src_ip)}
        multi_service = store.is_multi_service(src_ip)
        attack_type   = classify_attack(event, ip_history)
        tool_sig      = fingerprint_tool(event)
        severity      = score_severity(attack_type, tool_sig, multi_service)

        event["attack_type"]   = attack_type
        event["severity"]      = severity
        event["multi_service"] = multi_service
        event["services_seen"] = store.services_seen(src_ip)

        if tool_sig:
            event["tool"]          = tool_sig.name
            event["tool_category"] = tool_sig.category
            event["tool_risk"]     = tool_sig.risk
    else:
        event["severity"] = "INFO"

    # GeoIP enrichment
    geo = geo_enricher.lookup(src_ip)
    event["geo"] = {
        "country":      geo.country,
        "country_code": geo.country_code,
        "city":         geo.city,
        "asn":          geo.asn,
        "org":          geo.org,
        "is_private":   geo.is_private,
    }

    return event


# ─────────────────────────────────────────────
#  SSH honeypot
# ─────────────────────────────────────────────

async def handle_ssh(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    logger: HoneypotLogger,
    store: EventStore,
    geo: GeoIPEnricher,
    delay: float,
) -> None:
    addr     = writer.get_extra_info("peername")
    src_ip   = addr[0] if addr else "unknown"
    src_port = addr[1] if addr else 0

    ev = build_event("ssh", "connect", src_ip, src_port, store, geo)
    store.add(ev)
    logger.write(ev)

    try:
        writer.write(SSH_BANNER)
        await writer.drain()

        client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
        client_banner_str = client_banner.decode(errors="replace").strip()

        raw = await asyncio.wait_for(reader.read(4096), timeout=15.0)

        printable = "".join(
            c for c in raw.decode(errors="replace")
            if c.isprintable() or c in " \t"
        )
        username = _extract_printable_word(printable, 0)
        password = _extract_printable_word(printable, 1)

        ev = build_event(
            "ssh", "auth_attempt", src_ip, src_port, store, geo,
            client_banner=client_banner_str,
            username=username or "(unknown)",
            password=password or "(unknown)",
            raw_bytes=len(raw),
        )
        store.add(ev)
        logger.write(ev)

        await asyncio.sleep(delay)

        # Send plausible failure response to keep scanner engaged
        writer.write(b"\x00" * 16)
        await writer.drain()

    except asyncio.TimeoutError:
        ev = build_event("ssh", "timeout", src_ip, src_port, store, geo)
        store.add(ev)
        logger.write(ev)
    except Exception as exc:
        ev = build_event("ssh", "error", src_ip, src_port, store, geo,
                         error=str(exc))
        store.add(ev)
        logger.write(ev)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        ev = build_event("ssh", "disconnect", src_ip, src_port, store, geo)
        store.add(ev)
        logger.write(ev)


def _extract_printable_word(text: str, index: int) -> str:
    words = [w for w in text.split() if len(w) >= 2]
    return words[index] if index < len(words) else ""


# ─────────────────────────────────────────────
#  HTTP honeypot
# ─────────────────────────────────────────────

def _http_response(status: str, body: str, extra_headers: str = "") -> bytes:
    body_bytes = body.encode()
    headers = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: Apache/2.4.52 (Ubuntu)\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"{extra_headers}"
        f"\r\n"
    )
    return headers.encode() + body_bytes


def _parse_form_body(body: str) -> dict:
    result = {}
    for pair in body.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            result[k.strip()] = v.strip()
    return result


async def handle_http(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    logger: HoneypotLogger,
    store: EventStore,
    geo: GeoIPEnricher,
) -> None:
    addr     = writer.get_extra_info("peername")
    src_ip   = addr[0] if addr else "unknown"
    src_port = addr[1] if addr else 0

    ev = build_event("http", "connect", src_ip, src_port, store, geo)
    store.add(ev)
    logger.write(ev)

    try:
        raw  = await asyncio.wait_for(reader.read(8192), timeout=10.0)
        text = raw.decode(errors="replace")

        lines    = text.split("\r\n")
        req_line = lines[0] if lines else ""
        parts    = req_line.split(" ")
        method   = parts[0] if len(parts) > 0 else "UNKNOWN"
        path     = parts[1] if len(parts) > 1 else "/"

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ": " in line:
                k, _, v = line.partition(": ")
                headers[k.lower()] = v

        body  = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        creds = _parse_form_body(body)

        ev = build_event(
            "http", "http_request", src_ip, src_port, store, geo,
            method=method,
            path=path,
            user_agent=headers.get("user-agent", ""),
            host=headers.get("host", ""),
            content_length=headers.get("content-length", "0"),
            username=creds.get("username", ""),
            password=creds.get("password", ""),
            raw_body=body[:500],
        )
        store.add(ev)
        logger.write(ev)

        # Route responses
        login_paths = {"/", "/index.html", "/admin", "/login",
                       "/wp-admin", "/panel", "/wp-login.php"}
        if path in login_paths:
            if method == "POST" and creds:
                response = _http_response(
                    "401 Unauthorized", HTTP_401,
                    "WWW-Authenticate: Basic realm=\"Admin\"\r\n"
                )
            else:
                response = _http_response("200 OK", HTTP_FAKE_LOGIN_PAGE)
        elif path == "/robots.txt":
            response = _http_response("200 OK", "User-agent: *\nDisallow: /admin\n")
        else:
            response = _http_response("404 Not Found", HTTP_404)

        writer.write(response)
        await writer.drain()

    except asyncio.TimeoutError:
        ev = build_event("http", "timeout", src_ip, src_port, store, geo)
        store.add(ev)
        logger.write(ev)
    except Exception as exc:
        ev = build_event("http", "error", src_ip, src_port, store, geo,
                         error=str(exc))
        store.add(ev)
        logger.write(ev)
    finally:
        try:
            writer.close()
        except Exception:
            pass
        ev = build_event("http", "disconnect", src_ip, src_port, store, geo)
        store.add(ev)
        logger.write(ev)


# ─────────────────────────────────────────────
#  Stats
# ─────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.counts     = defaultdict(int)
        self.start_time = datetime.now(timezone.utc)

    def inc(self, key: str) -> None:
        self.counts[key] += 1

    def summary(self) -> str:
        uptime = datetime.now(timezone.utc) - self.start_time
        lines  = [f"\n  Uptime : {str(uptime).split('.')[0]}"]
        for k, v in sorted(self.counts.items()):
            lines.append(f"  {k:<30} {v}")
        return "\n".join(lines)


# ─────────────────────────────────────────────
#  Server wiring
# ─────────────────────────────────────────────

async def start_servers(
    args,
    logger: HoneypotLogger,
    store: EventStore,
    geo: GeoIPEnricher,
    stats: Stats,
) -> None:
    servers = []

    if not args.no_ssh:
        def ssh_cb(r, w):
            stats.inc("ssh_connections")
            return handle_ssh(r, w, logger, store, geo, args.delay)

        srv = await asyncio.start_server(ssh_cb, host=args.host, port=args.ssh_port)
        servers.append(srv)
        print(f"  [+] SSH  honeypot  → {args.host}:{args.ssh_port}")

    if not args.no_http:
        def http_cb(r, w):
            stats.inc("http_connections")
            return handle_http(r, w, logger, store, geo)

        srv = await asyncio.start_server(http_cb, host=args.host, port=args.http_port)
        servers.append(srv)
        print(f"  [+] HTTP honeypot  → {args.host}:{args.http_port}")

    geo_status = "enabled" if geo.available else "disabled (see EXPLICACAO_TECNICA_COMPLETA.md)"
    print(f"  [+] GeoIP          → {geo_status}")
    print(f"  [+] Events log     → {args.log}")
    print(f"\n  Waiting for attackers... (Ctrl+C to stop)\n")

    async with asyncio.TaskGroup() as tg:
        for srv in servers:
            tg.create_task(srv.serve_forever())


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeypot",
        description="Honeypot v2 — Threat Detection & Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python honeypot.py --verbose
  python honeypot.py --ssh-port 2222 --http-port 8080 --verbose
  python honeypot.py --no-ssh --http-port 8080 --log logs/http_events.jsonl
  python honeypot.py --geoip-city geoip/GeoLite2-City.mmdb \\
                     --geoip-asn  geoip/GeoLite2-ASN.mmdb --verbose
        """,
    )
    p.add_argument("--host",       default="0.0.0.0",                       help="Bind address")
    p.add_argument("--ssh-port",   default=2222,     type=int,               help="SSH port (default: 2222)")
    p.add_argument("--http-port",  default=8080,     type=int,               help="HTTP port (default: 8080)")
    p.add_argument("--log",        default="logs/honeypot_events.jsonl",
                   type=Path,                                                  help="JSONL log path")
    p.add_argument("--delay",      default=2.0,      type=float,             help="SSH tarpit delay (seconds)")
    p.add_argument("--geoip-city", default=None,                             help="Path to GeoLite2-City.mmdb")
    p.add_argument("--geoip-asn",  default=None,                             help="Path to GeoLite2-ASN.mmdb")
    p.add_argument("--no-ssh",     action="store_true",                      help="Disable SSH honeypot")
    p.add_argument("--no-http",    action="store_true",                      help="Disable HTTP honeypot")
    p.add_argument("--verbose",    action="store_true",                      help="Real-time colored output")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    print("\n  Honeypot v2 — Threat Detection & Analysis System")
    print("  ─────────────────────────────────────────────────")

    geo    = GeoIPEnricher(city_db=args.geoip_city, asn_db=args.geoip_asn)
    store  = EventStore()
    logger = HoneypotLogger(args.log, verbose=args.verbose)
    stats  = Stats()

    def _shutdown(sig, frame):
        print("\n\n  [*] Shutting down...")
        print(stats.summary())
        geo.close()
        logger.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        asyncio.run(start_servers(args, logger, store, geo, stats))
    except* OSError as eg:
        for exc in eg.exceptions:
            print(f"\n[!] Could not bind port: {exc}", file=sys.stderr)
            print("    Ports > 1024 don't need root. Try: --ssh-port 2222 --http-port 8080\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
