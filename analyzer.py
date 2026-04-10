#!/usr/bin/env python3
"""
Honeypot Analyzer v2
======================
Reads JSONL logs from honeypot.py and produces:
  - Threat reports (text / JSON / Markdown)
  - Per-IP attack timeline (first_seen, last_seen, duration, total_attempts)
  - Multi-service correlation summary
  - Tool fingerprint breakdown
  - Severity distribution
  - Auto-saved report bundle (--auto-report)

Usage:
  python analyzer.py logs/honeypot_events.jsonl
  python analyzer.py logs/honeypot_events.jsonl --format markdown --output report.md
  python analyzer.py logs/honeypot_events.jsonl --auto-report reports/
  python analyzer.py logs/honeypot_events.jsonl --live         
"""

from __future__ import annotations

import json
import time
import argparse
import sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional


SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[31m",
    "MEDIUM":   "\033[33m", "LOW":  "\033[34m", "INFO": "\033[37m",
}
RESET = "\033[0m"


# ─────────────────────────────────────────────
#  Data loading
# ─────────────────────────────────────────────

def load_events(path: Path) -> list[dict]:
    events = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"[!] Skipping malformed line {i}: {e}", file=sys.stderr)
    return events


# ─────────────────────────────────────────────
#  Analysis
# ─────────────────────────────────────────────

def analyze(events: list[dict], top_n: int = 10) -> dict:
    """
    Aggregate all events into analysis structures.
    Returns a dict consumed by render_* functions.
    """
    # Per-IP tracking
    ip_events:        dict[str, list[dict]] = defaultdict(list)
    ip_first_seen:    dict[str, str]        = {}
    ip_last_seen:     dict[str, str]        = {}
    ip_services:      dict[str, set]        = defaultdict(set)
    ip_attack_types:  dict[str, Counter]    = defaultdict(Counter)
    ip_severity_max:  dict[str, str]        = {}
    ip_tools:         dict[str, set]        = defaultdict(set)
    ip_creds:         dict[str, set]        = defaultdict(set)    # {(user, pass)}
    ip_paths:         dict[str, set]        = defaultdict(set)
    ip_countries:     dict[str, str]        = {}

    # Global counters
    attack_type_counter = Counter()
    severity_counter    = Counter()
    tool_counter        = Counter()
    path_counter        = Counter()
    username_counter    = Counter()
    password_counter    = Counter()
    user_agent_counter  = Counter()

    for ev in events:
        ip  = ev.get("src_ip", "unknown")
        ts  = ev.get("timestamp", "")
        svc = ev.get("service", "")
        et  = ev.get("event_type", "")

        ip_events[ip].append(ev)

        # Timeline
        if not ip_first_seen.get(ip) or ts < ip_first_seen[ip]:
            ip_first_seen[ip] = ts
        if not ip_last_seen.get(ip) or ts > ip_last_seen[ip]:
            ip_last_seen[ip] = ts

        if svc:
            ip_services[ip].add(svc)

        atype = ev.get("attack_type", "")
        sev   = ev.get("severity", "INFO")
        tool  = ev.get("tool", "")

        if atype:
            ip_attack_types[ip][atype] += 1
            attack_type_counter[atype] += 1

        if sev:
            severity_counter[sev] += 1
            curr_max = ip_severity_max.get(ip, "INFO")
            if SEVERITY_ORDER.get(sev, 9) < SEVERITY_ORDER.get(curr_max, 9):
                ip_severity_max[ip] = sev

        if tool:
            ip_tools[ip].add(tool)
            tool_counter[tool] += 1

        geo = ev.get("geo", {})
        if geo and geo.get("country"):
            ip_countries[ip] = geo["country"]

        if ev.get("username"):
            username_counter[ev["username"]] += 1
        if ev.get("password"):
            password_counter[ev["password"]] += 1
        if ev.get("user_agent"):
            user_agent_counter[ev["user_agent"]] += 1
        if ev.get("path"):
            path_counter[ev["path"]] += 1
            ip_paths[ip].add(ev["path"])
        if ev.get("username") and ev.get("password"):
            ip_creds[ip].add((ev["username"], ev["password"]))

    # Build per-IP timeline entries
    timeline = []
    for ip in ip_events:
        first  = ip_first_seen.get(ip, "")
        last   = ip_last_seen.get(ip, "")
        try:
            dt_first   = datetime.fromisoformat(first)
            dt_last    = datetime.fromisoformat(last)
            duration_s = int((dt_last - dt_first).total_seconds())
        except Exception:
            duration_s = 0

        total_attempts = sum(
            1 for e in ip_events[ip]
            if e.get("event_type") in ("auth_attempt", "http_request")
        )

        timeline.append({
            "ip":              ip,
            "first_seen":      first,
            "last_seen":       last,
            "duration_s":      duration_s,
            "total_attempts":  total_attempts,
            "total_events":    len(ip_events[ip]),
            "services":        sorted(ip_services[ip]),
            "multi_service":   len(ip_services[ip]) > 1,
            "attack_types":    dict(ip_attack_types[ip]),
            "max_severity":    ip_severity_max.get(ip, "INFO"),
            "tools":           sorted(ip_tools[ip]),
            "unique_creds":    len(ip_creds[ip]),
            "unique_paths":    len(ip_paths[ip]),
            "country":         ip_countries.get(ip, "Unknown"),
        })

    # Sort timeline: most severe first, then most active
    timeline.sort(
        key=lambda x: (SEVERITY_ORDER.get(x["max_severity"], 9), -x["total_events"])
    )

    multi_service_ips = [t for t in timeline if t["multi_service"]]

    return {
        "total_events":      len(events),
        "unique_ips":        len(ip_events),
        "timeline":          timeline,
        "multi_service_ips": multi_service_ips,
        "attack_types":      dict(attack_type_counter),
        "severity_dist":     dict(severity_counter),
        "top_tools":         tool_counter.most_common(top_n),
        "top_usernames":     username_counter.most_common(top_n),
        "top_passwords":     password_counter.most_common(top_n),
        "top_paths":         path_counter.most_common(top_n),
        "top_agents":        user_agent_counter.most_common(top_n),
    }


# ─────────────────────────────────────────────
#  Renderers
# ─────────────────────────────────────────────

def _fmt_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"


def render_text(data: dict) -> str:
    W   = 65
    sep = "=" * W
    s2  = "-" * W

    lines = [
        sep,
        " HONEYPOT THREAT REPORT",
        f" Generated : {datetime.now().isoformat()}",
        sep,
        f"  Total events   : {data['total_events']}",
        f"  Unique IPs     : {data['unique_ips']}",
        f"  Multi-service  : {len(data['multi_service_ips'])} IP(s) hit multiple services",
        "",
        " SEVERITY DISTRIBUTION",
        s2,
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = data["severity_dist"].get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "")
            bar   = "█" * min(count, 40)
            lines.append(f"  {color}{sev:<10}{RESET} {count:>5}  {bar}")

    lines += ["", " ATTACK TYPE BREAKDOWN", s2]
    for atype, count in sorted(data["attack_types"].items(),
                                key=lambda x: -x[1]):
        lines.append(f"  {atype:<25} {count:>5}x")

    lines += ["", " ATTACKER TIMELINE (sorted by severity)", s2]
    for t in data["timeline"][:20]:
        first = t["first_seen"][11:19]
        last  = t["last_seen"][11:19]
        dur   = _fmt_duration(t["duration_s"])
        sev   = t["max_severity"]
        color = SEVERITY_COLORS.get(sev, "")
        multi = " [MULTI-SERVICE]" if t["multi_service"] else ""
        svcs  = "+".join(t["services"])

        lines.append(
            f"  {color}[{sev}]{RESET} {t['ip']:<20} "
            f"{first}→{last} ({dur})  "
            f"{t['total_attempts']} attempts  "
            f"[{svcs}]{multi}"
        )
        if t["tools"]:
            lines.append(f"         tools: {', '.join(t['tools'])}")
        if t["country"] != "Unknown":
            lines.append(f"         country: {t['country']}")

    if data["multi_service_ips"]:
        lines += ["", " MULTI-SERVICE CORRELATION", s2]
        for t in data["multi_service_ips"]:
            lines.append(
                f"  {t['ip']:<20} hit [{'+'.join(t['services'])}]  "
                f"{t['total_attempts']} attempts  "
                f"creds tried: {t['unique_creds']}"
            )

    if data["top_tools"]:
        lines += ["", " TOOL FINGERPRINTS", s2]
        for tool, count in data["top_tools"]:
            lines.append(f"  {tool:<35} {count:>5}x")

    lines += ["", " TOP USERNAMES", s2]
    for user, count in data["top_usernames"]:
        lines.append(f"  {user:<35} {count:>5}x")

    lines += ["", " TOP PASSWORDS", s2]
    for pw, count in data["top_passwords"]:
        lines.append(f"  {pw[:40]:<40} {count:>5}x")

    lines += ["", " TOP HTTP PATHS PROBED", s2]
    for path, count in data["top_paths"]:
        lines.append(f"  {path:<40} {count:>5}x")

    return "\n".join(lines)


def render_markdown(data: dict) -> str:
    def table(rows: list, headers: list) -> str:
        h    = " | ".join(headers)
        sep  = " | ".join(["---"] * len(headers))
        body = "\n".join(
            "| " + " | ".join(str(c) for c in row) + " |"
            for row in rows
        )
        return f"| {h} |\n| {sep} |\n{body}"

    lines = [
        "# 🍯 Honeypot Threat Report",
        "",
        f"**Generated:** {datetime.now().isoformat()}  ",
        f"**Total Events:** {data['total_events']} | **Unique IPs:** {data['unique_ips']}",
        "",
        "---",
        "",
        "## Severity Distribution",
        "",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = data["severity_dist"].get(sev, 0)
        if count:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"- {emoji} **{sev}**: {count}")

    lines += [
        "",
        "## Attack Type Breakdown",
        table(
            [(k, v) for k, v in sorted(data["attack_types"].items(), key=lambda x: -x[1])],
            ["Attack Type", "Count"]
        ),
        "",
        "## Attacker Timeline",
        table(
            [
                (
                    f"`{t['ip']}`",
                    t["first_seen"][11:19],
                    t["last_seen"][11:19],
                    _fmt_duration(t["duration_s"]),
                    t["total_attempts"],
                    t["max_severity"],
                    ", ".join(t["services"]),
                    t["country"],
                    "✅" if t["multi_service"] else "",
                )
                for t in data["timeline"][:20]
            ],
            ["IP", "First Seen", "Last Seen", "Duration",
             "Attempts", "Max Severity", "Services", "Country", "Multi?"],
        ),
    ]

    if data["multi_service_ips"]:
        lines += [
            "",
            "## 🔗 Multi-Service Correlation",
            "> These IPs attacked more than one honeypot service — elevated threat.",
            table(
                [
                    (f"`{t['ip']}`", "+".join(t["services"]),
                     t["total_attempts"], t["unique_creds"], t["country"])
                    for t in data["multi_service_ips"]
                ],
                ["IP", "Services", "Attempts", "Unique Creds", "Country"],
            ),
        ]

    if data["top_tools"]:
        lines += [
            "",
            "## 🛠 Tool Fingerprints",
            table(data["top_tools"], ["Tool", "Detections"]),
        ]

    lines += [
        "",
        "## Top Credentials Attempted",
        "### Usernames",
        table(data["top_usernames"], ["Username", "Attempts"]),
        "",
        "### Passwords",
        table([(pw[:40], c) for pw, c in data["top_passwords"]], ["Password", "Attempts"]),
        "",
        "## Top HTTP Paths Probed",
        table(data["top_paths"], ["Path", "Hits"]),
    ]

    return "\n".join(lines)


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────
#  Live tail mode
# ─────────────────────────────────────────────

def live_tail(log_path: Path, interval: float = 1.0) -> None:
    """
    Watch a JSONL file in real time and print new events as they arrive.
    Similar to `tail -f` but parses and colors each event.
    """
    print(f"\n  [LIVE] Watching {log_path} — Ctrl+C to stop\n")
    seen_lines = 0

    while True:
        try:
            lines = log_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            time.sleep(interval)
            continue

        new_lines = lines[seen_lines:]
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev    = json.loads(line)
                sev   = ev.get("severity", "INFO")
                color = SEVERITY_COLORS.get(sev, "")
                ts    = ev.get("timestamp", "")[-14:-5]
                svc   = ev.get("service", "?").upper()
                etype = ev.get("event_type", "")
                ip    = ev.get("src_ip", "?")
                atype = ev.get("attack_type", "")
                tool  = ev.get("tool", "")

                extra = ""
                if ev.get("username"):
                    extra += f" user={ev['username']}"
                if ev.get("password"):
                    extra += f" pass={str(ev['password'])[:20]}"
                if ev.get("method"):
                    extra += f" {ev['method']} {ev.get('path', '')}"
                if tool:
                    extra += f" [{tool}]"
                if ev.get("multi_service"):
                    extra += " \033[95m[MULTI-SERVICE]\033[0m"

                print(
                    f"{color}[{ts}][{sev}][{svc}][{etype}]{RESET} "
                    f"{ip}{extra}"
                    f"{(' → ' + atype) if atype else ''}"
                )
            except json.JSONDecodeError:
                pass

        seen_lines = len(lines)
        time.sleep(interval)


# ─────────────────────────────────────────────
#  Auto-report bundle
# ─────────────────────────────────────────────

def auto_report(data: dict, output_dir: Path) -> None:
    """Generate all three report formats at once into output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for fmt, renderer, ext in [
        ("text",     render_text,     "txt"),
        ("markdown", render_markdown, "md"),
        ("json",     render_json,     "json"),
    ]:
        path    = output_dir / f"report_{ts}.{ext}"
        content = renderer(data)
        path.write_text(content, encoding="utf-8")
        print(f"  [+] {fmt:<10} → {path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer",
        description="Honeypot Analyzer v2 — threat report generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py logs/honeypot_events.jsonl
  python analyzer.py logs/honeypot_events.jsonl --format markdown --output report.md
  python analyzer.py logs/honeypot_events.jsonl --auto-report reports/
  python analyzer.py logs/honeypot_events.jsonl --live
        """,
    )
    p.add_argument("log",           type=Path,           help="Path to .jsonl log file")
    p.add_argument("--top",         type=int, default=10, help="Top N per category")
    p.add_argument("--format", "-f",
                   choices=["text", "markdown", "json"],
                   default="text",                        help="Output format")
    p.add_argument("--output", "-o",
                   type=Path, default=None,               help="Save to file instead of stdout")
    p.add_argument("--auto-report",
                   type=Path, default=None, metavar="DIR",
                   help="Generate all formats (txt+md+json) into DIR")
    p.add_argument("--live",        action="store_true",  help="Live tail mode (real-time)")
    p.add_argument("--interval",    type=float, default=1.0,
                   help="Live mode polling interval in seconds (default: 1.0)")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.log.exists():
        print(f"[!] File not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    # Live mode
    if args.live:
        try:
            live_tail(args.log, interval=args.interval)
        except KeyboardInterrupt:
            print("\n  [*] Live monitor stopped.")
        return

    events = load_events(args.log)
    if not events:
        print("[!] No events found in log file.")
        sys.exit(0)

    data = analyze(events, top_n=args.top)

    # Auto-report bundle
    if args.auto_report:
        print(f"\n  Generating report bundle → {args.auto_report}\n")
        auto_report(data, args.auto_report)
        return

    # Single format
    renderers = {
        "text":     render_text,
        "markdown": render_markdown,
        "json":     render_json,
    }
    content = renderers[args.format](data)

    if args.output:
        args.output.write_text(content, encoding="utf-8")
        print(f"[+] Report saved → {args.output}")
    else:
        print(content)


if __name__ == "__main__":
    main()
