#!/usr/bin/env python3
"""CLI tool that scores a URL's HTTP security headers."""

import argparse
import json
import sys
from datetime import datetime, timezone

import requests

CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "recommendation": "Set 'max-age=31536000; includeSubDomains' to enforce HTTPS and prevent downgrade attacks.",
        "is_ok": lambda v: v is not None and "max-age" in v.lower(),
    },
    {
        "header": "Content-Security-Policy",
        "recommendation": "Define a Content-Security-Policy to restrict script/style/frame sources and mitigate XSS.",
        "is_ok": lambda v: v is not None,
    },
    {
        "header": "X-Content-Type-Options",
        "recommendation": "Set to 'nosniff' to stop browsers from MIME-sniffing responses away from the declared type.",
        "is_ok": lambda v: v is not None and v.lower().strip() == "nosniff",
    },
    {
        "header": "X-Frame-Options",
        "recommendation": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking via iframes.",
        "is_ok": lambda v: v is not None and v.lower().strip() in ("deny", "sameorigin"),
    },
    {
        "header": "Referrer-Policy",
        "recommendation": "Set a restrictive policy (e.g. 'strict-origin-when-cross-origin') to limit referrer leakage.",
        "is_ok": lambda v: v is not None,
    },
    {
        "header": "Permissions-Policy",
        "recommendation": "Define a Permissions-Policy to disable unneeded browser features (camera, mic, geolocation, ...).",
        "is_ok": lambda v: v is not None,
    },
]

GRADE_TABLE = [
    (6, "A"),
    (5, "B"),
    (4, "C"),
    (3, "D"),
    (2, "E"),
    (0, "F"),
]

GRADE_ORDER = ["A", "B", "C", "D", "E", "F"]


def grade_for(score: int) -> str:
    for threshold, grade in GRADE_TABLE:
        if score >= threshold:
            return grade
    return "F"


def evaluate(headers: requests.structures.CaseInsensitiveDict) -> list[dict]:
    results = []
    for check in CHECKS:
        value = headers.get(check["header"])
        ok = check["is_ok"](value)
        results.append(
            {
                "header": check["header"],
                "present": value is not None,
                "value": value,
                "ok": ok,
                "recommendation": "OK" if ok else check["recommendation"],
            }
        )
    return results


def build_report(url: str, results: list[dict]) -> str:
    score = sum(1 for r in results if r["ok"])
    total = len(results)
    grade = grade_for(score)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Web Security Header Scan Report",
        "",
        f"- **Target URL:** {url}",
        f"- **Scanned at:** {timestamp}",
        f"- **Score:** {score}/{total} ({grade})",
        "",
        "| Header | Present | Value | Recommendation |",
        "|---|---|---|---|",
    ]
    for r in results:
        value = r["value"] if r["value"] else "—"
        value = value.replace("|", "\\|")
        if len(value) > 100:
            value = value[:100] + "… (truncated)"
        present = "Yes" if r["present"] else "No"
        lines.append(f"| {r['header']} | {present} | {value} | {r['recommendation']} |")

    return "\n".join(lines) + "\n"


def build_json_report(url: str, results: list[dict]) -> str:
    score = sum(1 for r in results if r["ok"])
    total = len(results)
    payload = {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score,
        "total": total,
        "grade": grade_for(score),
        "headers": results,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a URL's HTTP security headers.")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format"
    )
    parser.add_argument(
        "--fail-below",
        choices=GRADE_ORDER,
        default=None,
        help="Exit with code 1 if the resulting grade is worse than this (for CI gating).",
    )
    args = parser.parse_args()

    try:
        response = requests.get(args.url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    results = evaluate(response.headers)
    report = (
        build_json_report(args.url, results)
        if args.format == "json"
        else build_report(args.url, results)
    )

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(report)
    print(f"Report written to {args.output}")

    if args.fail_below is not None:
        grade = grade_for(sum(1 for r in results if r["ok"]))
        if GRADE_ORDER.index(grade) > GRADE_ORDER.index(args.fail_below):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
