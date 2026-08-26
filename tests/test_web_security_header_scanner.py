import json
import sys

import requests
from requests.structures import CaseInsensitiveDict

from web_security_header_scanner import build_json_report, build_report, evaluate, grade_for, main

ALL_HEADERS_GOOD = CaseInsensitiveDict(
    {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
)


def test_all_headers_present_scores_perfect_and_grade_a():
    results = evaluate(ALL_HEADERS_GOOD)
    score = sum(1 for r in results if r["ok"])
    assert score == 6
    assert grade_for(score) == "A"


def test_no_headers_scores_zero_and_grade_f():
    results = evaluate(CaseInsensitiveDict({}))
    score = sum(1 for r in results if r["ok"])
    assert score == 0
    assert grade_for(score) == "F"
    assert all(not r["present"] for r in results)


def test_partial_headers_scores_correctly():
    headers = CaseInsensitiveDict(
        {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "SAMEORIGIN",
        }
    )
    results = evaluate(headers)
    score = sum(1 for r in results if r["ok"])
    assert score == 2
    assert grade_for(score) == "E"


def test_x_content_type_options_wrong_value_flagged_not_ok():
    headers = CaseInsensitiveDict({"X-Content-Type-Options": "sniff-me-please"})
    results = evaluate(headers)
    xcto = next(r for r in results if r["header"] == "X-Content-Type-Options")
    assert xcto["present"] is True
    assert xcto["ok"] is False
    assert xcto["recommendation"] != "OK"


def test_report_lists_all_checked_headers_in_markdown_table():
    results = evaluate(CaseInsensitiveDict({}))
    report = build_report("https://example.com", results)
    for header_name in [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]:
        assert header_name in report
    assert "0/6" in report
    assert "(F)" in report


def test_json_report_is_valid_json_with_expected_fields():
    results = evaluate(ALL_HEADERS_GOOD)
    report = build_json_report("https://example.com", results)
    payload = json.loads(report)
    assert payload["url"] == "https://example.com"
    assert payload["score"] == 6
    assert payload["total"] == 6
    assert payload["grade"] == "A"
    assert len(payload["headers"]) == 6
    assert {"header", "present", "value", "ok", "recommendation"} <= payload["headers"][0].keys()


def test_json_report_reflects_partial_score():
    headers = CaseInsensitiveDict({"X-Frame-Options": "DENY"})
    results = evaluate(headers)
    payload = json.loads(build_json_report("https://example.com", results))
    assert payload["score"] == 1
    assert payload["grade"] == grade_for(1)


class FakeResponse:
    def __init__(self, headers):
        self.headers = CaseInsensitiveDict(headers)


def run_main(monkeypatch, tmp_path, headers, extra_args):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(headers))
    out = str(tmp_path / "out.md")
    argv = ["web_security_header_scanner.py", "--url", "https://example.com", "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_below_exits_nonzero_when_grade_worse_than_threshold(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, {}, ["--fail-below", "B"])
    assert exit_code == 1


def test_fail_below_exits_zero_when_grade_meets_threshold(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, ALL_HEADERS_GOOD, ["--fail-below", "B"])
    assert exit_code == 0


def test_no_fail_below_always_exits_zero(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, {}, [])
    assert exit_code == 0


def test_fail_below_returns_1_on_request_failure(monkeypatch, tmp_path):
    def raise_request_exception(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "get", raise_request_exception)
    out = str(tmp_path / "out.md")
    monkeypatch.setattr(sys, "argv", ["web_security_header_scanner.py", "--url", "https://example.com", "--output", out])
    assert main() == 1
