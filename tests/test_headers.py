from __future__ import annotations

from probegoblin.core import csp
from probegoblin.core.models import Status
from probegoblin.modules.headers import HeaderGoblin, parse_hsts
from tests.conftest import TARGET, make_ctx, make_page, run

GOOD = [
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; "
        "base-uri 'none'",
    ),
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
]


def results(headers, body="<html><title>x</title></html>"):
    ctx = make_ctx([make_page(TARGET, headers=headers, body=body, source="landing")])
    return run(HeaderGoblin().run(ctx)).findings


def by_status(findings, status):
    return {f.title for f in findings if f.status == status}


def test_well_configured_page_has_no_issues():
    findings = results(GOOD)
    assert by_status(findings, Status.ISSUE) == set()
    assert "CSP 'unsafe-inline' neutralised" not in by_status(findings, Status.OK)
    assert "HSTS max-age" in by_status(findings, Status.OK)


def test_missing_everything():
    issues = by_status(results([]), Status.ISSUE)
    assert {
        "Content-Security-Policy not enforced",
        "Strict-Transport-Security not set",
        "X-Content-Type-Options not set",
    } <= issues


def test_report_only_is_not_enforced():
    findings = results([("Content-Security-Policy-Report-Only", "default-src 'self'")])
    hit = [f for f in findings if f.title == "Content-Security-Policy not enforced"][0]
    assert "Report-Only only" in hit.observed


def test_unsafe_inline_issue_and_neutralised():
    weak = results([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")])
    assert "CSP allows inline scripts" in by_status(weak, Status.ISSUE)
    nonce = results(
        [("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'")]
    )
    assert "CSP allows inline scripts" not in by_status(nonce, Status.ISSUE)
    assert "CSP 'unsafe-inline' neutralised" in by_status(nonce, Status.OK)


def test_wildcards_and_schemes():
    for policy in ("script-src *", "script-src https:", "default-src 'self' data:"):
        issues = by_status(results([("Content-Security-Policy", policy)]), Status.ISSUE)
        assert "CSP allows scripts from any host or scheme" in issues, policy
    strict = results([("Content-Security-Policy", "script-src 'nonce-a' 'strict-dynamic' https:")])
    assert "CSP allows scripts from any host or scheme" not in by_status(strict, Status.ISSUE)


def test_known_bypass_host():
    findings = results([("Content-Security-Policy", "script-src 'self' https://www.google.com")])
    hit = [f for f in findings if f.title == "CSP allowlists hosts with known bypasses"]
    assert hit and "www.google.com" in hit[0].observed


def test_needs_eval_bypass_only_with_unsafe_eval():
    without = results([("Content-Security-Policy", "script-src www.googletagmanager.com")])
    assert "CSP allowlists hosts with known bypasses" not in by_status(without, Status.ISSUE)


def test_object_src_and_base_uri():
    findings = results([("Content-Security-Policy", "script-src 'self'")])
    assert "CSP object-src is not 'none'" in by_status(findings, Status.ISSUE)
    assert "CSP has no base-uri" in by_status(findings, Status.OBSERVATION)
    nonce = results([("Content-Security-Policy", "script-src 'nonce-a'; object-src 'none'")])
    assert "CSP has no base-uri" in by_status(nonce, Status.ISSUE)


def test_meta_policy_ignores_frame_ancestors():
    body = (
        '<html><head><meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'self'; frame-ancestors 'none'\"></head></html>"
    )
    findings = results([], body=body)
    assert "Content-Security-Policy not enforced" not in by_status(findings, Status.ISSUE)
    assert "CSP directives ignored in meta policy" in by_status(findings, Status.OBSERVATION)


def test_every_enforced_policy_must_be_weak():
    findings = results(
        [
            ("Content-Security-Policy", "script-src 'unsafe-inline' *"),
            ("Content-Security-Policy", "script-src 'self'"),
        ]
    )
    assert "CSP allows inline scripts" not in by_status(findings, Status.ISSUE)


def test_hsts():
    assert parse_hsts("max-age=10; max-age=20")[1] == ["duplicate max-age directive"]
    assert parse_hsts("includeSubDomains")[1] == ["no max-age directive"]
    short = results([("Strict-Transport-Security", "max-age=86400")])
    assert "HSTS max-age below one year" in by_status(short, Status.OBSERVATION)
    zero = results([("Strict-Transport-Security", "max-age=0")])
    assert "HSTS max-age is 0" in by_status(zero, Status.ISSUE)
    bad = results([("Strict-Transport-Security", "max-age=1; max-age=2")])
    assert "HSTS header is invalid" in by_status(bad, Status.ISSUE)


def test_hsts_over_http_noted():
    ctx = make_ctx(
        [
            make_page(
                "http://app.example.com/",
                headers=[("Strict-Transport-Security", "max-age=31536000")],
                source="landing",
            )
        ],
        target="http://app.example.com/",
    )
    findings = run(HeaderGoblin().run(ctx)).findings
    assert "HSTS sent over plain HTTP" in by_status(findings, Status.OBSERVATION)
    assert "Strict-Transport-Security not set" not in by_status(findings, Status.ISSUE)


def test_x_xss_protection_never_recommends_mode_block():
    findings = results([("X-XSS-Protection", "1; mode=block")])
    hit = [f for f in findings if f.title == "Deprecated X-XSS-Protection filter enabled"][0]
    assert hit.status == Status.OBSERVATION
    assert "mode=block" not in (hit.remediation or "")
    assert "X-XSS-Protection" in by_status(results([("X-XSS-Protection", "0")]), Status.OK)


def test_referrer_policy():
    assert "Referrer-Policy unsafe-url" in by_status(
        results([("Referrer-Policy", "unsafe-url")]), Status.ISSUE
    )
    assert "Referrer-Policy no-referrer-when-downgrade" in by_status(
        results([("Referrer-Policy", "no-referrer-when-downgrade")]), Status.ISSUE
    )
    assert "Referrer-Policy value not recognised" in by_status(
        results([("Referrer-Policy", "banana")]), Status.ISSUE
    )
    fallback = results([("Referrer-Policy", "no-referrer, strict-origin-when-cross-origin")])
    assert "Referrer-Policy" in by_status(fallback, Status.OK)


def test_differences_between_pages_are_reported():
    login = make_page(f"{TARGET}login", headers=[("X-Content-Type-Options", "nosniff")])
    landing = make_page(TARGET, headers=GOOD, source="landing")
    ctx = make_ctx([landing, login])
    findings = run(HeaderGoblin().run(ctx)).findings
    missing = [f for f in findings if f.title == "Content-Security-Policy not enforced"]
    assert missing and missing[0].affected_url == f"{TARGET}login"


def test_every_issue_has_a_safe_reproduce_command():
    for finding in results([]):
        if finding.status in (Status.ISSUE, Status.MANUAL_CHECK):
            assert finding.reproduce
            assert all(cmd.startswith("curl -sI") for cmd in finding.reproduce)


def test_csp_parser():
    policy = csp.parse_policy("Script-Src 'SELF' https://A.example.com; script-src *", "header")
    assert policy.directives["script-src"] == ["'self'", "https://A.example.com"]
    assert policy.duplicates == ["script-src"]
