from __future__ import annotations

import json
import os
import time

import httpx
import pytest
import respx

from probegoblin.intelligence import endoflife, epss_kev, lookup, npm_registry, nvd, osv, snyk
from probegoblin.intelligence import versions as v
from probegoblin.intelligence.cache import IntelClient, SourceError
from probegoblin.intelligence.cvss import base_score
from tests.conftest import FIXTURES, run

INTEL = FIXTURES / "intel"


def load(name):
    return json.loads((INTEL / name).read_text())


@pytest.fixture
def client(tmp_path):
    return IntelClient(cache_dir=tmp_path)


# Versions and ranges


def test_parse_versions():
    assert str(v.parse("1.12")) == "1.12.0"
    assert str(v.parse("v3.0.0-rc.1")) == "3.0.0-rc.1"
    assert str(v.parse("1.2.3.4")) == "1.2.3"
    assert v.parse("latest") is None
    assert v.parse("") is None


def test_compare_uses_semver_not_strings():
    assert v.compare("1.10.0", "1.9.0") == 1
    assert v.compare("3.5.0-beta", "3.5.0") == -1


EVENTS = [{"introduced": "1.12.0"}, {"fixed": "3.5.0"}]


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("1.12.4", True),  # in range
        ("1.12.0", True),  # lower boundary included
        ("3.5.0", False),  # fixed version excluded
        ("3.4.1", True),  # just below the fix
        ("1.11.3", False),  # below introduced
        ("3.5.0-beta.1", True),  # pre-release of the fixed version is still affected
        ("4.0.0", False),  # out of range
        ("not-a-version", False),  # unknown version never matches
    ],
)
def test_osv_range(version, expected):
    assert v.in_osv_range(version, EVENTS) is expected


def test_osv_last_affected_and_zero():
    assert v.in_osv_range("2.0.0", [{"introduced": "0"}, {"last_affected": "2.0.0"}])
    assert not v.in_osv_range("2.0.1", [{"introduced": "0"}, {"last_affected": "2.0.0"}])
    assert v.osv_range_label(EVENTS) == (">=1.12.0 <3.5.0", "3.5.0")


def test_nvd_range():
    match = {"versionStartIncluding": "0.6.18", "versionEndExcluding": "1.20.1"}
    assert v.in_nvd_range("1.18.0", match)
    assert not v.in_nvd_range("1.20.1", match)
    assert v.in_nvd_range("1.18.0", {"criteria": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"})
    assert not v.in_nvd_range("1.18.0", {"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"})


def test_cvss_scores_match_published():
    assert base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N") == 6.9
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L") == 7.7
    assert base_score("CVSS:4.0/AV:N") is None


# Sources, with real captured responses


def test_osv_parse_checks_range_itself():
    data = load("osv_GHSA-gxr4-xjj5-5px2.json")
    vuln = osv.parse_vuln(data, "jquery", "1.12.4")
    assert vuln.label == "CVE-2020-11022" and vuln.fixed == "3.5.0" and vuln.cvss_score == 6.9
    assert osv.parse_vuln(data, "jquery", "3.5.0") is None
    assert osv.parse_vuln(data, "jquery", "1.11.0") is None


@respx.mock
def test_osv_lookup(client):
    respx.post("https://api.osv.dev/v1/querybatch").respond(json=load("osv_querybatch.json"))
    for path in INTEL.glob("osv_GHSA-*.json"):
        respx.get(f"https://api.osv.dev/v1/vulns/{path.stem[4:]}").respond(json=load(path.name))
    respx.get(url__startswith="https://api.osv.dev/v1/vulns/").respond(404)
    found = run(osv.lookup(client, [("jquery", "1.12.4"), ("lodash", "4.17.21")]))
    labels = {x.label for x in found[("jquery", "1.12.4")]}
    assert labels == {"CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023", "CVE-2015-9251"}


@respx.mock
def test_npm_and_eol(client):
    respx.get("https://registry.npmjs.org/jquery").respond(json=load("npm_jquery.json"))
    info = run(npm_registry.info(client, "jquery", "1.12.4"))
    assert info.latest == "4.1.0" and info.latest_date == "2026-11-17"
    assert info.version_date == "2016-05-20"
    data = load("eol_jquery.json")
    assert endoflife.status_for(data, "4.1.0") == "supported"
    assert endoflife.status_for(data, "3.7.1").startswith("security fixes only")
    assert endoflife.status_for(data, "1.12.4").startswith("EOL")


@respx.mock
def test_epss_and_kev(client):
    respx.get(url__startswith="https://api.first.org/data/v1/epss").respond(json=load("epss.json"))
    respx.get(epss_kev.KEV).respond(json=load("kev.json"))
    scores = run(epss_kev.epss(client, ["CVE-2020-11022", "CVE-2020-11023"]))
    assert scores["CVE-2020-11022"][0] == pytest.approx(0.99215)
    assert "CVE-2020-11023" in run(epss_kev.kev(client))


def test_nvd_parse_real_response():
    cves = nvd.parse(load("nvd_nginx.json"), "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")
    ids = {c.id for c in cves}
    assert "CVE-2021-23017" in ids
    assert all(c.id.startswith("CVE-") for c in cves)
    assert nvd.cpe_with_version("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0") == (
        "cpe:2.3:a:f5:nginx:1.18.0"
    )


def test_nvd_needs_key(client, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert run(nvd.lookup(client, "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.18.0")) == []


def test_github_and_snyk_parsers_follow_documented_shape():
    github = [
        {
            "ghsa_id": "GHSA-xxxx",
            "cve_id": "CVE-2020-1",
            "summary": "s",
            "severity": "high",
            "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/..."},
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "npm", "name": "x"},
                    "vulnerable_version_range": "< 2.0.0",
                    "first_patched_version": "2.0.0",
                }
            ],
        }
    ]
    vuln = snyk.parse_github(github, "x")[0]
    assert vuln.cves == ["CVE-2020-1"] and vuln.fixed == "2.0.0" and vuln.sources == ["GitHub"]
    data = {
        "data": [{"id": "SNYK-1", "attributes": {"title": "t", "problems": [{"id": "CVE-2020-1"}]}}]
    }
    assert snyk.parse_snyk(data)[0].cves == ["CVE-2020-1"]


def test_merge_deduplicates_by_cve():
    a = osv.Vuln(id="GHSA-1", cves=["CVE-1"], sources=["OSV"])
    b = osv.Vuln(id="GHSA-1", cves=["CVE-1"], fixed="2.0.0", sources=["GitHub"])
    merged = lookup.merge([a], [b])
    assert (
        len(merged) == 1 and merged[0].sources == ["OSV", "GitHub"] and merged[0].fixed == "2.0.0"
    )


# Cache


@respx.mock
def test_cache_24h(client, tmp_path):
    route = respx.get("https://registry.npmjs.org/x").respond(json={"a": 1})
    assert run(client.json("npm", "https://registry.npmjs.org/x")) == {"a": 1}
    assert run(client.json("npm", "https://registry.npmjs.org/x")) == {"a": 1}
    assert route.call_count == 1
    for path in tmp_path.rglob("*.json"):
        old = time.time() - 25 * 3600
        os.utime(path, (old, old))
    run(client.json("npm", "https://registry.npmjs.org/x"))
    assert route.call_count == 2


def test_only_allowed_hosts(client):
    with pytest.raises(SourceError):
        run(client.json("x", "https://app.example.com/api"))


@respx.mock
def test_unreachable_source_is_reported_and_others_continue(client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(side_effect=httpx.ConnectError("down"))
    respx.get("https://registry.npmjs.org/jquery").respond(json=load("npm_jquery.json"))
    report = run(lookup.libraries(client, [("jquery", "1.12.4")], {}, ["jquery"]))
    assert any("OSV" in note for note in report.notes)
    assert report.info_by_name["jquery"].latest == "4.1.0"
