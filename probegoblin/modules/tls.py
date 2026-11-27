"""TLSGoblin: runs testssl.sh with its defaults and summarises the result."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from probegoblin.core.context import TargetContext
from probegoblin.core.external import INSTALL_HINTS, find_tool, run_tool
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import STAGE_EXTERNAL, Goblin

PROBLEM = {"CRITICAL", "HIGH", "MEDIUM"}
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "OK", "INFO"]

# Group name, testssl option that rechecks it, and ids (exact or prefix ending in *).
GROUPS: list[tuple[str, str, list[str]]] = [
    ("Protocols", "-p", ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3", "ALPN", "NPN"]),
    (
        "Ciphers",
        "-s",
        [
            "cipherlist_*",
            "cipher_order",
            "cipher-tls*",
            "cipher-ssl*",
        ],
    ),
    ("Forward secrecy", "-f", ["FS", "FS_ECDHE_curves", "DH_groups"]),
    (
        "Certificate",
        "-S",
        [
            "cert_chain_of_trust",
            "cert_trust",
            "cert_commonName",
            "cert_subjectAltName",
            "cert_expirationStatus",
            "cert_notAfter",
            "cert_signatureAlgorithm",
            "cert_keySize",
            "cert_revocation",
            "cert_extlifeSpan",
            "OCSP_stapling",
            "certificate_transparency",
            "certs_list_ordering_problem",
            "intermediate_cert_*",
        ],
    ),
    ("Renegotiation", "-R", ["secure_renego", "secure_client_renego"]),
    ("TLS compression", "-C", ["CRIME_TLS"]),
    (
        "Vulnerabilities",
        "-U",
        [
            "heartbleed",
            "CCS",
            "ticketbleed",
            "opossum",
            "ROBOT",
            "POODLE_SSL",
            "fallback_SCSV",
            "SWEET32",
            "FREAK",
            "DROWN",
            "LOGJAM",
            "LOGJAM-common_primes",
            "BEAST",
            "BEAST_CBC_*",
            "LUCKY13",
            "winshock",
            "RC4",
            "GREASE",
        ],
    ),
]
# Owned by other modules, so not repeated here.
SKIP = {"HSTS", "HPKP", "BREACH", "security_headers", "cookie_count", "cookie_secure"}
VULN_FLAGS = {
    "heartbleed": "-H",
    "CCS": "-I",
    "ticketbleed": "-T",
    "ROBOT": "--BB",
    "POODLE_SSL": "-O",
    "fallback_SCSV": "-Z",
    "SWEET32": "-W",
    "FREAK": "-F",
    "DROWN": "-D",
    "LOGJAM": "-J",
    "BEAST": "-A",
    "LUCKY13": "-L",
    "winshock": "-WS",
    "RC4": "-4",
}
TITLES = {
    "SSLv2": "SSLv2 offered",
    "SSLv3": "SSLv3 offered",
    "TLS1": "TLS 1.0 offered",
    "TLS1_1": "TLS 1.1 offered",
    "cert_chain_of_trust": "Certificate chain not trusted",
    "cert_trust": "Certificate does not match the hostname",
    "cert_subjectAltName": "Certificate has no subjectAltName",
    "cert_expirationStatus": "Certificate expiry",
    "cert_notAfter": "Certificate expiry date",
    "cert_signatureAlgorithm": "Weak certificate signature algorithm",
    "cert_keySize": "Weak certificate key",
    "cert_revocation": "No certificate revocation information",
    "FS": "Forward secrecy",
    "secure_client_renego": "Client-initiated renegotiation",
    "secure_renego": "Secure renegotiation",
    "CRIME_TLS": "TLS compression (CRIME)",
}


@dataclass
class Item:
    id: str
    ip: str
    severity: str
    finding: str


def parse_testssl(text: str) -> list[Item]:
    data = json.loads(text)
    if isinstance(data, dict) and "scanResult" in data:  # --jsonfile-pretty layout
        data = [
            entry
            for result in data["scanResult"]
            for section in result.values()
            if isinstance(section, list)
            for entry in section
        ]
    if not isinstance(data, list):
        raise ValueError("unexpected testssl JSON layout")
    items = []
    for entry in data:
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        items.append(
            Item(
                id=str(entry["id"]),
                ip=str(entry.get("ip", "")),
                severity=str(entry.get("severity", "INFO")).upper(),
                finding=" ".join(str(entry.get("finding", "")).split()),
            )
        )
    return items


def group_of(item_id: str) -> tuple[str, str] | None:
    for name, flag, ids in GROUPS:
        for pattern in ids:
            if pattern.endswith("*"):
                if item_id.startswith(pattern[:-1]):
                    return name, flag
            elif item_id == pattern:
                return name, flag
    return None


def summary(items: list[Item]) -> str:
    by_id = {i.id: i for i in items}
    offered = [
        label
        for key, label in (
            ("SSLv2", "SSLv2"),
            ("SSLv3", "SSLv3"),
            ("TLS1", "1.0"),
            ("TLS1_1", "1.1"),
            ("TLS1_2", "1.2"),
            ("TLS1_3", "1.3"),
        )
        if key in by_id and by_id[key].finding.startswith("offered")
    ]
    parts = []
    if offered:
        parts.append("TLS " + ", ".join(offered))
    if "cert_notAfter" in by_id:
        parts.append(f"certificate valid until {by_id['cert_notAfter'].finding.split()[0]}")
    problems = sum(
        1 for i in items if i.severity in PROBLEM and i.id not in SKIP and group_of(i.id)
    )
    parts.append(f"{problems} issue{'s' if problems != 1 else ''}")
    if "overall_grade" in by_id:
        parts.append(f"testssl grade {by_id['overall_grade'].finding}")
    return " | ".join(parts)


class TLSGoblin(Goblin):
    name = "TLSGoblin"
    flag = "tls"
    prefix = "TLS"
    order = 160
    stage = STAGE_EXTERNAL
    description = (
        "testssl.sh with default options: protocols, ciphers, certificate, vulnerabilities"
    )

    def unavailable_reason(self) -> str | None:
        if find_tool("testssl") is None:
            return f"testssl.sh not found ({INSTALL_HINTS['testssl']})"
        return None

    def command(self, ctx: TargetContext, jsonfile: Path) -> list[str]:
        argv = [find_tool("testssl") or "testssl", "--jsonfile", str(jsonfile)]
        if ctx.settings.pinned_ip:
            argv += ["--ip", ctx.settings.pinned_ip]
        return [*argv, ctx.target]

    def reproduce(self, ctx: TargetContext, flag: str) -> str:
        pin = f" --ip {ctx.settings.pinned_ip}" if ctx.settings.pinned_ip else ""
        return f"testssl {flag}{pin} {ctx.target}"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        if not ctx.https:
            result.not_assessed_reason = "target uses plain HTTP"
            return result
        limit = ctx.settings.tool_limits.testssl
        with tempfile.TemporaryDirectory(prefix="probegoblin-") as tmp:
            jsonfile = Path(tmp) / "testssl.json"
            try:
                run = await run_tool(self.command(ctx, jsonfile), limit)
            except OSError as exc:
                result.not_assessed_reason = f"testssl.sh failed to start: {exc}"
                return result
            if run.timed_out:
                result.not_assessed_reason = f"timed out after {limit} seconds"
                return result
            try:
                items = parse_testssl(jsonfile.read_text("utf-8"))
            except (OSError, ValueError):
                result.not_assessed_reason = "could not parse testssl.sh output"
                return result
        fatal = [i for i in items if i.severity == "FATAL"]
        if fatal:
            result.not_assessed_reason = f"testssl.sh stopped: {fatal[0].finding}"
            return result
        ctx.summary["tls"] = summary(items)
        result.tables.append(self._table(items))
        result.findings = self._findings(ctx, items)
        return result

    def _table(self, items: list[Item]) -> Table:
        ips = {i.ip for i in items if i.ip}
        rows: list[list[str]] = []
        for name, _flag, _ids in GROUPS:
            group = [i for i in items if group_of(i.id) and group_of(i.id)[0] == name]
            if name == "Ciphers":
                # One row per cipher category; individual ciphers only when rated LOW or worse.
                group = [
                    i
                    for i in group
                    if not i.id.startswith("cipher-") or i.severity in PROBLEM | {"LOW"}
                ]
            for item in sorted(
                group, key=lambda i: ORDER.index(i.severity) if i.severity in ORDER else 9
            ):
                row = [name, item.id, item.severity, item.finding[:90]]
                if len(ips) > 1:
                    row.insert(0, item.ip.split("/")[-1])
                rows.append(row)
        columns = ["Group", "Check", "testssl", "Result"]
        if len(ips) > 1:
            columns.insert(0, "IP")
        return Table(title="TLS (testssl.sh)", columns=columns, rows=rows)

    def _findings(self, ctx: TargetContext, items: list[Item]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            if item.id in SKIP:
                continue
            group = group_of(item.id)
            if group is None:
                continue
            name, flag = group
            flag = VULN_FLAGS.get(item.id, flag)
            key = (item.id, item.finding)
            if key in seen:
                continue
            if item.id == "cert_notAfter" and any(i.id == "cert_expirationStatus" for i in items):
                continue  # same problem as cert_expirationStatus, kept in the table only
            seen.add(key)
            if item.severity in PROBLEM:
                status = Status.ISSUE
            elif item.severity == "LOW":
                status = Status.OBSERVATION
            elif item.severity == "WARN":
                status = Status.NOT_ASSESSED
            elif item.severity == "OK":
                status = Status.OK
            else:
                continue
            title = TITLES.get(item.id) or f"{name}: {item.id}"
            if item.id.startswith("cipher-"):
                title = f"Weaker cipher offered: {_cipher_name(item.finding)}"
            observed = f"testssl {item.severity}: {item.finding}"
            if item.ip and len({i.ip for i in items}) > 1:
                observed += f" ({item.ip.split('/')[-1]})"
            out.append(
                self.finding(
                    title=title,
                    status=status,
                    affected_url=ctx.target,
                    observed=(
                        observed if status != Status.NOT_ASSESSED else f"Not assessed: {observed}"
                    ),
                    why_it_matters=(
                        _why(name, item)
                        if status in (Status.ISSUE, Status.OBSERVATION)
                        else (
                            "Check passed."
                            if status == Status.OK
                            else "testssl.sh could not complete this check."
                        )
                    ),
                    reproduce=(
                        [self.reproduce(ctx, flag)]
                        if status in (Status.ISSUE, Status.OBSERVATION)
                        else []
                    ),
                )
            )
        return out


def _cipher_name(finding: str) -> str:
    parts = finding.split()
    return parts[2] if len(parts) > 2 else finding


def _why(group: str, item: Item) -> str:
    reasons = {
        "Protocols": "Old protocol versions have known weaknesses and are disabled in modern "
        "browsers.",
        "Ciphers": "Weaker cipher suites reduce the protection of the connection.",
        "Forward secrecy": "Without forward secrecy, a stolen server key decrypts recorded "
        "traffic.",
        "Certificate": "Certificate problems cause browser warnings or weaken trust in the "
        "connection.",
        "Renegotiation": "Insecure renegotiation can allow request injection or denial of "
        "service.",
        "TLS compression": "TLS compression allows the CRIME attack on secrets in requests.",
        "Vulnerabilities": f"testssl.sh rates the server {item.severity} for {item.id}. "
        "Version-based and configuration-based checks can be wrong; confirm before reporting.",
    }
    return reasons.get(group, f"testssl.sh rates this {item.severity}.")
