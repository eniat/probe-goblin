"""CVSS v3.x base score from a published vector (FIRST specification, section 7)."""

from __future__ import annotations

import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope = metrics["S"]
        iss = 1 - (
            (1 - WEIGHTS["C"][metrics["C"]])
            * (1 - WEIGHTS["I"][metrics["I"]])
            * (1 - WEIGHTS["A"][metrics["A"]])
        )
        unchanged = 6.42 * iss
        changed = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        impact = unchanged if scope == "U" else changed
        exploitability = (
            8.22
            * WEIGHTS["AV"][metrics["AV"]]
            * WEIGHTS["AC"][metrics["AC"]]
            * PR[scope][metrics["PR"]]
            * WEIGHTS["UI"][metrics["UI"]]
        )
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope == "U":
        return roundup(min(impact + exploitability, 10))
    return roundup(min(1.08 * (impact + exploitability), 10))
