from __future__ import annotations

import math
import re
from dataclasses import dataclass

from fastapi import HTTPException, status

CVSS_VECTOR_RE = re.compile(r"^(?:CVSS:3\.1/)?([A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])*)$")
REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass(frozen=True)
class CVSSValidationResult:
    normalized_vector: str
    computed_score: float


def _round_up_one_decimal(value: float) -> float:
    return math.ceil(value * 10.0) / 10.0


def parse_cvss_v31(vector: str) -> dict[str, str]:
    if not CVSS_VECTOR_RE.match(vector):
        raise ValueError("Malformed CVSS v3.1 vector")
    normalized = vector.removeprefix("CVSS:3.1/")
    metrics = {}
    for part in normalized.split("/"):
        key, value = part.split(":", 1)
        if key in metrics:
            raise ValueError(f"Duplicate CVSS metric: {key}")
        metrics[key] = value
    missing = REQUIRED_METRICS - set(metrics)
    if missing:
        raise ValueError(f"Missing CVSS metrics: {', '.join(sorted(missing))}")
    try:
        AV[metrics["AV"]]
        AC[metrics["AC"]]
        (PR_C if metrics["S"] == "C" else PR_U)[metrics["PR"]]
        UI[metrics["UI"]]
        CIA[metrics["C"]]
        CIA[metrics["I"]]
        CIA[metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"Invalid CVSS metric value: {exc}") from exc
    if metrics["S"] not in {"U", "C"}:
        raise ValueError("Invalid CVSS scope")
    return metrics


def calculate_cvss_v31_score(vector: str) -> float:
    metrics = parse_cvss_v31(vector)
    impact_sub_score = 1 - (
        (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    )
    if metrics["S"] == "U":
        impact = 6.42 * impact_sub_score
    else:
        impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15
    exploitability = (
        8.22
        * AV[metrics["AV"]]
        * AC[metrics["AC"]]
        * (PR_C if metrics["S"] == "C" else PR_U)[metrics["PR"]]
        * UI[metrics["UI"]]
    )
    if impact <= 0:
        return 0.0
    if metrics["S"] == "U":
        return _round_up_one_decimal(min(impact + exploitability, 10.0))
    return _round_up_one_decimal(min(1.08 * (impact + exploitability), 10.0))


def validate_cvss_vector(vector: str | None, supplied_score: float | None = None) -> CVSSValidationResult | None:
    if vector is None:
        return None
    try:
        computed_score = calculate_cvss_v31_score(vector)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if supplied_score is not None and abs(computed_score - supplied_score) > 0.1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"cvss_v3_score {supplied_score} does not match vector score {computed_score}",
        )
    normalized = vector if vector.startswith("CVSS:3.1/") else f"CVSS:3.1/{vector}"
    return CVSSValidationResult(normalized_vector=normalized, computed_score=computed_score)

