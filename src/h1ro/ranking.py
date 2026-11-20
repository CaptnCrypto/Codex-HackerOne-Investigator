from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any


SEVERITY_VALUE = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ASSET_FIT = {
    "url": 1.0,
    "domain": 1.0,
    "cidr": 0.8,
    "source_code": 0.8,
    "android: play store": 0.65,
    "android: apk": 0.65,
    "ios: app store": 0.6,
    "ios: testflight": 0.6,
    "other": 0.35,
}


def _reward_points(program: dict[str, Any]) -> tuple[float, str]:
    amounts = program["derived"]["advertised_amounts"]
    if not amounts:
        return 5.0, "offers bounties; exact amounts not reliably extractable"
    maximum = max(amounts)
    points = min(30.0, 6.0 + 6.0 * math.log10(maximum / 100 + 1))
    return round(points, 1), f"policy amount heuristic found a maximum of {maximum:,}"


def _fit_points(scopes: list[dict[str, Any]]) -> tuple[float, str]:
    eligible = [s for s in scopes if s["eligible_for_submission"] and s["eligible_for_bounty"]]
    if not eligible:
        return 0.0, "no eligible bounty scopes"
    fits = [ASSET_FIT.get(str(s.get("asset_type") or "").lower(), 0.5) for s in eligible]
    points = 25.0 * (sum(sorted(fits, reverse=True)[:5]) / min(5, len(fits)))
    kinds = sorted({str(s.get("asset_type") or "unknown") for s in eligible})
    return round(points, 1), "eligible asset types: " + ", ".join(kinds[:6])


def _scope_points(scopes: list[dict[str, Any]]) -> tuple[float, str]:
    eligible = [s for s in scopes if s["eligible_for_submission"] and s["eligible_for_bounty"]]
    count_points = min(12.0, 4.0 + 3.0 * math.log2(max(1, len(eligible))))
    severity = max(
        (SEVERITY_VALUE.get(str(s.get("max_severity") or "none").lower(), 0) for s in eligible),
        default=0,
    )
    points = count_points + severity * 2.0
    return round(min(20.0, points), 1), f"{len(eligible)} eligible scopes; maximum severity level {severity}/4"


def _safety_points(program: dict[str, Any]) -> tuple[float, str]:
    points = 0.0
    reasons = []
    if program.get("gold_standard_safe_harbor") is True:
        points += 8.0
        reasons.append("Gold Standard Safe Harbor")
    policy = program.get("policy") or ""
    if len(policy) >= 500:
        points += 4.0
        reasons.append("substantive policy text")
    exclusions = program.get("scope_exclusions") or []
    if not exclusions:
        points += 3.0
        reasons.append("no additional scope exclusions returned")
    elif all(x.get("category") and x.get("details") for x in exclusions):
        points += 3.0
        reasons.append("explicit exclusion details")
    return min(15.0, points), "; ".join(reasons) or "limited structured safety signals"


def _operations_points(program: dict[str, Any]) -> tuple[float, str]:
    points = 0.0
    reasons = []
    if program.get("triage_active") is True:
        points += 4.0
        reasons.append("active triage")
    if program.get("fast_payments") is True:
        points += 4.0
        reasons.append("fast payments")
    newest = None
    for scope in program.get("scopes") or []:
        value = scope.get("updated_at")
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            newest = parsed if newest is None or parsed > newest else newest
        except ValueError:
            continue
    if newest and (datetime.now(timezone.utc) - newest).days <= 365:
        points += 2.0
        reasons.append("scope updated within one year")
    return min(10.0, points), "; ".join(reasons) or "limited operational signals"


def score_program(program: dict[str, Any]) -> dict[str, Any]:
    eligible = (
        program.get("submission_state") == "open"
        and program.get("offers_bounties") is True
        and program.get("derived", {}).get("eligible_scope_count", 0) > 0
    )
    disqualifiers = []
    if program.get("submission_state") != "open":
        disqualifiers.append("submissions are not open")
    if program.get("offers_bounties") is not True:
        disqualifiers.append("program does not advertise bounties")
    if program.get("derived", {}).get("eligible_scope_count", 0) < 1:
        disqualifiers.append("no scope is both submission- and bounty-eligible")

    parts = {}
    for key, function, argument in (
        ("reward", _reward_points, program),
        ("fit", _fit_points, program.get("scopes") or []),
        ("scope", _scope_points, program.get("scopes") or []),
        ("safety", _safety_points, program),
        ("operations", _operations_points, program),
    ):
        points, explanation = function(argument)
        parts[key] = {"points": points, "explanation": explanation}
    total = round(sum(part["points"] for part in parts.values()), 1) if eligible else 0.0
    return {
        "handle": program.get("handle"),
        "name": program.get("name"),
        "eligible": eligible,
        "score": total,
        "components": parts,
        "disqualifiers": disqualifiers,
        "limitations": [
            "Reward amounts are heuristically parsed from policy text and require manual verification.",
            "The score does not measure program-wide competition or expected vulnerability prevalence.",
        ],
    }


def rank_programs(programs: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    scored = [score_program(program) for program in programs]
    eligible = [item for item in scored if item["eligible"]]
    return sorted(eligible, key=lambda item: (-item["score"], str(item["handle"])))[:limit]
