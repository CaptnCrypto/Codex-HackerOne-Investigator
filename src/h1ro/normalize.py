from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


MONEY_RE = re.compile(
    r"(?i)(?:USD\s*|US\$\s*|[$€£]\s*)"
    r"([0-9]{1,3}(?:[,.][0-9]{3})+|[0-9]{2,6})(?:\.00)?"
)


def _attributes(item: dict[str, Any]) -> dict[str, Any]:
    value = item.get("attributes") or {}
    return value if isinstance(value, dict) else {}


def _extract_amounts(policy: str) -> list[int]:
    amounts: list[int] = []
    for match in MONEY_RE.finditer(policy or ""):
        raw = match.group(1).replace(",", "").replace(".", "")
        try:
            amounts.append(int(raw))
        except ValueError:
            continue
    return sorted(set(amounts))


def normalize_program(
    program: dict[str, Any],
    scopes: list[dict[str, Any]],
    exclusions: list[dict[str, Any]],
    *,
    retrieved_at: str,
) -> dict[str, Any]:
    attrs = _attributes(program)
    normalized_scopes = []
    for scope in scopes:
        value = _attributes(scope)
        normalized_scopes.append(
            {
                "id": str(scope.get("id", "")),
                "asset_type": value.get("asset_type"),
                "asset_identifier": value.get("asset_identifier"),
                "eligible_for_submission": value.get("eligible_for_submission") is True,
                "eligible_for_bounty": value.get("eligible_for_bounty") is True,
                "max_severity": value.get("max_severity"),
                "instruction": value.get("instruction"),
                "created_at": value.get("created_at"),
                "updated_at": value.get("updated_at"),
            }
        )
    normalized_exclusions = []
    for exclusion in exclusions:
        value = _attributes(exclusion)
        normalized_exclusions.append(
            {
                "id": str(exclusion.get("id", "")),
                "category": value.get("category"),
                "details": value.get("details"),
                "updated_at": value.get("updated_at"),
            }
        )

    policy = attrs.get("policy") or ""
    eligible_scopes = [
        scope
        for scope in normalized_scopes
        if scope["eligible_for_submission"] and scope["eligible_for_bounty"]
    ]
    return {
        "id": str(program.get("id", "")),
        "handle": attrs.get("handle"),
        "name": attrs.get("name"),
        "currency": attrs.get("currency"),
        "policy": policy,
        "submission_state": attrs.get("submission_state"),
        "state": attrs.get("state"),
        "started_accepting_at": attrs.get("started_accepting_at"),
        "triage_active": attrs.get("triage_active"),
        "bookmarked": attrs.get("bookmarked"),
        "allows_bounty_splitting": attrs.get("allows_bounty_splitting"),
        "offers_bounties": attrs.get("offers_bounties"),
        "open_scope": attrs.get("open_scope"),
        "fast_payments": attrs.get("fast_payments"),
        "gold_standard_safe_harbor": attrs.get("gold_standard_safe_harbor"),
        "user_history": {
            "reports": attrs.get("number_of_reports_for_user"),
            "valid_reports": attrs.get("number_of_valid_reports_for_user"),
            "bounty_earned": attrs.get("bounty_earned_for_user"),
        },
        "scopes": normalized_scopes,
        "scope_exclusions": normalized_exclusions,
        "derived": {
            "eligible_scope_count": len(eligible_scopes),
            "advertised_amounts": _extract_amounts(policy),
            "reward_extraction_confidence": "heuristic" if _extract_amounts(policy) else "unknown",
        },
        "provenance": {
            "retrieved_at": retrieved_at,
            "api_version": "v1",
            "normalized_at": datetime.now(timezone.utc).isoformat(),
        },
    }
