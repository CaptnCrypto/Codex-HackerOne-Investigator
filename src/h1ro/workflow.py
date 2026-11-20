from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .normalize import normalize_program
from .ranking import rank_programs
from .security import atomic_write, ensure_private_directory


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _safe_handle(value: str) -> str:
    return value.replace("_", "-")


def _raw_recorder(raw_root: Path):
    prefix = "/v1/hackers/programs"
    scope_batches: dict[str, int] = {}

    def record(path: str, query: dict[str, str], body: bytes) -> None:
        if path == prefix:
            page = int(query.get("page[number]", "1"))
            target = raw_root / "programs" / f"page-{page:04d}.json"
        elif path.startswith(prefix + "/"):
            relative = path[len(prefix) + 1 :].split("/")
            if len(relative) == 1:
                target = raw_root / _safe_handle(relative[0]) / "program.json"
            elif len(relative) == 2 and relative[1] == "structured_scopes":
                scope_batches[path] = scope_batches.get(path, 0) + 1
                batch = scope_batches[path]
                target = (
                    raw_root
                    / _safe_handle(relative[0])
                    / "structured-scopes"
                    / f"batch-{batch:04d}.json"
                )
            elif len(relative) == 2 and relative[1] == "scope_exclusions":
                target = raw_root / _safe_handle(relative[0]) / "scope-exclusions.json"
            else:
                raise RuntimeError("refusing to record an unexpected API path")
        else:
            raise RuntimeError("refusing to record an unexpected API path")
        atomic_write(target, body.decode("utf-8") + ("" if body.endswith(b"\n") else "\n"))

    return record


def render_report(ranked: list[dict[str, Any]], *, retrieved_at: str, total: int) -> str:
    lines = [
        "# HackerOne Opportunity Ranking",
        "",
        f"Retrieved: {retrieved_at}",
        f"Normalized programs: {total}",
        f"Top opportunities shown: {len(ranked)} (maximum 10)",
        "",
        "Eligibility requires open submissions, advertised bounties, and at least one scope "
        "eligible for both submission and bounty.",
        "",
        "## Top opportunities",
        "",
    ]
    if not ranked:
        lines.append("No programs met the eligibility gates.")
    for index, item in enumerate(ranked, 1):
        lines.extend(
            [
                f"### {index}. {item['name']} (`{item['handle']}`) — {item['score']}/100",
                "",
            ]
        )
        for label, component in item["components"].items():
            lines.append(
                f"- {label.title()}: {component['points']} — {component['explanation']}"
            )
        lines.extend(["", "Limitations:", ""])
        lines.extend(f"- {limitation}" for limitation in item["limitations"])
        lines.append("")
    lines.extend(
        [
            "## Scoring model",
            "",
            "- Reward potential and policy clarity: 30 points.",
            "- Match to web/API-oriented Investigator capabilities: 25 points.",
            "- Scope breadth and maximum severity: 20 points.",
            "- Safe-harbor and exclusion clarity: 15 points.",
            "- Triage, payment, and scope-freshness indicators: 10 points.",
            "",
            "This is an opportunity-screening aid, not authorization to test. Always review the current "
            "program policy, scope instructions, and exclusions before any testing.",
        ]
    )
    return "\n".join(lines) + "\n"


def synchronize(client: Any, case_root: Path) -> dict[str, Path]:
    case_root = case_root.resolve(strict=True)
    expected = (case_root / "CASE-INFO.txt").read_text(encoding="utf-8")
    case_ids = [
        line.removeprefix("CASE_ID=").strip()
        for line in expected.splitlines()
        if line.startswith("CASE_ID=")
    ]
    if (
        len(case_ids) != 1
        or not case_ids[0]
        or any(character.isspace() for character in case_ids[0])
    ):
        raise RuntimeError("case root has no single valid CASE_ID")

    os.umask(0o077)
    retrieved_at = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    raw_root = case_root / "reports" / "hackerone" / "raw" / stamp
    artifact_root = case_root / "artifacts" / "hackerone" / stamp
    report_root = case_root / "reports" / "hackerone" / stamp
    for directory in (raw_root, artifact_root, report_root):
        ensure_private_directory(directory)

    client.recorder = _raw_recorder(raw_root)
    listed = client.programs()
    normalized = []
    for listed_program in listed:
        if not isinstance(listed_program, dict):
            raise RuntimeError("program list contained a non-object resource")
        listed_attrs = listed_program.get("attributes") or {}
        handle = listed_attrs.get("handle")
        if not isinstance(handle, str):
            raise RuntimeError("program list contained no valid handle")
        scopes = client.structured_scopes(handle)
        exclusions = client.scope_exclusions(handle)
        normalized.append(
            normalize_program(listed_program, scopes, exclusions, retrieved_at=retrieved_at)
        )

    ranked = rank_programs(normalized, limit=10)
    normalized_path = artifact_root / "normalized-programs.json"
    ranking_path = artifact_root / "ranking.json"
    report_path = report_root / "top-10-opportunities.md"
    atomic_write(normalized_path, _json({"retrieved_at": retrieved_at, "programs": normalized}))
    atomic_write(ranking_path, _json({"retrieved_at": retrieved_at, "ranking": ranked}))
    atomic_write(report_path, render_report(ranked, retrieved_at=retrieved_at, total=len(normalized)))

    manifest = {}
    for path in sorted(raw_root.rglob("*.json")) + [normalized_path, ranking_path, report_path]:
        manifest[str(path.relative_to(case_root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path = report_root / "sha256-manifest.json"
    atomic_write(manifest_path, _json(manifest))
    return {
        "raw": raw_root,
        "normalized": normalized_path,
        "ranking": ranking_path,
        "report": report_path,
        "manifest": manifest_path,
    }
