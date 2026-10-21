#!/usr/bin/env python3
"""Audit a published M3 comparison without modifying canonical state."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

ALLOWED_FLAGS = {
    "relocated",
    "body_changed",
    "signature_changed",
    "layout_changed",
    "references_changed",
    "referenced_data_changed",
    "renamed",
    "added",
    "removed",
    "not_observed",
    "unknown",
}
SIMILARITY_METHODS = {
    "unique_observed_name_candidate",
    "raw_body_hash_candidate",
    "bsim_candidate",
}
FORBIDDEN_PATH_MARKERS = (
    b"C:\\aniimo",
    b"C:/aniimo",
    b"/inputs/snapshots/",
    b"/state/registry",
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            inspected = carry + chunk
            _assert(
                not any(marker in inspected for marker in FORBIDDEN_PATH_MARKERS),
                f"Absolute host/container path leaked: {path.name}",
            )
            carry = inspected[-64:]
    return digest.hexdigest()


def _ndjson(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def audit(
    registry_path: Path, comparison_root: Path, cache_run: str
) -> dict[str, object]:
    summary = json.loads((comparison_root / "comparison.json").read_text("utf-8"))
    output_manifest = json.loads(
        (comparison_root / "output-manifest.json").read_text("utf-8")
    )
    matches = _ndjson(comparison_root / "matches.ndjson")
    changes = _ndjson(comparison_root / "changes.ndjson")
    fingerprints = _ndjson(comparison_root / "dependency-fingerprints.ndjson")
    for logical_path, expected in output_manifest["files"].items():
        target = comparison_root.joinpath(*logical_path.split("/"))
        _assert(target.is_file(), f"Missing published file: {logical_path}")
        _assert(_sha256(target) == expected, f"Digest mismatch: {logical_path}")
    manifest_sha256 = hashlib.sha256(
        (
            json.dumps(
                output_manifest["files"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    _assert(
        manifest_sha256 == output_manifest["manifest_sha256"],
        "Output-manifest identity mismatch",
    )

    match_counts = Counter(str(item["match_status"]) for item in matches)
    invalidation_counts = Counter(str(item["invalidation_status"]) for item in changes)
    flag_counts = Counter(
        str(flag) for item in changes for flag in item.get("change_flags", [])
    )
    _assert(len(matches) == int(summary["match_count"]), "Match count differs")
    _assert(
        dict(sorted(match_counts.items())) == summary["match_status_counts"],
        "Match status counts differ",
    )
    _assert(
        dict(sorted(invalidation_counts.items()))
        == summary["invalidation_status_counts"],
        "Invalidation counts differ",
    )
    _assert(
        dict(sorted(flag_counts.items())) == summary["change_flag_counts"],
        "Change flags differ",
    )
    _assert(set(flag_counts) <= ALLOWED_FLAGS, "Unknown change flag")
    _assert(
        all(
            item["match_status"] != "confirmed"
            for item in matches
            if item["match_method"] in SIMILARITY_METHODS
        ),
        "Similarity evidence was promoted automatically",
    )
    _assert(
        all(
            item.get("semantic_operands_hash") == item.get("raw_body_hash")
            for item in fingerprints
        ),
        "Strict semantic operands were normalized",
    )
    _assert(
        summary["uncertainties"]["runtime_compatibility_certified"] is False,
        "Static comparison claims runtime certification",
    )

    uri = f"file:{registry_path.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        comparison = db.execute(
            """SELECT comparison_id,status,output_manifest_sha256
               FROM build_comparisons WHERE comparison_key=?""",
            (summary["comparison_key"],),
        ).fetchone()
        cached_steps = [
            dict(row)
            for row in db.execute(
                """SELECT sr.step_id,sr.status,sr.cache_status,sr.reason
                   FROM stage_runs sr JOIN analysis_runs ar
                     ON ar.analysis_id=sr.analysis_id
                   WHERE ar.workflow_run_id=?
                   ORDER BY sr.step_id""",
                (cache_run,),
            )
        ]
        registry_match_count = (
            int(
                db.execute(
                    "SELECT COUNT(*) FROM matches WHERE comparison_id=?",
                    (comparison["comparison_id"],),
                ).fetchone()[0]
            )
            if comparison
            else -1
        )
        registry_change_count = (
            int(
                db.execute(
                    "SELECT COUNT(*) FROM comparison_changes WHERE comparison_id=?",
                    (comparison["comparison_id"],),
                ).fetchone()[0]
            )
            if comparison
            else -1
        )

    _assert(user_version >= 5, "Unexpected registry migration level")
    _assert(integrity == "ok", "SQLite integrity check failed")
    _assert(not foreign_keys, "SQLite foreign-key check failed")
    _assert(comparison is not None, "Comparison missing from registry")
    _assert(comparison["status"] == "completed", "Comparison is not completed")
    _assert(
        comparison["output_manifest_sha256"] == output_manifest["manifest_sha256"],
        "Registry output digest differs",
    )
    _assert(registry_match_count == len(matches), "Registry match count differs")
    _assert(registry_change_count == len(changes), "Registry change count differs")
    documentation_steps = [
        item for item in cached_steps if item["step_id"] == "comparison.documentation"
    ]
    matching_steps = [
        item for item in cached_steps if item["step_id"] == "comparison.matching"
    ]
    _assert(len(documentation_steps) == 1, "Cache run documentation step missing")
    _assert(len(matching_steps) == 1, "Cache run matching step missing")
    _assert(
        documentation_steps[0]["status"] == "cache_hit"
        and documentation_steps[0]["cache_status"] == "hit",
        "Identical comparison rewrote documentation",
    )
    _assert(
        matching_steps[0]["status"] == "cache_hit"
        and matching_steps[0]["cache_status"] == "hit",
        "Identical comparison recomputed matching",
    )
    return {
        "change_flag_counts": dict(sorted(flag_counts.items())),
        "comparison_id": comparison["comparison_id"],
        "comparison_key": summary["comparison_key"],
        "fingerprint_count": len(fingerprints),
        "foreign_key_check": "ok",
        "integrity_check": integrity,
        "invalidation_status_counts": dict(sorted(invalidation_counts.items())),
        "match_count": len(matches),
        "match_status_counts": dict(sorted(match_counts.items())),
        "output_manifest_sha256": output_manifest["manifest_sha256"],
        "user_version": user_version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--comparison-root", type=Path, required=True)
    parser.add_argument("--cache-run", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            audit(args.registry, args.comparison_root, args.cache_run),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
