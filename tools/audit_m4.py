#!/usr/bin/env python3
"""Audit a published M4 Lua analysis without modifying canonical state."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

FORBIDDEN_PATH_MARKERS = (
    b"C:\\aniimo",
    b"C:/aniimo",
    b"C:\\Program Files",
    b"/inputs/snapshots/",
    b"/state/registry",
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _sha256(path: Path, *, inspect_paths: bool = True) -> str:
    digest = hashlib.sha256()
    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            if inspect_paths:
                inspected = carry + chunk
                _assert(
                    not any(marker in inspected for marker in FORBIDDEN_PATH_MARKERS),
                    f"Absolute host/container path leaked: {path}",
                )
                carry = inspected[-128:]
    return digest.hexdigest()


def _csv_count(path: Path) -> int:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return sum(1 for _ in csv.DictReader(stream))


def audit(registry_path: Path, analysis_root: Path, cache_run: str) -> dict[str, Any]:
    summary = json.loads((analysis_root / "lua-analysis.json").read_text("utf-8"))
    coverage = json.loads((analysis_root / "lua-coverage.json").read_text("utf-8"))
    output_manifest = json.loads(
        (analysis_root / "output-manifest.json").read_text("utf-8")
    )
    files = output_manifest["files"]
    _assert(isinstance(files, list) and files, "Published file manifest is empty")
    for item in files:
        logical_path = str(item["path"])
        _assert(".." not in Path(logical_path).parts, "Unsafe output path")
        target = analysis_root.joinpath(*logical_path.split("/"))
        _assert(target.is_file(), f"Missing published file: {logical_path}")
        _assert(target.stat().st_size == int(item["size_bytes"]), "Size mismatch")
        _assert(_sha256(target) == item["sha256"], f"Digest mismatch: {logical_path}")

    _assert(summary["schema_version"] == 1, "Unexpected Lua schema version")
    _assert(summary["runtime_probe"]["status"] == "not_tested", "Runtime status lied")
    _assert(summary["runtime_probe"]["executed"] is False, "Runtime probe was claimed")
    _assert(
        summary["bridge"]["classification"] == "reference_only"
        and summary["bridge"]["implementation_exported"] is False,
        "xLua implementation escaped the reference-only boundary",
    )
    _assert(coverage["runtime_status"] == "not_tested", "Coverage runtime status lied")
    _assert(
        coverage["discovery_complete"] is False, "Lua discovery claims completeness"
    )
    _assert(coverage["archive_component_count"] == 2, "Active/bundled roles collapsed")
    csv_counts = {
        "archives": _csv_count(analysis_root / "lua_archives.csv"),
        "bindings": _csv_count(analysis_root / "lua_bindings.csv"),
        "dependencies": _csv_count(analysis_root / "lua_dependencies.csv"),
        "modules": _csv_count(analysis_root / "lua_modules.csv"),
        "symbols": _csv_count(analysis_root / "lua_symbols.csv"),
    }
    _assert(csv_counts["archives"] == 2, "Archive CSV does not separate roles")
    _assert(
        csv_counts["modules"] == int(coverage["lua_entry_observation_count"]),
        "Lua module count differs",
    )
    _assert(
        csv_counts["bindings"] == int(coverage["binding_count"]),
        "Lua binding count differs",
    )

    uri = f"file:{registry_path.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        analysis = db.execute(
            """SELECT lua_analysis_id,status,output_manifest_sha256
               FROM lua_analyses WHERE lua_analysis_key=?""",
            (summary["analysis_key"],),
        ).fetchone()
        observations = db.execute(
            """SELECT parse_status,COUNT(*) AS count FROM lua_observations
               WHERE lua_analysis_id=? GROUP BY parse_status""",
            (summary["lua_analysis_id"],),
        ).fetchall()
        archive_rows = db.execute(
            """SELECT archive_role,component_revision_id,evidence_json
               FROM lua_archive_observations WHERE lua_analysis_id=?
               ORDER BY archive_role""",
            (summary["lua_analysis_id"],),
        ).fetchall()
        cached_steps = db.execute(
            """SELECT sr.step_id,sr.status,sr.cache_status
               FROM stage_runs sr JOIN analysis_runs ar ON ar.analysis_id=sr.analysis_id
               WHERE ar.workflow_run_id=? ORDER BY sr.step_id""",
            (cache_run,),
        ).fetchall()

    _assert(user_version >= 7, "Unexpected registry migration level")
    _assert(integrity == "ok", "SQLite integrity check failed")
    _assert(not foreign_keys, "SQLite foreign-key check failed")
    _assert(
        analysis is not None and analysis["status"] == "completed",
        "Lua analysis incomplete",
    )
    manifest_sha256 = _sha256(analysis_root / "output-manifest.json")
    _assert(
        analysis["output_manifest_sha256"] == manifest_sha256,
        "Registry output digest differs",
    )
    _assert(len(archive_rows) == 2, "Registry archive roles are incomplete")
    _assert(
        len({row["component_revision_id"] for row in archive_rows}) == 2,
        "Active/bundled component revisions are not distinct",
    )
    parse_counts = Counter(
        {str(row["parse_status"]): int(row["count"]) for row in observations}
    )
    _assert(
        sum(parse_counts.values()) == int(coverage["lua_entry_observation_count"]),
        "Registry Lua observation count differs",
    )
    _assert(
        all(
            json.loads(row["evidence_json"])["non_lua_entries_indexed_only"] >= 0
            for row in archive_rows
        ),
        "Non-Lua entries were not accounted for",
    )
    step_status = {
        row["step_id"]: (row["status"], row["cache_status"]) for row in cached_steps
    }
    _assert(
        step_status.get("lua.analysis") == ("cache_hit", "hit"),
        "Identical Lua analysis did not hit its cache",
    )
    _assert(
        step_status.get("lua.documentation") == ("cache_hit", "hit"),
        "Identical Lua analysis rewrote documentation",
    )
    return {
        "analysis_key": summary["analysis_key"],
        "archive_component_count": len(archive_rows),
        "build_id": summary["build_id"],
        "csv_counts": csv_counts,
        "foreign_key_check": "ok",
        "integrity_check": integrity,
        "output_file_count": len(files) + 1,
        "output_manifest_sha256": manifest_sha256,
        "parse_status_counts": dict(sorted(parse_counts.items())),
        "runtime_probe_status": summary["runtime_probe"]["status"],
        "user_version": user_version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--analysis-root", type=Path, required=True)
    parser.add_argument("--cache-run", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            audit(args.registry, args.analysis_root, args.cache_run),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
