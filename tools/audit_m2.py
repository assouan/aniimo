#!/usr/bin/env python3
"""Audit a published M2 analysis without modifying the registry or artifacts."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import Counter
from pathlib import Path

EXPECTED_MODULES = {
    "KernelDumpAnalyzer.exe",
    "NEP2.dll",
    "NEPCleaner.exe",
    "NEPKernel.sys",
}
BODY_STATUSES = {"c_and_asm", "asm_only", "disassembly_failed", "pending"}


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def audit(
    registry_path: Path, analysis_root: Path, cache_run: str
) -> dict[str, object]:
    coverage = json.loads((analysis_root / "coverage.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (analysis_root / "analysis-manifest.json").read_text(encoding="utf-8")
    )
    build_id = str(manifest["build_id"])
    registry_uri = f"file:{registry_path.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(registry_uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        status_counts = {status: 0 for status in BODY_STATUSES}
        status_counts.update(
            {
                str(row[0]): int(row[1])
                for row in db.execute(
                    """SELECT body_output_status,COUNT(*) FROM body_observations
                       WHERE build_id=? AND scope_decision='game_decompile'
                       GROUP BY body_output_status""",
                    (build_id,),
                )
            }
        )
        modules = {
            str(row[0]): int(row[1])
            for row in db.execute(
                """SELECT module_logical_path,COUNT(*) FROM body_observations
                   WHERE build_id=? AND scope_decision='game_decompile'
                   GROUP BY module_logical_path""",
                (build_id,),
            )
        }
        table_counts = {
            "native_bodies": int(
                db.execute(
                    "SELECT COUNT(DISTINCT native_body_id) FROM body_observations WHERE build_id=?",
                    (build_id,),
                ).fetchone()[0]
            ),
            "body_observations": int(
                db.execute(
                    "SELECT COUNT(*) FROM body_observations WHERE build_id=?",
                    (build_id,),
                ).fetchone()[0]
            ),
            "native_body_attempts": int(
                db.execute(
                    """SELECT COUNT(DISTINCT a.native_body_id)
                       FROM native_body_attempts a
                       WHERE EXISTS (
                           SELECT 1 FROM body_observations bo
                           WHERE bo.native_body_id=a.native_body_id AND bo.build_id=?
                       )""",
                    (build_id,),
                ).fetchone()[0]
            ),
            "native_references": int(
                db.execute(
                    "SELECT COUNT(*) FROM native_references WHERE build_id=?",
                    (build_id,),
                ).fetchone()[0]
            ),
            "native_module_analyses": int(
                db.execute(
                    """SELECT COUNT(*) FROM native_module_analyses nma
                       WHERE EXISTS (
                           SELECT 1 FROM build_components bc
                           WHERE bc.component_revision_id=nma.component_revision_id
                             AND bc.build_id=?
                       )""",
                    (build_id,),
                ).fetchone()[0]
            ),
            "symbol_body_links": int(
                db.execute(
                    "SELECT COUNT(*) FROM symbol_body_links WHERE build_id=?",
                    (build_id,),
                ).fetchone()[0]
            ),
            "unresolved_code_regions": int(
                db.execute(
                    "SELECT COUNT(*) FROM unresolved_code_regions WHERE build_id=?",
                    (build_id,),
                ).fetchone()[0]
            ),
        }
        cache_steps = [
            dict(row)
            for row in db.execute(
                """SELECT sr.step_id,sr.status,sr.cache_status,sr.reason
                   FROM stage_runs sr
                   JOIN analysis_runs ar ON ar.analysis_id=sr.analysis_id
                   WHERE ar.workflow_run_id=? AND sr.stage_name='native_module'
                   ORDER BY sr.step_id""",
                (cache_run,),
            )
        ]
        cache_run_status = db.execute(
            "SELECT status FROM analysis_runs WHERE workflow_run_id=?", (cache_run,)
        ).fetchone()

    coverage_counts = {
        key: int(value) for key, value in coverage["body_status_counts"].items()
    }
    body_sets = {
        status: set(coverage["body_ids_by_status"].get(status, []))
        for status in BODY_STATUSES
    }
    body_union: set[str] = set()
    for status in BODY_STATUSES:
        _assert(body_union.isdisjoint(body_sets[status]), "Overlapping coverage states")
        body_union.update(body_sets[status])

    body_file_counts: Counter[str] = Counter()
    body_root = analysis_root / "native" / "bodies"
    for path in body_root.iterdir():
        name = path.name
        if name.endswith(".managed-signature.txt"):
            body_file_counts["managed_signature"] += 1
        elif name.endswith(".prototype.txt"):
            body_file_counts["prototype"] += 1
        elif name.endswith(".references.json"):
            body_file_counts["references"] += 1
        elif name.endswith(".diagnostic.json"):
            body_file_counts["diagnostic"] += 1
        else:
            body_file_counts[path.suffix.removeprefix(".") or "no_suffix"] += 1

    file_count = 0
    maximum_component_bytes = 0
    for directory, directories, files in os.walk(analysis_root):
        for name in (*directories, *files):
            maximum_component_bytes = max(
                maximum_component_bytes, len(name.encode("utf-8"))
            )
        file_count += len(files)

    approved_count = int(coverage["approved_body_count"])
    _assert(user_version >= 4, "Unexpected registry migration level")
    _assert(integrity == "ok", "SQLite integrity check failed")
    _assert(not foreign_keys, "SQLite foreign-key check failed")
    _assert(set(modules) == EXPECTED_MODULES, "Unexpected native module scope")
    _assert(set(status_counts) <= BODY_STATUSES, "Unknown body status in registry")
    _assert(status_counts == coverage_counts, "Coverage and registry counts differ")
    _assert(sum(coverage_counts.values()) == approved_count, "Coverage is not exact")
    _assert(len(body_union) == approved_count, "Coverage body IDs are not exact")
    _assert(bool(coverage["exact_body_reconciliation"]), "Reconciliation is false")
    _assert(coverage_counts["pending"] == 0, "Pending native bodies remain")
    _assert(table_counts["native_bodies"] == approved_count, "Body count differs")
    _assert(
        table_counts["body_observations"] == approved_count,
        "Body observation count differs",
    )
    _assert(
        table_counts["native_body_attempts"] == approved_count,
        "Attempt count differs",
    )
    _assert(table_counts["native_module_analyses"] == 4, "Module count differs")
    _assert(
        len(manifest["body_manifest_sha256"]) == approved_count,
        "Body manifest count differs",
    )
    _assert(set(manifest["body_manifest_sha256"]) == body_union, "Manifest IDs differ")
    _assert(body_file_counts["json"] == approved_count, "Body JSON count differs")
    _assert(body_file_counts["references"] == approved_count, "Reference views differ")
    _assert(body_file_counts["diagnostic"] == approved_count, "Diagnostics differ")
    _assert(body_file_counts["prototype"] == approved_count, "Prototypes differ")
    _assert(
        body_file_counts["managed_signature"] == approved_count,
        "Managed-signature views differ",
    )
    _assert(
        body_file_counts["c"] == coverage_counts["c_and_asm"],
        "C output count differs",
    )
    _assert(
        body_file_counts["asm"]
        == coverage_counts["c_and_asm"]
        + coverage_counts["asm_only"]
        + coverage_counts["pending"],
        "ASM output count differs",
    )
    _assert(maximum_component_bytes <= 255, "Non-portable path component remains")
    _assert(
        cache_run_status is not None and cache_run_status[0] == "completed",
        "Cache run failed",
    )
    _assert(len(cache_steps) == 4, "Cache run has an unexpected module count")
    _assert(
        all(
            row["status"] == "cache_hit" and row["cache_status"] == "hit"
            for row in cache_steps
        ),
        "Cache run re-executed native analysis",
    )

    return {
        "analysis_key": coverage["analysis_key"],
        "approved_body_count": approved_count,
        "body_file_counts": dict(sorted(body_file_counts.items())),
        "body_status_counts": coverage_counts,
        "cache_run": cache_run,
        "cache_steps": cache_steps,
        "file_count": file_count,
        "foreign_key_check": "ok",
        "integrity_check": integrity,
        "maximum_path_component_bytes": maximum_component_bytes,
        "metadata_catalog_status": coverage["expected_methods"]["catalog_status"],
        "modules": modules,
        "registry_counts": table_counts,
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
