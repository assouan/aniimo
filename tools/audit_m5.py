#!/usr/bin/env python3
"""Audit the M5 SDK release without modifying canonical state."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_LOADER_SHA256 = (
    "616ec7eb06cf11b2a0000e8fcef04d1b12bb58e84a2e0bdac9523234fc193ceb"
)
FORBIDDEN_BYTES = (
    b"C:\\aniimo",
    b"C:/aniimo",
    b"C:\\Program Files",
    b"/inputs/snapshots/",
    b"/state/registry",
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _assert(isinstance(value, dict), f"Expected a JSON object: {path}")
    return value


def _sha256(path: Path, *, inspect: bool = True) -> str:
    digest = hashlib.sha256()
    carry = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
            if inspect:
                sample = carry + chunk
                _assert(
                    not any(marker in sample for marker in FORBIDDEN_BYTES),
                    f"Absolute analysis path leaked: {path}",
                )
                carry = sample[-128:]
    return digest.hexdigest()


def _validate_output(generated_root: Path) -> tuple[dict[str, Any], str]:
    manifest_path = generated_root / "output-manifest.json"
    output_manifest = _read_json(manifest_path)
    files = output_manifest.get("files")
    _assert(isinstance(files, list) and files, "SDK output manifest is empty")
    paths: list[str] = []
    for item in files:
        logical = str(item["path"])
        pure = PurePosixPath(logical)
        _assert(not pure.is_absolute() and ".." not in pure.parts, "Unsafe output path")
        target = generated_root.joinpath(*pure.parts)
        _assert(target.is_file(), f"Missing generated SDK file: {logical}")
        _assert(target.stat().st_size == int(item["size_bytes"]), "Output size differs")
        _assert(_sha256(target) == item["sha256"], f"Output digest differs: {logical}")
        paths.append(logical)
    _assert(len(paths) == len(set(paths)), "Duplicate generated SDK path")
    return output_manifest, _sha256(manifest_path)


def _validate_zip(package: Path) -> tuple[list[str], dict[str, Any]]:
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        _assert(len(names) == len(set(names)), "Duplicate SDK package entry")
        _assert(
            all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in infos),
            "SDK package timestamps are not deterministic",
        )
        for item in infos:
            pure = PurePosixPath(item.filename)
            _assert(
                not item.is_dir() and not pure.is_absolute() and ".." not in pure.parts,
                f"Unsafe SDK package entry: {item.filename}",
            )
            data = archive.read(item)
            _assert(
                not any(marker in data for marker in FORBIDDEN_BYTES),
                f"Absolute analysis path leaked in package: {item.filename}",
            )
        package_manifest = json.loads(archive.read("package-manifest.json"))
    _assert(package_manifest["contains_game_binaries"] is False, "Game binary claim")
    _assert(package_manifest["contains_game_scripts"] is False, "Game script claim")
    _assert(
        package_manifest["runtime_validation_status"] == "not_tested",
        "Package overstates runtime validation",
    )
    expected = sorted(package_manifest["allowed_files"] + ["package-manifest.json"])
    _assert(sorted(names) == expected, "Package differs from its explicit allowlist")
    _assert(
        not any(name.lower().endswith(".lua") for name in names),
        "Extracted Lua script escaped into the SDK package",
    )
    return sorted(names), package_manifest


def audit(
    *,
    registry_path: Path,
    generated_root: Path,
    package_path: Path,
    rebuild_package_path: Path,
    contract_path: Path,
    test_report_path: Path,
    release_evidence_path: Path,
    cache_report_path: Path,
) -> dict[str, Any]:
    output_manifest, output_manifest_sha256 = _validate_output(generated_root)
    generation = _read_json(generated_root / "sdk-generation.json")
    build_ids = list(generation["build_ids"])
    _assert(len(build_ids) == 2 and len(set(build_ids)) == 2, "Expected two builds")
    _assert(
        build_ids == sorted(build_ids, reverse=True), "Build order is not canonical"
    )
    _assert(
        generation["runtime_validation_status"] == "not_tested",
        "Generation overstates runtime validation",
    )

    adapter_manifests = [
        _read_json(generated_root / "adapters" / f"{build_id}.json")
        for build_id in build_ids
    ]
    bases = {item["capability_basis_id"] for item in adapter_manifests}
    _assert(len(bases) == 1, "Equivalent builds do not share one capability basis")
    basis_id = next(iter(bases))
    for build_id, manifest in zip(build_ids, adapter_manifests, strict=True):
        _assert(manifest["build_id"] == build_id, "Adapter build identity differs")
        _assert(manifest["capability_status"] == "requires_validation", "Unsafe status")
        _assert(manifest["runtime_validation_status"] == "not_tested", "Runtime lied")
        modules = manifest["modules"]
        _assert(len(modules) == 8636, "Unexpected Lua catalog size")
        names = [str(item["module_name"]) for item in modules]
        _assert(
            names == sorted(names) and len(names) == len(set(names)), "Catalog order"
        )

    loader = _read_json(generated_root / "loader-evaluation.json")
    _assert(
        loader["artifact_sha256"] == EXPECTED_LOADER_SHA256, "Loader digest differs"
    )
    _assert(
        loader["evaluation_status"] == "selected_candidate", "Loader status differs"
    )
    _assert(loader["installation_status"] == "not_installed", "Loader was installed")
    _assert(loader["runtime_validation_status"] == "not_tested", "Loader runtime lied")

    entries, package_manifest = _validate_zip(package_path)
    package_sha256 = _sha256(package_path, inspect=False)
    _assert(
        package_sha256 == _sha256(rebuild_package_path, inspect=False),
        "Independent SDK package rebuild is not byte-for-byte reproducible",
    )
    test_report = _read_json(test_report_path)
    _assert(test_report["status"] == "passed", "Offline SDK tests failed")
    _assert(test_report["same_plugin_binary"] is True, "Two plugin binaries were used")
    _assert(
        test_report["runtime_game_status"] == "not_tested", "Runtime tests were claimed"
    )
    _assert(
        sorted(test_report["build_ids"]) == sorted(build_ids),
        "Test build scope differs",
    )
    _assert(len(test_report["results"]) == 2, "Expected two adapter test results")
    _assert(
        all(
            item["status"] == "passed"
            and item["capability_basis_id"] == basis_id
            and int(item["module_count"]) == 8636
            for item in test_report["results"]
        ),
        "Offline adapter test result differs",
    )

    evidence = _read_json(release_evidence_path)
    contract_sha256 = _sha256(contract_path, inspect=False)
    _assert(evidence["package_sha256"] == package_sha256, "Release package differs")
    _assert(evidence["contract_sha256"] == contract_sha256, "Contract digest differs")
    _assert(evidence["offline_validation_status"] == "passed", "Offline status differs")
    _assert(
        evidence["runtime_validation_status"] == "not_tested", "Runtime status lied"
    )
    _assert(
        evidence["authorization"]["status"] == "not_requested", "Authorization lied"
    )

    cache_report = _read_json(cache_report_path)
    steps = {item["step_id"]: item for item in cache_report["steps"]}
    cache_step = steps.get("sdk.generation")
    _assert(cache_report["status"] == "completed", "Cache run failed")
    _assert(
        cache_step is not None
        and cache_step["status"] == "cache_hit"
        and cache_step["cache_status"] == "hit",
        "Identical SDK generation did not hit its complete cache",
    )

    uri = f"file:{registry_path.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        release = db.execute(
            """SELECT * FROM sdk_releases WHERE sdk_release_id=?""",
            (generation["release_id"],),
        ).fetchone()
        evaluations = db.execute(
            """SELECT build_id,capability_status,static_analysis_status,
                      required_tests_status,runtime_validation_status
               FROM capability_build_evaluations WHERE capability_basis_id=?
               ORDER BY build_id""",
            (basis_id,),
        ).fetchall()
        validations = db.execute(
            """SELECT validation_kind,validation_status,COUNT(*) AS count
               FROM capability_validations WHERE capability_basis_id=?
               GROUP BY validation_kind,validation_status""",
            (basis_id,),
        ).fetchall()
        authorization = db.execute(
            """SELECT authorization_status FROM runtime_authorizations
               WHERE package_sha256=?""",
            (package_sha256,),
        ).fetchone()
        loader_row = db.execute(
            """SELECT evaluation_status,installation_status,runtime_validation_status
               FROM loader_evaluations WHERE artifact_sha256=?""",
            (EXPECTED_LOADER_SHA256,),
        ).fetchone()

    _assert(user_version >= 8, "Unexpected registry migration level")
    _assert(integrity == "ok" and not foreign_keys, "SQLite integrity check failed")
    _assert(release is not None and release["status"] == "built", "Release not built")
    _assert(release["package_sha256"] == package_sha256, "Registry package differs")
    _assert(release["contract_sha256"] == contract_sha256, "Registry contract differs")
    _assert(len(evaluations) == 2, "Capability evaluations are incomplete")
    _assert(
        all(
            row["capability_status"] == "requires_validation"
            and row["static_analysis_status"] == "passed"
            and row["required_tests_status"] == "partial"
            and row["runtime_validation_status"] == "not_tested"
            for row in evaluations
        ),
        "Capability evaluation overstates readiness",
    )
    validation_counts = {
        (row["validation_kind"], row["validation_status"]): int(row["count"])
        for row in validations
    }
    _assert(validation_counts.get(("static_contract", "passed")) == 2, "Static tests")
    _assert(validation_counts.get(("offline_adapter", "passed")) == 2, "Adapter tests")
    _assert(validation_counts.get(("runtime_game", "not_tested")) == 2, "Runtime tests")
    _assert(authorization is not None and authorization[0] == "not_requested", "Auth")
    _assert(
        loader_row is not None
        and tuple(loader_row) == ("selected_candidate", "not_installed", "not_tested"),
        "Loader registry status differs",
    )
    return {
        "build_ids": build_ids,
        "cache_status": "hit",
        "capability_basis_id": basis_id,
        "contract_sha256": contract_sha256,
        "foreign_key_check": "ok",
        "integrity_check": integrity,
        "offline_validation_status": "passed",
        "output_file_count": len(output_manifest["files"]) + 1,
        "output_manifest_sha256": output_manifest_sha256,
        "package_entry_count": len(entries),
        "package_manifest_sdk_version": package_manifest["sdk_version"],
        "package_sha256": package_sha256,
        "runtime_authorization_status": "not_requested",
        "runtime_validation_status": "not_tested",
        "user_version": user_version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--generated-root", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--rebuild-package", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--test-report", type=Path, required=True)
    parser.add_argument("--release-evidence", type=Path, required=True)
    parser.add_argument("--cache-report", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            audit(
                registry_path=args.registry,
                generated_root=args.generated_root,
                package_path=args.package,
                rebuild_package_path=args.rebuild_package,
                contract_path=args.contract,
                test_report_path=args.test_report,
                release_evidence_path=args.release_evidence,
                cache_report_path=args.cache_report,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
