#!/usr/bin/env python3
"""Audit the final M6 SDK extension and distribution evidence read-only."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any

from modkit.sdk import verify_sdk_package

OLD_PLUGIN_SHA256 = "d623064583c6aba9b77b0ac77eea487039454b3a7f4cc46de9687534c1af3340"
API_IDS = {"aniimo.lua-module-catalog", "aniimo.build-identity"}
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


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _assert(isinstance(value, dict), f"Expected object: {path}")
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
                    f"Absolute path leaked: {path}",
                )
                carry = sample[-128:]
    return digest.hexdigest()


def _output_manifest(root: Path) -> str:
    path = root / "output-manifest.json"
    manifest = _json(path)
    files = manifest["files"]
    _assert(isinstance(files, list) and files, "Empty output manifest")
    for item in files:
        pure = PurePosixPath(str(item["path"]))
        _assert(not pure.is_absolute() and ".." not in pure.parts, "Unsafe path")
        target = root.joinpath(*pure.parts)
        _assert(target.is_file(), f"Missing output: {pure}")
        _assert(target.stat().st_size == int(item["size_bytes"]), "Output size")
        _assert(_sha256(target) == item["sha256"], f"Output digest: {pure}")
    return _sha256(path)


def audit(
    *,
    registry: Path,
    generated: Path,
    package: Path,
    rebuild_package: Path,
    contract: Path,
    test_report_path: Path,
    evidence_path: Path,
    cache_report_path: Path,
) -> dict[str, Any]:
    output_manifest_sha256 = _output_manifest(generated)
    generation = _json(generated / "sdk-generation.json")
    _assert(generation["release_key"].startswith("m6-"), "Wrong milestone key")
    _assert(set(generation["api_ids"]) == API_IDS, "API set differs")
    _assert(len(generation["build_ids"]) == 2, "Expected two builds")
    _assert(len(generation["capability_basis_ids"]) == 3, "Expected three bases")

    manifests = [
        _json(generated / "adapters" / f"{build_id}.json")
        for build_id in generation["build_ids"]
    ]
    _assert(all(item["schema_version"] == 2 for item in manifests), "Manifest v2")
    _assert(
        len({item["capability_basis_id"] for item in manifests}) == 1,
        "Catalog basis should be shared",
    )
    identity_bases = {
        item["build_identity"]["capability_basis_id"] for item in manifests
    }
    _assert(len(identity_bases) == 2, "Build identity bases must remain exact")
    _assert(
        all(
            item["capability_status"] == "requires_validation"
            and item["runtime_validation_status"] == "not_tested"
            and item["build_identity"]["capability_status"] == "requires_validation"
            for item in manifests
        ),
        "Capability status overstates runtime readiness",
    )
    optimization = _json(generated / "native-optimization-evaluation.json")
    _assert(
        optimization["decision"] == "not_needed"
        and optimization["advanced_native_matching_enabled"] is False
        and optimization["native_hook_count"] == 0,
        "Native matching was enabled without a capability need",
    )

    verified = verify_sdk_package(package)
    _assert(verified["schema_version"] == 2, "Package manifest is not hardened")
    _assert(
        verified["package_sha256"] == _sha256(rebuild_package, inspect=False),
        "Package rebuild differs",
    )
    report = _json(test_report_path)
    _assert(report["schema_version"] == 2 and report["status"] == "passed", "Tests")
    _assert(report["plugin_sha256"] == OLD_PLUGIN_SHA256, "Old plugin changed")
    _assert(report["plugin_compiled_sdk_version"] == "1.0.0", "Old SDK differs")
    _assert(report["adapter_sdk_version"] == "1.1.0", "New SDK differs")
    _assert(report["binary_compatibility_status"] == "passed", "A38 failed")
    _assert(
        report["old_contract_assembly_version"]
        == report["current_contract_assembly_version"]
        == "1.0.0.0",
        "Public assembly version changed",
    )
    _assert(report["runtime_game_status"] == "not_tested", "Runtime status lied")
    _assert(len(report["results"]) == 2, "Two build results required")

    evidence = _json(evidence_path)
    _assert(evidence["schema_version"] == 2, "Release evidence version")
    _assert(evidence["package_sha256"] == verified["package_sha256"], "Package")
    _assert(evidence["contract_sha256"] == _sha256(contract, inspect=False), "Contract")
    _assert(evidence["binary_compatibility_status"] == "passed", "Compatibility")
    _assert(evidence["distribution_verification_status"] == "passed", "Distribution")
    _assert(evidence["signature_status"] == "unsigned", "Signature status differs")
    _assert(evidence["runtime_validation_status"] == "not_tested", "Runtime lied")
    _assert(evidence["authorization"]["status"] == "not_requested", "Auth lied")

    cache_report = _json(cache_report_path)
    steps = {item["step_id"]: item for item in cache_report["steps"]}
    _assert(
        steps["sdk.generation"]["status"] == "cache_hit"
        and steps["sdk.generation"]["cache_status"] == "hit",
        "M6 generation cache missed",
    )

    uri = f"file:{registry.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        integrity = str(db.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        user_version = int(db.execute("PRAGMA user_version").fetchone()[0])
        release = db.execute(
            "SELECT status,package_sha256 FROM sdk_releases WHERE sdk_release_id=?",
            (generation["release_id"],),
        ).fetchone()
        evaluations = db.execute(
            """SELECT cb.api_id,cbe.capability_status,cbe.static_analysis_status,
                      cbe.required_tests_status,cbe.runtime_validation_status
               FROM capability_build_evaluations cbe JOIN capability_bases cb
                 ON cb.capability_basis_id=cbe.capability_basis_id
               WHERE cb.adapter_id=?""",
            (generation["adapter_id"],),
        ).fetchall()
        validations = db.execute(
            """SELECT validation_kind,validation_status,COUNT(*) AS count
               FROM capability_validations cv JOIN capability_bases cb
                 ON cb.capability_basis_id=cv.capability_basis_id
               WHERE cb.adapter_id=? GROUP BY validation_kind,validation_status""",
            (generation["adapter_id"],),
        ).fetchall()
        compatibility = db.execute(
            """SELECT status,old_plugin_sha256,old_contract_assembly_version
               FROM sdk_binary_compatibility_tests WHERE sdk_release_id=?""",
            (generation["release_id"],),
        ).fetchone()
        attestation = db.execute(
            """SELECT verification_status,signature_status
               FROM distribution_attestations WHERE sdk_release_id=?""",
            (generation["release_id"],),
        ).fetchone()

    _assert(user_version == 9, "Unexpected migration level")
    _assert(integrity == "ok" and not foreign_keys, "SQLite integrity failed")
    _assert(
        release is not None and tuple(release) == ("built", verified["package_sha256"]),
        "Release is not built",
    )
    _assert(len(evaluations) == 4, "Capability evaluations are incomplete")
    _assert({row["api_id"] for row in evaluations} == API_IDS, "Registry APIs differ")
    _assert(
        all(
            row["capability_status"] == "requires_validation"
            and row["static_analysis_status"] == "passed"
            and row["required_tests_status"] == "partial"
            and row["runtime_validation_status"] == "not_tested"
            for row in evaluations
        ),
        "Registry capability status differs",
    )
    counts = {
        (row["validation_kind"], row["validation_status"]): int(row["count"])
        for row in validations
    }
    _assert(counts.get(("static_contract", "passed")) == 4, "Static validations")
    _assert(counts.get(("offline_adapter", "passed")) == 4, "Adapter validations")
    _assert(counts.get(("runtime_game", "not_tested")) == 4, "Runtime validations")
    _assert(
        compatibility is not None
        and tuple(compatibility) == ("passed", OLD_PLUGIN_SHA256, "1.0.0.0"),
        "Binary compatibility evidence differs",
    )
    _assert(
        attestation is not None and tuple(attestation) == ("passed", "unsigned"),
        "Distribution attestation differs",
    )
    return {
        "api_ids": sorted(API_IDS),
        "binary_compatibility_status": "passed",
        "build_count": 2,
        "cache_status": "hit",
        "capability_basis_count": 3,
        "distribution_verification_status": "passed",
        "foreign_key_check": "ok",
        "integrity_check": integrity,
        "native_optimization_status": "not_needed",
        "old_plugin_sha256": OLD_PLUGIN_SHA256,
        "output_manifest_sha256": output_manifest_sha256,
        "package_file_count": verified["file_count"],
        "package_sha256": verified["package_sha256"],
        "runtime_authorization_status": "not_requested",
        "runtime_validation_status": "not_tested",
        "signature_status": "unsigned",
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
                registry=args.registry,
                generated=args.generated_root,
                package=args.package,
                rebuild_package=args.rebuild_package,
                contract=args.contract,
                test_report_path=args.test_report,
                evidence_path=args.release_evidence,
                cache_report_path=args.cache_report,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
