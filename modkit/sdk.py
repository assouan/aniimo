from __future__ import annotations

import csv
import json
import os
import shutil
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import ValidationError
from .registry import Registry, registry_writer_lock
from .reporting import RunReport, publish_report
from .util import (
    atomic_write_bytes,
    canonical_json_bytes,
    digest_json,
    fsync_directory,
    pretty_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

SDK_PRODUCER = {"name": "modkit.sdk", "version": "0.1.0"}
API_ID = "aniimo.lua-module-catalog"
PUBLIC_NAME = "Aniimo Lua Module Catalog"
BUILD_IDENTITY_API_ID = "aniimo.build-identity"
BUILD_IDENTITY_PUBLIC_NAME = "Aniimo Build Identity"
ABI_CONTEXT = "managed-netstandard2.1/no-native-hook"
RESOLVER_VERSION = "aniimo-lua-catalog-json/1.0.0"
LOADER_NAME = "BepInEx.Unity.IL2CPP"
LOADER_VERSION = "6.0.0-pre.2"
LOADER_SHA256 = "616ec7eb06cf11b2a0000e8fcef04d1b12bb58e84a2e0bdac9523234fc193ceb"
INTEROP_VERSION = "1.4.6.0"


@dataclass(frozen=True)
class SdkRoots:
    state: Path
    output: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _version_tuple(value: str) -> tuple[int, int, int]:
    try:
        parts = tuple(int(item) for item in value.split("."))
    except ValueError as exc:
        raise ValidationError(
            "Version SDK invalide.", error_code="sdk_version_invalid"
        ) from exc
    if len(parts) != 3 or any(item < 0 for item in parts):
        raise ValidationError("Version SDK invalide.", error_code="sdk_version_invalid")
    return parts


def _has_build_identity(sdk_version: str) -> bool:
    return _version_tuple(sdk_version) >= (1, 1, 0)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _active_catalog(db: Any, build_id: str) -> dict[str, Any]:
    analysis = db.execute(
        """SELECT la.lua_analysis_id,la.lua_analysis_key,ar.snapshot_id
           FROM lua_analyses la JOIN analysis_runs ar ON ar.analysis_id=la.analysis_id
           WHERE la.build_id=? AND la.status='completed'
           ORDER BY la.completed_at DESC LIMIT 1""",
        (build_id,),
    ).fetchone()
    if analysis is None:
        raise ValidationError(
            f"Analyse Lua M4 absente pour {build_id}.",
            error_code="sdk_lua_analysis_missing",
        )
    archive = db.execute(
        """SELECT component_revision_id,xdf_sha256,xdt_sha256,content_version
           FROM lua_archive_observations
           WHERE lua_analysis_id=? AND archive_role='active'""",
        (analysis["lua_analysis_id"],),
    ).fetchone()
    if archive is None:
        raise ValidationError(
            "Archive Lua active absente.", error_code="sdk_lua_archive_missing"
        )
    modules = [
        {
            "module_name": str(row["module_name"]),
            "parse_status": str(row["parse_status"]),
            "script_sha256": str(row["script_sha256"]),
        }
        for row in db.execute(
            """SELECT module_name,script_sha256,parse_status FROM lua_observations
               WHERE lua_analysis_id=? AND component_revision_id=?
               ORDER BY module_name,lua_script_id""",
            (analysis["lua_analysis_id"], archive["component_revision_id"]),
        )
    ]
    if not modules or any(
        item["parse_status"] not in {"parsed", "unsupported", "parse_error"}
        for item in modules
    ):
        raise ValidationError(
            "Catalogue Lua actif incomplet ou non interprété.",
            error_code="sdk_lua_catalog_incomplete",
        )
    names = [item["module_name"] for item in modules]
    if len(names) != len(set(names)):
        raise ValidationError(
            "Noms de modules Lua ambigus.", error_code="sdk_lua_catalog_ambiguous"
        )
    bridge = db.execute(
        """SELECT cr.content_sha256 FROM build_components bc
           JOIN component_revisions cr
             ON cr.component_revision_id=bc.component_revision_id
           WHERE bc.build_id=? AND bc.role='lua_bridge_reference'""",
        (build_id,),
    ).fetchone()
    if bridge is None:
        raise ValidationError(
            "Révision du bridge Lua absente.", error_code="sdk_lua_bridge_missing"
        )
    return {
        "build_id": build_id,
        "catalog_sha256": digest_json(modules),
        "content_version": str(archive["content_version"]),
        "lua_analysis_id": str(analysis["lua_analysis_id"]),
        "lua_analysis_key": str(analysis["lua_analysis_key"]),
        "modules": modules,
        "snapshot_id": str(analysis["snapshot_id"]),
        "xdf_sha256": str(archive["xdf_sha256"]),
        "xdt_sha256": str(archive["xdt_sha256"]),
        "xlua_sha256": str(bridge["content_sha256"]),
    }


def _dependencies(
    catalog: dict[str, Any], adapter_version: str
) -> list[dict[str, Any]]:
    return [
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "active-lua-module-name-and-hash-set",
            "dependency_kind": "data",
            "evidence": {"module_count": len(catalog["modules"])},
            "required_revision_or_hash": catalog["catalog_sha256"],
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "xlua-native-bridge",
            "dependency_kind": "component",
            "evidence": {"classification": "reference_only"},
            "required_revision_or_hash": catalog["xlua_sha256"],
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "catalog-manifest-resolver",
            "dependency_kind": "resolver",
            "evidence": {},
            "required_revision_or_hash": adapter_version,
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "public-managed-contract",
            "dependency_kind": "abi",
            "evidence": {"native_hook_count": 0},
            "required_revision_or_hash": ABI_CONTEXT,
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "same-plugin-two-build-offline-suite",
            "dependency_kind": "test",
            "evidence": {"runtime_game_test_required_separately": True},
            "required_revision_or_hash": "sdk-contract-suite/1",
            "resolver_version": RESOLVER_VERSION,
            "status": "not_tested",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": LOADER_NAME,
            "dependency_kind": "loader",
            "evidence": {
                "artifact_sha256": LOADER_SHA256,
                "bundled_il2cppinterop_version": INTEROP_VERSION,
                "installation_status": "not_installed",
            },
            "required_revision_or_hash": LOADER_VERSION,
            "resolver_version": RESOLVER_VERSION,
            "status": "not_tested",
        },
    ]


def _identity_dependencies(
    catalog: dict[str, Any], adapter_version: str
) -> list[dict[str, Any]]:
    return [
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "exact-build-and-snapshot-identity",
            "dependency_kind": "data",
            "evidence": {"snapshot_id": catalog["snapshot_id"]},
            "required_revision_or_hash": catalog["build_id"],
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "build-manifest-resolver",
            "dependency_kind": "resolver",
            "evidence": {"native_hook_count": 0},
            "required_revision_or_hash": adapter_version,
            "resolver_version": RESOLVER_VERSION,
            "status": "resolved",
        },
        {
            "abi_context": ABI_CONTEXT,
            "dependency_id": "binary-compatibility-old-plugin-suite",
            "dependency_kind": "test",
            "evidence": {"runtime_game_test_required_separately": True},
            "required_revision_or_hash": "sdk-contract-suite/2",
            "resolver_version": RESOLVER_VERSION,
            "status": "not_tested",
        },
    ]


def _basis(
    dependencies: list[dict[str, Any]], adapter_id: str, api_id: str = API_ID
) -> tuple[str, str]:
    fingerprint = digest_json(dependencies)
    basis_id = f"capability-basis:{digest_json([api_id, adapter_id, fingerprint, ABI_CONTEXT])}"
    return basis_id, fingerprint


def _output_manifest(staging: Path, release_key: str) -> tuple[bytes, str]:
    files = []
    for path in sorted(staging.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_file() and path.name != "output-manifest.json":
            digest, size = sha256_file(path)
            files.append(
                {
                    "path": path.relative_to(staging).as_posix(),
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
    value = {"files": files, "release_key": release_key, "schema_version": 1}
    data = pretty_json_bytes(value)
    return data, sha256_bytes(data)


def _valid_output(destination: Path, expected_sha256: str | None) -> bool:
    manifest = destination / "output-manifest.json"
    return bool(
        expected_sha256
        and manifest.is_file()
        and sha256_file(manifest)[0] == expected_sha256
    )


def generate_sdk_release(
    *,
    roots: SdkRoots,
    build_ids: list[str],
    sdk_version: str,
    adapter_version: str,
    migrations_root: Path,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    """Generate exact build manifests for the safe Lua catalog capability."""
    if len(build_ids) < 2 or len(build_ids) != len(set(build_ids)):
        raise ValidationError(
            "M5 exige au moins deux builds distincts.",
            error_code="sdk_two_builds_required",
        )
    # Release identity is based on a set of exact builds, not CLI argument order.
    build_ids = sorted(build_ids, reverse=True)
    extended_contract = _has_build_identity(sdk_version)
    run_id = workflow_run_id or f"run-m5-{uuid.uuid4().hex}"
    report = RunReport(run_id, "sdk-generation")
    roots.output.mkdir(parents=True, exist_ok=True)
    with (
        registry_writer_lock(roots.state),
        Registry(roots.state / "registry.sqlite", migrations_root) as registry,
    ):
        catalogs = [_active_catalog(registry.db, build_id) for build_id in build_ids]
        adapter_id = f"adapter:aniimo-lua-catalog:{adapter_version}"
        manifests: list[dict[str, Any]] = []
        for catalog in catalogs:
            dependencies = _dependencies(catalog, adapter_version)
            basis_id, fingerprint = _basis(dependencies, adapter_id)
            manifest: dict[str, Any] = {
                "adapter": {
                    "adapter_id": adapter_id,
                    "adapter_version": adapter_version,
                    "resolver_version": RESOLVER_VERSION,
                },
                "api_id": API_ID,
                "build_id": catalog["build_id"],
                "capability_basis_id": basis_id,
                "capability_status": "requires_validation",
                "catalog_sha256": catalog["catalog_sha256"],
                "dependencies": dependencies,
                "dependency_fingerprint": fingerprint,
                "external_authorization_status": "not_requested",
                "lua_analysis_id": catalog["lua_analysis_id"],
                "modules": catalog["modules"],
                "runtime_environment_id": "aniimo-windows-x64-il2cpp-bepinex6-pre2",
                "runtime_validation_status": "not_tested",
                "schema_version": 2 if extended_contract else 1,
                "sdk_version": sdk_version,
                "snapshot_id": catalog["snapshot_id"],
                "source_archive": {
                    "content_version": catalog["content_version"],
                    "role": "active",
                    "xdf_sha256": catalog["xdf_sha256"],
                    "xdt_sha256": catalog["xdt_sha256"],
                },
            }
            if extended_contract:
                identity_dependencies = _identity_dependencies(catalog, adapter_version)
                identity_basis_id, identity_fingerprint = _basis(
                    identity_dependencies, adapter_id, BUILD_IDENTITY_API_ID
                )
                manifest["build_identity"] = {
                    "api_id": BUILD_IDENTITY_API_ID,
                    "architecture": "x86_64",
                    "backend": "Unity IL2CPP",
                    "capability_basis_id": identity_basis_id,
                    "capability_status": "requires_validation",
                    "dependencies": identity_dependencies,
                    "dependency_fingerprint": identity_fingerprint,
                    "runtime_validation_status": "not_tested",
                }
            manifests.append(manifest)
        release_basis = {
            "adapter_version": adapter_version,
            "builds": [
                {
                    "basis": item["capability_basis_id"],
                    "build": item["build_id"],
                    "catalog": item["catalog_sha256"],
                    **(
                        {
                            "build_identity_basis": item["build_identity"][
                                "capability_basis_id"
                            ]
                        }
                        if extended_contract
                        else {}
                    ),
                }
                for item in manifests
            ],
            "sdk_version": sdk_version,
        }
        release_prefix = "m6" if extended_contract else "m5"
        release_key = f"{release_prefix}-{digest_json(release_basis)}"
        release_id = f"sdk-release:{sdk_version}:{release_key}"
        destination = roots.output / "sdk" / f"v{sdk_version}" / release_key
        cached = registry.db.execute(
            """SELECT sdk_release_id,output_manifest_sha256 FROM sdk_releases
               WHERE sdk_release_key=?""",
            (release_key,),
        ).fetchone()
        if cached is not None and _valid_output(
            destination, cached["output_manifest_sha256"]
        ):
            report.add_step(
                "sdk.generation",
                "sdk_generation",
                category="publication",
                status="cache_hit",
                reason="complete_sdk_release_key_match",
                cache_status="hit",
                tool_name=SDK_PRODUCER["name"],
                tool_version=SDK_PRODUCER["version"],
            )
            report.finish("completed")
            publish_report(roots.output, report.public())
            summary = read_json(destination / "sdk-generation.json")
            return {
                **summary,
                "cache_status": "hit",
                "output_root": destination.relative_to(roots.output).as_posix(),
                "workflow_run_id": run_id,
            }
        conflicting = registry.db.execute(
            "SELECT sdk_release_key FROM sdk_releases WHERE sdk_version=?",
            (sdk_version,),
        ).fetchone()
        if conflicting is not None:
            raise ValidationError(
                "La version SDK existe avec une autre base ; incrément de version requis.",
                error_code="sdk_version_basis_conflict",
            )

        with report.step(
            "sdk.generation",
            "sdk_generation",
            category="publication",
            cache_status="miss",
            tool_name=SDK_PRODUCER["name"],
            tool_version=SDK_PRODUCER["version"],
        ) as step:
            destination.parent.mkdir(parents=True, exist_ok=True)
            staging = Path(
                tempfile.mkdtemp(prefix=f".{release_key}.", dir=destination.parent)
            )
            try:
                (staging / "adapters").mkdir(parents=True)
                for manifest in manifests:
                    (staging / "adapters" / f"{manifest['build_id']}.json").write_bytes(
                        pretty_json_bytes(manifest)
                    )
                loader = {
                    "architecture": "x86_64",
                    "artifact_sha256": LOADER_SHA256,
                    "backend": "Unity IL2CPP",
                    "bundled_cpp2il_version": "2022.1.0.0",
                    "bundled_il2cppinterop_version": INTEROP_VERSION,
                    "documentation": "https://docs.bepinex.dev/master/articles/user_guide/installation/unity_il2cpp.html",
                    "evaluation_status": "selected_candidate",
                    "installation_status": "not_installed",
                    "loader": LOADER_NAME,
                    "platform": "windows-x64",
                    "reason": "official_il2cpp_loader_candidate_requires_authorized_runtime_validation",
                    "runtime_validation_status": "not_tested",
                    "schema_version": 1,
                    "version": LOADER_VERSION,
                }
                (staging / "loader-evaluation.json").write_bytes(
                    pretty_json_bytes(loader)
                )
                if extended_contract:
                    (staging / "native-optimization-evaluation.json").write_bytes(
                        pretty_json_bytes(
                            {
                                "advanced_native_matching_enabled": False,
                                "decision": "not_needed",
                                "native_hook_count": 0,
                                "reason": (
                                    "published_capabilities_use_exact_static_manifests_"
                                    "and_require_no_native_resolution"
                                ),
                                "schema_version": 1,
                            }
                        )
                    )
                generation = {
                    "adapter_id": adapter_id,
                    "api_id": API_ID,
                    "api_ids": (
                        [API_ID, BUILD_IDENTITY_API_ID]
                        if extended_contract
                        else [API_ID]
                    ),
                    "build_ids": build_ids,
                    "capability_basis_ids": sorted(
                        {
                            basis
                            for item in manifests
                            for basis in (
                                [item["capability_basis_id"]]
                                + (
                                    [item["build_identity"]["capability_basis_id"]]
                                    if extended_contract
                                    else []
                                )
                            )
                        }
                    ),
                    "public_name": PUBLIC_NAME,
                    "release_id": release_id,
                    "release_key": release_key,
                    "runtime_validation_status": "not_tested",
                    "schema_version": 1,
                    "sdk_version": sdk_version,
                }
                (staging / "sdk-generation.json").write_bytes(
                    pretty_json_bytes(generation)
                )
                capability_rows = []
                for item in manifests:
                    capability_rows.append(
                        {
                            "schema_version": 1,
                            "build_id": item["build_id"],
                            "analysis_id": item["lua_analysis_id"],
                            "api_id": API_ID,
                            "sdk_version": sdk_version,
                            "adapter_id": adapter_id,
                            "capability_basis_id": item["capability_basis_id"],
                            "dependency_fingerprint": item["dependency_fingerprint"],
                            "runtime_environment_id": item["runtime_environment_id"],
                            "capability_status": item["capability_status"],
                            "required_tests_status": "not_tested",
                            "runtime_validation_status": "not_tested",
                            "external_authorization_status": "not_requested",
                            "evidence_id": item["lua_analysis_id"],
                        }
                    )
                    if extended_contract:
                        identity = item["build_identity"]
                        capability_rows.append(
                            {
                                "schema_version": 2,
                                "build_id": item["build_id"],
                                "analysis_id": item["lua_analysis_id"],
                                "api_id": BUILD_IDENTITY_API_ID,
                                "sdk_version": sdk_version,
                                "adapter_id": adapter_id,
                                "capability_basis_id": identity["capability_basis_id"],
                                "dependency_fingerprint": identity[
                                    "dependency_fingerprint"
                                ],
                                "runtime_environment_id": item[
                                    "runtime_environment_id"
                                ],
                                "capability_status": identity["capability_status"],
                                "required_tests_status": "not_tested",
                                "runtime_validation_status": "not_tested",
                                "external_authorization_status": "not_requested",
                                "evidence_id": item["lua_analysis_id"],
                            }
                        )
                _write_csv(
                    staging / "capabilities.csv",
                    list(capability_rows[0]),
                    capability_rows,
                )
                dependency_rows = []
                seen_dependencies: set[tuple[str, str, str]] = set()
                for item in manifests:
                    dependency_sets = [
                        (item["capability_basis_id"], item["dependencies"])
                    ]
                    if extended_contract:
                        dependency_sets.append(
                            (
                                item["build_identity"]["capability_basis_id"],
                                item["build_identity"]["dependencies"],
                            )
                        )
                    for dependency_basis_id, dependencies in dependency_sets:
                        for dependency in dependencies:
                            key = (
                                dependency_basis_id,
                                dependency["dependency_kind"],
                                dependency["dependency_id"],
                            )
                            if key in seen_dependencies:
                                continue
                            seen_dependencies.add(key)
                            dependency_rows.append(
                                {
                                    "schema_version": 2 if extended_contract else 1,
                                    "api_id": (
                                        BUILD_IDENTITY_API_ID
                                        if dependency_basis_id
                                        == item.get("build_identity", {}).get(
                                            "capability_basis_id"
                                        )
                                        else API_ID
                                    ),
                                    "capability_basis_id": dependency_basis_id,
                                    "dependency_kind": dependency["dependency_kind"],
                                    "dependency_id": dependency["dependency_id"],
                                    "required_revision_or_hash": dependency[
                                        "required_revision_or_hash"
                                    ],
                                    "resolver_version": dependency["resolver_version"],
                                    "abi_context": dependency["abi_context"],
                                    "status": dependency["status"],
                                    "evidence_id": item["lua_analysis_id"],
                                }
                            )
                _write_csv(
                    staging / "capability_dependencies.csv",
                    list(dependency_rows[0]),
                    dependency_rows,
                )
                (staging / "README.md").write_text(
                    "# SDK Aniimo généré\n\n"
                    "Cette livraison expose uniquement un catalogue de modules Lua par "
                    + (
                        "manifeste et l’identité exacte du build. "
                        if extended_contract
                        else "manifeste. "
                    )
                    + "Elle ne contient aucun hook natif, binaire du jeu ou script "
                    "extrait. La validation dans le processus de jeu reste `not_tested`.\n",
                    encoding="utf-8",
                )
                manifest_bytes, manifest_sha256 = _output_manifest(staging, release_key)
                (staging / "output-manifest.json").write_bytes(manifest_bytes)
                if destination.exists():
                    raise ValidationError(
                        "Destination SDK déjà présente sans cache valide.",
                        error_code="sdk_output_conflict",
                    )
                os.replace(staging, destination)
                fsync_directory(destination.parent)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
            step.input_item_count = sum(len(item["modules"]) for item in manifests)
            step.output_item_count = sum(
                1 for path in destination.rglob("*") if path.is_file()
            )

        registry.transaction()
        try:
            registry.db.execute(
                """INSERT INTO sdk_releases(
                       sdk_release_id,sdk_release_key,sdk_version,contract_sha256,
                       package_sha256,output_manifest_sha256,status,created_at,completed_at
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    release_id,
                    release_key,
                    sdk_version,
                    None,
                    None,
                    manifest_sha256,
                    "draft",
                    _utc_now(),
                    None,
                ),
            )
            registry.db.execute(
                """INSERT OR IGNORE INTO adapter_releases(
                       adapter_id,adapter_version,backend,resolver_version,
                       loader_kind,package_sha256,created_at
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    adapter_id,
                    adapter_version,
                    "il2cpp-static-catalog",
                    RESOLVER_VERSION,
                    LOADER_NAME,
                    None,
                    _utc_now(),
                ),
            )
            registry.db.execute(
                """INSERT OR IGNORE INTO capabilities(
                       api_id,public_name,contract_version,capability_kind,
                       client_requirement,description
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    API_ID,
                    PUBLIC_NAME,
                    sdk_version,
                    "read_only_metadata",
                    "host_metadata_only",
                    "Exact catalog of observed Lua modules without executing game code.",
                ),
            )
            if extended_contract:
                registry.db.execute(
                    """INSERT OR IGNORE INTO capabilities(
                           api_id,public_name,contract_version,capability_kind,
                           client_requirement,description
                       ) VALUES(?,?,?,?,?,?)""",
                    (
                        BUILD_IDENTITY_API_ID,
                        BUILD_IDENTITY_PUBLIC_NAME,
                        sdk_version,
                        "read_only_metadata",
                        "host_metadata_only",
                        "Exact declared build identity without native resolution.",
                    ),
                )
            for manifest in manifests:
                basis_id = manifest["capability_basis_id"]
                registry.db.execute(
                    """INSERT OR IGNORE INTO capability_bases(
                           capability_basis_id,api_id,adapter_id,dependency_fingerprint,
                           abi_context,created_at
                       ) VALUES(?,?,?,?,?,?)""",
                    (
                        basis_id,
                        API_ID,
                        adapter_id,
                        manifest["dependency_fingerprint"],
                        ABI_CONTEXT,
                        _utc_now(),
                    ),
                )
                for dependency in manifest["dependencies"]:
                    dependency_id = f"capability-dependency:{digest_json([basis_id, dependency['dependency_kind'], dependency['dependency_id']])}"
                    registry.db.execute(
                        """INSERT OR IGNORE INTO capability_dependencies(
                               capability_dependency_id,capability_basis_id,
                               dependency_kind,dependency_id,required_revision_or_hash,
                               resolver_version,abi_context,status,evidence_json
                           ) VALUES(?,?,?,?,?,?,?,?,?)""",
                        (
                            dependency_id,
                            basis_id,
                            dependency["dependency_kind"],
                            dependency["dependency_id"],
                            dependency["required_revision_or_hash"],
                            dependency["resolver_version"],
                            dependency["abi_context"],
                            dependency["status"],
                            canonical_json_bytes(dependency["evidence"]).decode(
                                "utf-8"
                            ),
                        ),
                    )
                evaluation_id = f"capability-build-evaluation:{digest_json([basis_id, manifest['build_id']])}"
                registry.db.execute(
                    """INSERT INTO capability_build_evaluations(
                           capability_build_evaluation_id,capability_basis_id,build_id,
                           lua_analysis_id,capability_status,static_analysis_status,
                           required_tests_status,runtime_validation_status,transfer_rule,
                           evidence_json,evaluated_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        evaluation_id,
                        basis_id,
                        manifest["build_id"],
                        manifest["lua_analysis_id"],
                        "requires_validation",
                        "passed",
                        "not_tested",
                        "not_tested",
                        "exact_catalog_and_bridge_dependency_fingerprint",
                        canonical_json_bytes(
                            {
                                "catalog_sha256": manifest["catalog_sha256"],
                                "runtime_hook_enabled": False,
                            }
                        ).decode("utf-8"),
                        _utc_now(),
                    ),
                )
                if extended_contract:
                    identity = manifest["build_identity"]
                    identity_basis_id = identity["capability_basis_id"]
                    registry.db.execute(
                        """INSERT OR IGNORE INTO capability_bases(
                               capability_basis_id,api_id,adapter_id,
                               dependency_fingerprint,abi_context,created_at
                           ) VALUES(?,?,?,?,?,?)""",
                        (
                            identity_basis_id,
                            BUILD_IDENTITY_API_ID,
                            adapter_id,
                            identity["dependency_fingerprint"],
                            ABI_CONTEXT,
                            _utc_now(),
                        ),
                    )
                    for dependency in identity["dependencies"]:
                        dependency_id = "capability-dependency:" + digest_json(
                            [
                                identity_basis_id,
                                dependency["dependency_kind"],
                                dependency["dependency_id"],
                            ]
                        )
                        registry.db.execute(
                            """INSERT OR IGNORE INTO capability_dependencies(
                                   capability_dependency_id,capability_basis_id,
                                   dependency_kind,dependency_id,
                                   required_revision_or_hash,resolver_version,
                                   abi_context,status,evidence_json
                               ) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (
                                dependency_id,
                                identity_basis_id,
                                dependency["dependency_kind"],
                                dependency["dependency_id"],
                                dependency["required_revision_or_hash"],
                                dependency["resolver_version"],
                                dependency["abi_context"],
                                dependency["status"],
                                canonical_json_bytes(dependency["evidence"]).decode(
                                    "utf-8"
                                ),
                            ),
                        )
                    identity_evaluation_id = (
                        "capability-build-evaluation:"
                        + digest_json([identity_basis_id, manifest["build_id"]])
                    )
                    registry.db.execute(
                        """INSERT INTO capability_build_evaluations(
                               capability_build_evaluation_id,capability_basis_id,
                               build_id,lua_analysis_id,capability_status,
                               static_analysis_status,required_tests_status,
                               runtime_validation_status,transfer_rule,evidence_json,
                               evaluated_at
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            identity_evaluation_id,
                            identity_basis_id,
                            manifest["build_id"],
                            manifest["lua_analysis_id"],
                            "requires_validation",
                            "passed",
                            "not_tested",
                            "not_tested",
                            "exact_build_manifest_only",
                            canonical_json_bytes(
                                {
                                    "native_hook_enabled": False,
                                    "snapshot_id": manifest["snapshot_id"],
                                }
                            ).decode("utf-8"),
                            _utc_now(),
                        ),
                    )
            registry.db.execute(
                """INSERT OR IGNORE INTO loader_evaluations(
                       loader_evaluation_id,loader_name,loader_version,platform,
                       backend,artifact_sha256,evaluation_status,installation_status,
                       runtime_validation_status,evidence_json,evaluated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"loader-evaluation:{digest_json([LOADER_NAME, LOADER_VERSION, LOADER_SHA256])}",
                    LOADER_NAME,
                    LOADER_VERSION,
                    "windows-x64",
                    "Unity IL2CPP",
                    LOADER_SHA256,
                    "selected_candidate",
                    "not_installed",
                    "not_tested",
                    canonical_json_bytes(loader).decode("utf-8"),
                    _utc_now(),
                ),
            )
            registry.commit()
        except BaseException:
            registry.rollback()
            raise

    report.finish("completed")
    publish_report(roots.output, report.public())
    return {
        **generation,
        "cache_status": "miss",
        "output_manifest_sha256": manifest_sha256,
        "output_root": destination.relative_to(roots.output).as_posix(),
        "workflow_run_id": run_id,
    }


def package_sdk_release(
    *,
    compiled_root: Path,
    generated_root: Path,
    documentation_path: Path,
    destination: Path,
) -> dict[str, Any]:
    """Create a deterministic SDK ZIP from an explicit publication allowlist."""
    generation = read_json(generated_root / "sdk-generation.json")
    extended_contract = _has_build_identity(str(generation["sdk_version"]))
    required = {
        "lib/netstandard2.1/GameModAPI.Contracts.dll": compiled_root
        / "GameModAPI.Contracts.dll",
        "lib/net8.0/GameModAPI.Runtime.dll": compiled_root / "GameModAPI.Runtime.dll",
        "lib/net8.0/GameModAPI.Adapter.Aniimo.dll": compiled_root
        / "GameModAPI.Adapter.Aniimo.dll",
        "mods/LuaCatalogExample.dll": compiled_root / "LuaCatalogExample.dll",
        "README.md": documentation_path,
        "loader-evaluation.json": generated_root / "loader-evaluation.json",
    }
    if extended_contract:
        required["native-optimization-evaluation.json"] = (
            generated_root / "native-optimization-evaluation.json"
        )
    for adapter in sorted((generated_root / "adapters").glob("*.json")):
        required[f"adapters/{adapter.name}"] = adapter
    missing = [logical for logical, path in required.items() if not path.is_file()]
    if missing:
        raise ValidationError(
            f"Fichiers SDK compilés absents : {', '.join(missing)}",
            error_code="sdk_compiled_file_missing",
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    payloads = {logical: source.read_bytes() for logical, source in required.items()}
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for logical_path, data in sorted(payloads.items()):
                info = zipfile.ZipInfo(logical_path, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
            package_manifest = {
                "allowed_files": sorted(required),
                "build_ids": generation["build_ids"],
                "contains_game_binaries": False,
                "contains_game_scripts": False,
                "runtime_validation_status": "not_tested",
                "schema_version": 2 if extended_contract else 1,
                "sdk_version": generation["sdk_version"],
            }
            if extended_contract:
                package_manifest.update(
                    {
                        "api_ids": generation["api_ids"],
                        "binary_compatibility_required": True,
                        "contract_assembly_version": "1.0.0.0",
                        "files": [
                            {
                                "path": logical,
                                "sha256": sha256_bytes(data),
                                "size_bytes": len(data),
                            }
                            for logical, data in sorted(payloads.items())
                        ],
                    }
                )
            info = zipfile.ZipInfo(
                "package-manifest.json", date_time=(1980, 1, 1, 0, 0, 0)
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, pretty_json_bytes(package_manifest))
        os.replace(temporary, destination)
        fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)
    digest, size = sha256_file(destination)
    return {
        "build_ids": generation["build_ids"],
        "file_count": len(required) + 1,
        "package": destination.as_posix(),
        "package_sha256": digest,
        "package_size_bytes": size,
        "runtime_validation_status": "not_tested",
        "sdk_version": generation["sdk_version"],
    }


def verify_sdk_package(
    path: Path, *, expected_sha256: str | None = None
) -> dict[str, Any]:
    """Verify a published SDK ZIP and its internal distribution allowlist."""
    package_sha256, package_size = sha256_file(path)
    if expected_sha256 is not None and package_sha256 != expected_sha256:
        raise ValidationError(
            "Le hash du package SDK diffère.", error_code="sdk_package_hash_mismatch"
        )
    if package_size > 128 * 1024 * 1024:
        raise ValidationError(
            "Package SDK trop volumineux.", error_code="sdk_package_too_large"
        )
    allowed_prefixes = ("adapters/", "lib/", "mods/")
    allowed_roots = {
        "README.md",
        "loader-evaluation.json",
        "native-optimization-evaluation.json",
        "package-manifest.json",
    }
    allowed_libraries = {
        "lib/net8.0/GameModAPI.Adapter.Aniimo.dll",
        "lib/net8.0/GameModAPI.Runtime.dll",
        "lib/netstandard2.1/GameModAPI.Contracts.dll",
    }
    allowed_mods = {"mods/LuaCatalogExample.dll"}
    with zipfile.ZipFile(path) as archive:
        names: list[str] = []
        uncompressed_size = 0
        for info in archive.infolist():
            pure = PurePosixPath(info.filename)
            if (
                info.is_dir()
                or pure.is_absolute()
                or ".." in pure.parts
                or info.flag_bits & 1
                or info.date_time != (1980, 1, 1, 0, 0, 0)
                or not (
                    info.filename in allowed_roots
                    or info.filename.startswith(allowed_prefixes)
                )
            ):
                raise ValidationError(
                    "Entrée interdite dans le package SDK.",
                    error_code="sdk_package_entry_forbidden",
                )
            if (
                info.filename.startswith("lib/")
                and info.filename not in allowed_libraries
            ):
                raise ValidationError(
                    "Assembly non autorisée dans le package SDK.",
                    error_code="sdk_package_entry_forbidden",
                )
            if info.filename.startswith("mods/") and info.filename not in allowed_mods:
                raise ValidationError(
                    "Mod non autorisé dans le package SDK.",
                    error_code="sdk_package_entry_forbidden",
                )
            if info.filename.startswith("adapters/"):
                stem = pure.name.removesuffix(".json")
                digest = stem.removeprefix("build-")
                if (
                    pure.parent.as_posix() != "adapters"
                    or not pure.name.endswith(".json")
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                ):
                    raise ValidationError(
                        "Manifest d’adaptateur non autorisé.",
                        error_code="sdk_package_entry_forbidden",
                    )
            if info.filename.lower().endswith(".lua"):
                raise ValidationError(
                    "Script Lua interdit dans le package SDK.",
                    error_code="sdk_package_entry_forbidden",
                )
            uncompressed_size += info.file_size
            if (
                info.file_size > 64 * 1024 * 1024
                or uncompressed_size > 128 * 1024 * 1024
            ):
                raise ValidationError(
                    "Contenu décompressé du package SDK trop volumineux.",
                    error_code="sdk_package_too_large",
                )
            names.append(info.filename)
        if len(names) != len(set(names)):
            raise ValidationError(
                "Entrée dupliquée dans le package SDK.",
                error_code="sdk_package_duplicate_entry",
            )
        try:
            package_manifest_bytes = archive.read("package-manifest.json")
            manifest = json.loads(package_manifest_bytes.decode("utf-8"))
        except (KeyError, UnicodeDecodeError, ValueError) as exc:
            raise ValidationError(
                "Manifeste du package SDK invalide.",
                error_code="sdk_package_manifest_invalid",
            ) from exc
        schema_version = manifest.get("schema_version")
        if schema_version not in {1, 2}:
            raise ValidationError(
                "Version de manifeste SDK inconnue.",
                error_code="sdk_package_manifest_invalid",
            )
        allowed_files = manifest.get("allowed_files")
        if (
            not isinstance(allowed_files, list)
            or sorted(allowed_files) != sorted(set(names) - {"package-manifest.json"})
            or manifest.get("contains_game_binaries") is not False
            or manifest.get("contains_game_scripts") is not False
            or manifest.get("runtime_validation_status") != "not_tested"
        ):
            raise ValidationError(
                "Allowlist ou statut du package SDK invalide.",
                error_code="sdk_package_manifest_invalid",
            )
        if schema_version == 2:
            records = manifest.get("files")
            if not isinstance(records, list):
                raise ValidationError(
                    "Empreintes de distribution absentes.",
                    error_code="sdk_package_manifest_invalid",
                )
            observed_records = []
            for name in sorted(set(names) - {"package-manifest.json"}):
                data = archive.read(name)
                observed_records.append(
                    {
                        "path": name,
                        "sha256": sha256_bytes(data),
                        "size_bytes": len(data),
                    }
                )
            if records != observed_records:
                raise ValidationError(
                    "Empreinte interne du package SDK invalide.",
                    error_code="sdk_package_content_mismatch",
                )
            if (
                manifest.get("binary_compatibility_required") is not True
                or manifest.get("contract_assembly_version") != "1.0.0.0"
            ):
                raise ValidationError(
                    "Contrat de compatibilité binaire absent.",
                    error_code="sdk_package_manifest_invalid",
                )
    return {
        "build_ids": manifest["build_ids"],
        "entries": sorted(names),
        "file_count": len(names),
        "package_sha256": package_sha256,
        "package_manifest_sha256": sha256_bytes(package_manifest_bytes),
        "package_size_bytes": package_size,
        "runtime_validation_status": "not_tested",
        "schema_version": schema_version,
        "sdk_version": manifest["sdk_version"],
        "status": "valid",
    }


def _validate_package(path: Path) -> list[str]:
    return list(verify_sdk_package(path)["entries"])


def finalize_sdk_release(
    *,
    roots: SdkRoots,
    generated_root: Path,
    package_path: Path,
    contract_path: Path,
    test_report_path: Path,
    migrations_root: Path,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    """Record offline tests and package identity while preserving runtime uncertainty."""
    generation = read_json(generated_root / "sdk-generation.json")
    test_report = read_json(test_report_path)
    build_ids = list(generation["build_ids"])
    extended_contract = _has_build_identity(str(generation["sdk_version"]))
    expected_report_schema = 2 if extended_contract else 1
    if (
        test_report.get("schema_version") != expected_report_schema
        or test_report.get("status") != "passed"
        or sorted(test_report.get("build_ids", [])) != sorted(build_ids)
        or sorted(item.get("build_id") for item in test_report.get("results", []))
        != sorted(build_ids)
        or test_report.get("same_plugin_binary") is not True
        or test_report.get("runtime_game_status") != "not_tested"
        or (
            extended_contract
            and (
                test_report.get("binary_compatibility_status") != "passed"
                or test_report.get("plugin_compiled_sdk_version") != "1.0.0"
                or test_report.get("adapter_sdk_version") != generation["sdk_version"]
                or test_report.get("old_contract_assembly_version") != "1.0.0.0"
            )
        )
    ):
        raise ValidationError(
            "Rapport de tests SDK invalide ou incomplet.",
            error_code="sdk_test_report_invalid",
        )
    verification = verify_sdk_package(package_path)
    entries = list(verification["entries"])
    if verification["sdk_version"] != generation["sdk_version"] or sorted(
        verification["build_ids"]
    ) != sorted(build_ids):
        raise ValidationError(
            "Le package ne correspond pas à la release générée.",
            error_code="sdk_package_release_mismatch",
        )
    package_sha256 = str(verification["package_sha256"])
    package_size = int(verification["package_size_bytes"])
    contract_sha256 = sha256_file(contract_path)[0]
    run_id = workflow_run_id or f"run-sdk-finalize-{uuid.uuid4().hex}"
    report = RunReport(run_id, "sdk-finalization")
    report.metadata = {
        "package_sha256": package_sha256,
        "runtime_validation_status": "not_tested",
        "sdk_version": generation["sdk_version"],
    }
    with report.step(
        "sdk.package_validation",
        "sdk_package_validation",
        category="validation",
        cache_status="not_applicable",
        tool_name=SDK_PRODUCER["name"],
        tool_version=SDK_PRODUCER["version"],
    ) as step:
        step.input_item_count = len(entries)
        step.input_bytes = package_size
        step.output_item_count = len(test_report.get("results", []))

    release_id = str(generation["release_id"])
    mod_package_id = f"mod-package:{package_sha256}"
    authorization_id = f"runtime-authorization:{package_sha256}"
    with (
        registry_writer_lock(roots.state),
        Registry(roots.state / "registry.sqlite", migrations_root) as registry,
    ):
        registry.transaction()
        try:
            release = registry.db.execute(
                "SELECT sdk_release_id FROM sdk_releases WHERE sdk_release_id=?",
                (release_id,),
            ).fetchone()
            if release is None:
                raise ValidationError(
                    "Release SDK générée absente du registre.",
                    error_code="sdk_release_missing",
                )
            registry.db.execute(
                """UPDATE sdk_releases SET contract_sha256=?,package_sha256=?,
                       status='built',completed_at=? WHERE sdk_release_id=?""",
                (contract_sha256, package_sha256, _utc_now(), release_id),
            )
            adapter_id = str(generation["adapter_id"])
            registry.db.execute(
                "UPDATE adapter_releases SET package_sha256=? WHERE adapter_id=?",
                (package_sha256, adapter_id),
            )
            registry.db.execute(
                """INSERT OR IGNORE INTO mod_packages(
                       mod_package_id,mod_id,mod_version,sdk_release_id,package_sha256,
                       package_size_bytes,signer_identity,build_scope_json,created_at
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    mod_package_id,
                    "aniimo.lua-catalog-example",
                    "1.0.0",
                    release_id,
                    package_sha256,
                    package_size,
                    None,
                    canonical_json_bytes(build_ids).decode("utf-8"),
                    _utc_now(),
                ),
            )
            registry.db.execute(
                """INSERT OR IGNORE INTO runtime_authorizations(
                       runtime_authorization_id,mod_package_id,package_sha256,
                       mod_version,signer_identity,declared_build_scope_json,
                       authorization_status,valid_from,valid_until,evidence_reference,
                       recorded_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    authorization_id,
                    mod_package_id,
                    package_sha256,
                    "1.0.0",
                    None,
                    canonical_json_bytes(build_ids).decode("utf-8"),
                    "not_requested",
                    None,
                    None,
                    None,
                    _utc_now(),
                ),
            )
            for result in test_report["results"]:
                build_id = str(result["build_id"])
                basis_id = str(result.get("capability_basis_id", ""))
                basis_pairs = [(API_ID, basis_id)]
                if extended_contract:
                    basis_pairs.append(
                        (
                            BUILD_IDENTITY_API_ID,
                            str(result.get("build_identity_basis_id", "")),
                        )
                    )
                if (
                    build_id not in build_ids
                    or any(
                        basis not in generation["capability_basis_ids"]
                        for _api_id, basis in basis_pairs
                    )
                    or result.get("status") != "passed"
                ):
                    raise ValidationError(
                        "Résultat de build SDK incohérent.",
                        error_code="sdk_test_report_invalid",
                    )
                for api_id, tested_basis_id in basis_pairs:
                    evaluation = registry.db.execute(
                        """SELECT cbe.capability_basis_id,cb.api_id
                           FROM capability_build_evaluations cbe
                           JOIN capability_bases cb
                             ON cb.capability_basis_id=cbe.capability_basis_id
                           WHERE cbe.capability_basis_id=? AND cbe.build_id=?""",
                        (tested_basis_id, build_id),
                    ).fetchone()
                    if evaluation is None or evaluation["api_id"] != api_id:
                        raise ValidationError(
                            "Évaluation de capacité absente.",
                            error_code="sdk_capability_evaluation_missing",
                        )
                    for kind, status in (
                        ("static_contract", "passed"),
                        ("offline_adapter", "passed"),
                        ("runtime_game", "not_tested"),
                    ):
                        validation_id = "capability-validation:" + digest_json(
                            [tested_basis_id, build_id, kind, package_sha256]
                        )
                        registry.db.execute(
                            """INSERT OR REPLACE INTO capability_validations(
                                   capability_validation_id,api_id,
                                   capability_basis_id,build_id,
                                   runtime_environment_id,test_suite,
                                   validation_kind,validation_status,evidence_json,
                                   validated_at
                               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                            (
                                validation_id,
                                api_id,
                                tested_basis_id,
                                build_id,
                                "offline-dotnet8-container"
                                if kind != "runtime_game"
                                else "aniimo-windows-x64-il2cpp-bepinex6-pre2",
                                (
                                    "sdk-contract-suite/2"
                                    if extended_contract
                                    else "sdk-contract-suite/1"
                                ),
                                kind,
                                status,
                                canonical_json_bytes(
                                    {
                                        "package_sha256": package_sha256,
                                        "plugin_sha256": test_report["plugin_sha256"],
                                    }
                                ).decode("utf-8"),
                                _utc_now(),
                            ),
                        )
                    registry.db.execute(
                        """UPDATE capability_build_evaluations
                           SET required_tests_status='partial',
                               runtime_validation_status='not_tested',
                               capability_status='requires_validation'
                           WHERE capability_basis_id=? AND build_id=?""",
                        (tested_basis_id, build_id),
                    )
            if extended_contract:
                compatibility_id = "sdk-binary-compatibility:" + digest_json(
                    [
                        release_id,
                        test_report["plugin_sha256"],
                        contract_sha256,
                        generation["sdk_version"],
                    ]
                )
                registry.db.execute(
                    """INSERT OR REPLACE INTO sdk_binary_compatibility_tests(
                           compatibility_test_id,sdk_release_id,old_plugin_sha256,
                           old_contract_assembly_version,current_contract_sha256,
                           adapter_version,build_scope_json,status,evidence_json,
                           tested_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        compatibility_id,
                        release_id,
                        test_report["plugin_sha256"],
                        test_report["old_contract_assembly_version"],
                        contract_sha256,
                        generation["sdk_version"],
                        canonical_json_bytes(build_ids).decode("utf-8"),
                        "passed",
                        canonical_json_bytes(
                            {
                                "same_plugin_binary": True,
                                "test_report_sha256": sha256_file(test_report_path)[0],
                            }
                        ).decode("utf-8"),
                        _utc_now(),
                    ),
                )
                attestation_id = "distribution-attestation:" + digest_json(
                    [release_id, package_sha256]
                )
                registry.db.execute(
                    """INSERT OR REPLACE INTO distribution_attestations(
                           distribution_attestation_id,sdk_release_id,
                           package_sha256,package_manifest_schema,
                           verification_status,signature_status,signer_identity,
                           sbom_sha256,evidence_json,created_at
                       ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (
                        attestation_id,
                        release_id,
                        package_sha256,
                        verification["schema_version"],
                        "passed",
                        "unsigned",
                        None,
                        None,
                        canonical_json_bytes(
                            {
                                "file_count": len(entries),
                                "internal_hashes_verified": True,
                            }
                        ).decode("utf-8"),
                        _utc_now(),
                    ),
                )
            registry.commit()
        except BaseException:
            registry.rollback()
            raise

    evidence = {
        "api_id": API_ID,
        "authorization": {
            "runtime_authorization_id": authorization_id,
            "status": "not_requested",
        },
        "build_ids": build_ids,
        "contract_sha256": contract_sha256,
        "offline_validation_status": "passed",
        "package_file_count": len(entries),
        "package_sha256": package_sha256,
        "package_size_bytes": package_size,
        "release_id": release_id,
        "runtime_validation_status": "not_tested",
        "schema_version": 1,
        "sdk_version": generation["sdk_version"],
        "test_report_sha256": sha256_file(test_report_path)[0],
    }
    if extended_contract:
        evidence.update(
            {
                "api_ids": generation["api_ids"],
                "binary_compatibility_status": "passed",
                "distribution_verification_status": "passed",
                "native_optimization_status": "not_needed",
                "schema_version": 2,
                "signature_status": "unsigned",
            }
        )
    destination = roots.output / "sdk-releases" / package_sha256
    destination.mkdir(parents=True, exist_ok=True)
    evidence_path = destination / "release-evidence.json"
    if evidence_path.exists() and evidence_path.read_bytes() != pretty_json_bytes(
        evidence
    ):
        raise ValidationError(
            "Preuve de release SDK conflictuelle.", error_code="sdk_release_conflict"
        )
    atomic_write_bytes(evidence_path, pretty_json_bytes(evidence))
    report.finish("completed")
    publish_report(roots.output, report.public())
    return {
        **evidence,
        "evidence": evidence_path.relative_to(roots.output).as_posix(),
        "workflow_run_id": run_id,
    }
