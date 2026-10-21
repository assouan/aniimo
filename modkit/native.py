from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import (
    AnalyzerRoots,
    _publish_artifact,
    _register_snapshot,
    _scope_decisions,
    assert_inputs_read_only,
    assert_no_live_source_environment,
)
from .capture import verify_snapshot
from .config import LoadedYaml
from .errors import ValidationError
from .ghidra_adapter import BODY_STATUSES, GhidraAdapter, GhidraExport
from .il2cpp import inspect_metadata_pair
from .pe import PeImage
from .registry import Registry, registry_writer_lock
from .reporting import RunReport, publish_report
from .util import (
    atomic_write_json,
    canonical_json_bytes,
    confined_path,
    digest_json,
    fsync_directory,
    object_path,
    pretty_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

NATIVE_PRODUCER = {"name": "modkit.native", "version": "0.2.0"}


@dataclass(frozen=True)
class NativeRoots:
    inputs: Path
    state: Path
    artifacts: Path
    ghidra: Path
    work: Path
    output: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _slug(value: str, *, maximum_length: int = 80) -> str:
    result = "".join(
        character if character.isalnum() or character in "_.-" else "-"
        for character in value
    ).strip(".-")
    result = result or "unnamed"
    if len(result.encode("utf-8")) <= maximum_length:
        return result
    suffix = sha256_bytes(value.encode("utf-8"))[:12]
    prefix_budget = maximum_length - len(suffix) - 1
    prefix = result.encode("utf-8")[:prefix_budget].decode("utf-8", errors="ignore")
    return f"{prefix.rstrip('.-')}-{suffix}"


def _manifest_payloads(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["logical_path"]): item for item in manifest.get("payloads", [])}


def _approved_modules(
    manifest: dict[str, Any], policy: LoadedYaml
) -> list[dict[str, Any]]:
    decisions = _scope_decisions(manifest, policy)
    approved_full = {
        Path(value).name.casefold()
        for value in policy.data.get("approved", {}).get("full_module_decompile", [])
    }
    selected = [
        decision
        for decision in decisions
        if decision["decision"] == "game_decompile"
        and Path(decision["logical_path"]).name.casefold() in approved_full
    ]
    expected = {
        Path(value).name.casefold()
        for value in policy.data.get("approved", {}).get("game_decompile", [])
        if Path(value).name.casefold() in approved_full
    }
    actual = {Path(item["logical_path"]).name.casefold() for item in selected}
    if actual != expected:
        missing = sorted(expected - actual)
        raise ValidationError(
            f"Modules natifs approuvés absents du snapshot : {missing}",
            error_code="approved_native_module_missing",
        )
    return sorted(selected, key=lambda item: item["logical_path"].casefold())


def body_attempt_context(
    *,
    body: dict[str, Any],
    module_sha256: str,
    load_context_hash: str,
    tool_context: dict[str, Any],
    reference_context_hash: str,
    managed_signature: str | None,
    layout_hash: str | None,
    budget_class: str,
) -> dict[str, Any]:
    """Return every semantic dependency used by the C-attempt cache."""
    return {
        "body": {
            "body_byte_count": int(body.get("body_byte_count", 0)),
            "raw_body_hash": body.get("raw_body_hash"),
            "rva": str(body.get("rva")),
        },
        "budget_class": budget_class,
        "layout_hash": layout_hash,
        "load_context_hash": load_context_hash,
        "managed_signature": managed_signature,
        "module_sha256": module_sha256,
        "native_prototype": body.get("native_prototype"),
        "reference_context_hash": reference_context_hash,
        "tool_context": tool_context,
    }


def body_attempt_key(context: dict[str, Any]) -> str:
    return f"native-attempt:{digest_json(context)}"


def _read_artifact(root: Path, digest: str) -> bytes:
    path = object_path(root, digest)
    if not path.is_file():
        raise ValidationError(
            "Artefact CAS natif absent.", error_code="native_artifact_missing"
        )
    data = path.read_bytes()
    if sha256_bytes(data) != digest:
        raise ValidationError(
            "Artefact CAS natif corrompu.", error_code="native_artifact_corrupt"
        )
    return data


def _publish_generated(artifacts_root: Path, data: bytes) -> str:
    digest, _, _ = _publish_artifact(artifacts_root, data)
    return digest


def _sqlite_address(value: int | None) -> int | None:
    if value is None or value < -(2**63) or value > 2**63 - 1:
        return None
    return value


def normalize_ghidra_export(
    *,
    export: GhidraExport,
    module_logical_path: str,
    module_sha256: str,
    pe: PeImage,
    analysis_context_sha256: str,
    artifacts_root: Path,
) -> tuple[dict[str, Any], str]:
    references_by_ordinal: dict[int, list[dict[str, Any]]] = {}
    for reference in export.references:
        references_by_ordinal.setdefault(int(reference["source_ordinal"]), []).append(
            reference
        )
    normalized_bodies: list[dict[str, Any]] = []
    for raw in export.bodies:
        body = dict(raw)
        rva = int(str(raw["rva"]), 0)
        body["file_offset"] = pe.rva_to_offset(rva)
        asm_digest = None
        c_digest = None
        if raw.get("asm_path") is not None:
            asm = confined_path(export.output_root, str(raw["asm_path"]))
            asm_digest = _publish_generated(artifacts_root, asm.read_bytes())
        if raw.get("c_path") is not None:
            c_file = confined_path(export.output_root, str(raw["c_path"]))
            c_digest = _publish_generated(artifacts_root, c_file.read_bytes())
        body.pop("asm_path", None)
        body.pop("c_path", None)
        body["asm_artifact_sha256"] = asm_digest
        body["c_artifact_sha256"] = c_digest
        body["references"] = sorted(
            references_by_ordinal.get(int(raw["ordinal"]), []),
            key=lambda item: (
                str(item.get("source_instruction_rva")),
                str(item.get("kind")),
                str(item.get("target_address")),
            ),
        )
        normalized_bodies.append(body)
    bundle = {
        "analysis_context_sha256": analysis_context_sha256,
        "bsim": {
            "config": export.bsim_config,
            "signature_artifact_sha256": (
                _publish_generated(artifacts_root, export.bsim_signature.read_bytes())
                if export.bsim_signature is not None
                else None
            ),
            "status": "generated" if export.bsim_signature is not None else "disabled",
        },
        "bodies": normalized_bodies,
        "load_context": pe.load_context(),
        "module_logical_path": module_logical_path,
        "module_sha256": module_sha256,
        "project_uri": export.project_uri,
        "schema_version": 1,
        "summary": export.summary,
        "unattributed_executable_ranges": list(export.unattributed_ranges),
    }
    data = pretty_json_bytes(bundle)
    return bundle, _publish_generated(artifacts_root, data)


def _load_module_bundle(artifacts_root: Path, digest: str) -> dict[str, Any]:
    value = json.loads(_read_artifact(artifacts_root, digest))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValidationError(
            "Manifeste de module natif invalide.",
            error_code="native_module_manifest_invalid",
        )
    return value


def _component_revision_id(logical_path: str, module_sha256: str) -> str:
    return f"component-revision:{digest_json({'logical_path': logical_path, 'sha256': module_sha256})}"


def _component_id(logical_path: str) -> str:
    return f"component:{digest_json({'logical_path': logical_path})}"


def _register_component(
    db: sqlite3.Connection,
    *,
    build_id: str,
    logical_path: str,
    module_sha256: str,
) -> str:
    component_id = _component_id(logical_path)
    revision_id = _component_revision_id(logical_path, module_sha256)
    db.execute(
        "INSERT OR IGNORE INTO components(component_id,logical_name,component_kind) VALUES(?,?,?)",
        (component_id, logical_path, "native_module"),
    )
    db.execute(
        """INSERT OR IGNORE INTO component_revisions(
            component_revision_id,component_id,content_sha256,source_artifact_id,provenance_json
        ) VALUES(?,?,?,?,?)""",
        (
            revision_id,
            component_id,
            module_sha256,
            f"input-object:sha256:{module_sha256}",
            canonical_json_bytes(
                {
                    "classification": "game_decompile",
                    "logical_path": logical_path,
                    "reason": "explicit_approved_full_module",
                }
            ).decode("utf-8"),
        ),
    )
    db.execute(
        "INSERT OR IGNORE INTO build_components(build_id,component_revision_id,role) VALUES(?,?,?)",
        (build_id, revision_id, "approved_native_module"),
    )
    return revision_id


def _body_id(db: sqlite3.Connection, *, component_revision_id: str, rva: int) -> str:
    row = db.execute(
        """SELECT native_body_id FROM body_observations
           WHERE component_revision_id=? AND rva=? LIMIT 1""",
        (component_revision_id, rva),
    ).fetchone()
    if row is not None:
        return str(row[0])
    native_body_id = f"body-{uuid.uuid4()}"
    db.execute(
        "INSERT INTO native_bodies(native_body_id,first_seen_component_revision_id,created_at) VALUES(?,?,?)",
        (native_body_id, component_revision_id, _utc_now()),
    )
    return native_body_id


def _symbol_id(db: sqlite3.Connection, *, component_revision_id: str, rva: int) -> str:
    row = db.execute(
        """SELECT symbol_id FROM symbol_observations
           WHERE component_revision_id=? AND native_entry_rva=? LIMIT 1""",
        (component_revision_id, rva),
    ).fetchone()
    if row is not None:
        return str(row[0])
    symbol_id = f"symbol-{uuid.uuid4()}"
    db.execute(
        "INSERT INTO symbols(symbol_id,symbol_kind,created_at) VALUES(?,?,?)",
        (symbol_id, "native_function", _utc_now()),
    )
    return symbol_id


def _managed_symbol_id(
    db: sqlite3.Connection, *, component_revision_id: str, signature_key: str
) -> str:
    row = db.execute(
        """SELECT symbol_id FROM symbol_observations
           WHERE signature_key=? ORDER BY symbol_observation_id LIMIT 1""",
        (signature_key,),
    ).fetchone()
    if row is not None:
        return str(row[0])
    symbol_id = f"symbol-{uuid.uuid4()}"
    db.execute(
        "INSERT INTO symbols(symbol_id,symbol_kind,created_at) VALUES(?,?,?)",
        (symbol_id, "managed_method", _utc_now()),
    )
    return symbol_id


def _ingest_module(
    *,
    db: sqlite3.Connection,
    build_id: str,
    analysis_id: str,
    bundle: dict[str, Any],
    bundle_sha256: str,
    cache_status: str,
    tool_context: dict[str, Any],
    record_attempts: bool = True,
    record_module_analysis: bool = True,
) -> dict[str, Any]:
    logical_path = str(bundle["module_logical_path"])
    module_sha256 = str(bundle["module_sha256"])
    revision_id = _register_component(
        db,
        build_id=build_id,
        logical_path=logical_path,
        module_sha256=module_sha256,
    )
    load_context = dict(bundle["load_context"])
    load_context_hash = digest_json(load_context)
    architecture = str(load_context["architecture"])
    image_base = int(str(load_context["image_base"]), 0)
    body_by_ordinal: dict[int, tuple[str, int]] = {}
    for body in bundle["bodies"]:
        ordinal = int(body["ordinal"])
        rva = int(str(body["rva"]), 0)
        native_body_id = _body_id(db, component_revision_id=revision_id, rva=rva)
        symbol_id = _symbol_id(db, component_revision_id=revision_id, rva=rva)
        body_by_ordinal[ordinal] = (native_body_id, rva)
        references = list(body.get("references", []))
        reference_context_hash = digest_json(references)
        decompiler_context_hash = digest_json(
            {
                "load_context_hash": load_context_hash,
                "tool_context": tool_context,
            }
        )
        status = str(body["body_output_status"])
        if status not in BODY_STATUSES:
            raise ValidationError(
                "État natif inconnu.", error_code="native_status_invalid"
            )
        file_offset = body.get("file_offset")
        if file_offset is not None:
            file_offset = int(file_offset)
        observation_id = f"body-observation:{digest_json([build_id, revision_id, rva])}"
        db.execute(
            """INSERT OR REPLACE INTO body_observations(
                body_observation_id,native_body_id,build_id,component_revision_id,
                module_logical_path,module_sha256,architecture,file_format,rva,file_offset,
                preferred_va,raw_body_hash,relocation_normalized_hash,body_output_status,
                discovery_origin,scope_decision,diagnostic,asm_artifact_sha256,c_artifact_sha256,
                instruction_count,body_byte_count,decompiler_context_hash,reference_context_hash
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                observation_id,
                native_body_id,
                build_id,
                revision_id,
                logical_path,
                module_sha256,
                architecture,
                str(load_context["file_format"]),
                rva,
                file_offset,
                f"0x{image_base + rva:x}",
                body.get("raw_body_hash"),
                None,
                status,
                "ghidra_auto_analysis",
                "game_decompile",
                body.get("diagnostic"),
                body.get("asm_artifact_sha256"),
                body.get("c_artifact_sha256"),
                int(body.get("instruction_count", 0)),
                int(body.get("body_byte_count", 0)),
                decompiler_context_hash,
                reference_context_hash,
            ),
        )
        symbol_observation_id = (
            f"symbol-observation:{digest_json([build_id, revision_id, rva, symbol_id])}"
        )
        db.execute(
            """INSERT OR REPLACE INTO symbol_observations(
                symbol_observation_id,symbol_id,build_id,component_revision_id,observed_name,
                namespace,native_entry_rva,managed_signature,signature_key,static_kind,
                body_resolution_status,provenance_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                symbol_observation_id,
                symbol_id,
                build_id,
                revision_id,
                body.get("name"),
                body.get("namespace"),
                rva,
                None,
                None,
                None,
                "resolved",
                canonical_json_bytes(
                    {
                        "name_source": body.get("symbol_source"),
                        "source": "Ghidra",
                    }
                ).decode("utf-8"),
            ),
        )
        link_id = f"symbol-body-link:{digest_json([symbol_id, native_body_id, build_id, revision_id, 'native_function'])}"
        db.execute(
            """INSERT OR REPLACE INTO symbol_body_links(
                symbol_body_link_id,symbol_id,native_body_id,build_id,component_revision_id,
                entrypoint_role,generic_context,body_resolution_status,evidence_json
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                link_id,
                symbol_id,
                native_body_id,
                build_id,
                revision_id,
                "native_function",
                None,
                "resolved",
                canonical_json_bytes(
                    {"module": logical_path, "rva": f"0x{rva:x}"}
                ).decode("utf-8"),
            ),
        )
        managed_symbols = list(body.get("managed_symbols", []))
        for managed_symbol in managed_symbols:
            signature_key = str(managed_symbol["signature_key"])
            managed_symbol_id = _managed_symbol_id(
                db,
                component_revision_id=revision_id,
                signature_key=signature_key,
            )
            managed_observation_id = f"symbol-observation:{digest_json([build_id, revision_id, signature_key, managed_symbol_id])}"
            resolution = "shared" if len(managed_symbols) > 1 else "resolved"
            db.execute(
                """INSERT OR REPLACE INTO symbol_observations(
                    symbol_observation_id,symbol_id,build_id,component_revision_id,
                    observed_name,namespace,native_entry_rva,managed_signature,
                    signature_key,static_kind,body_resolution_status,provenance_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    managed_observation_id,
                    managed_symbol_id,
                    build_id,
                    revision_id,
                    managed_symbol.get("method"),
                    managed_symbol.get("type"),
                    rva,
                    managed_symbol.get("managed_signature"),
                    signature_key,
                    managed_symbol.get("static_kind"),
                    resolution,
                    canonical_json_bytes(
                        {
                            "assembly": managed_symbol.get("assembly"),
                            "property_provenance": managed_symbol.get(
                                "property_provenance", {}
                            ),
                            "source": "il2cpp_metadata",
                        }
                    ).decode("utf-8"),
                ),
            )
            managed_link_id = f"symbol-body-link:{digest_json([managed_symbol_id, native_body_id, build_id, revision_id, 'method'])}"
            db.execute(
                """INSERT OR REPLACE INTO symbol_body_links(
                    symbol_body_link_id,symbol_id,native_body_id,build_id,
                    component_revision_id,entrypoint_role,generic_context,
                    body_resolution_status,evidence_json
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    managed_link_id,
                    managed_symbol_id,
                    native_body_id,
                    build_id,
                    revision_id,
                    "method",
                    managed_symbol.get("generic_context"),
                    resolution,
                    canonical_json_bytes(
                        {
                            "module": logical_path,
                            "rva": f"0x{rva:x}",
                            "signature_key": signature_key,
                        }
                    ).decode("utf-8"),
                ),
            )
        prototype_id = f"native-prototype:{digest_json([build_id, revision_id, rva, 'native_function'])}"
        db.execute(
            """INSERT OR REPLACE INTO native_prototypes(
                native_prototype_id,native_body_id,build_id,component_revision_id,architecture,
                abi,entrypoint_role,calling_convention,prototype_text,provenance,status
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                prototype_id,
                native_body_id,
                build_id,
                revision_id,
                architecture,
                "windows",
                "native_function",
                body.get("calling_convention"),
                body.get("native_prototype"),
                "ghidra_inferred",
                "unreviewed",
            ),
        )
        attempt_context = body_attempt_context(
            body=body,
            module_sha256=module_sha256,
            load_context_hash=load_context_hash,
            tool_context=tool_context,
            reference_context_hash=reference_context_hash,
            managed_signature=None,
            layout_hash=None,
            budget_class="primary",
        )
        attempt_key = body_attempt_key(attempt_context)
        if record_attempts and (
            db.execute(
                "SELECT 1 FROM native_body_attempts WHERE attempt_key=?",
                (attempt_key,),
            ).fetchone()
            is None
        ):
            db.execute(
                """INSERT INTO native_body_attempts(
                    native_body_attempt_id,native_body_id,analysis_id,attempt_key,
                    body_output_status,budget_class,context_json,diagnostic,warnings_json,
                    asm_artifact_sha256,c_artifact_sha256,cache_status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"attempt-{uuid.uuid4()}",
                    native_body_id,
                    analysis_id,
                    attempt_key,
                    status,
                    "primary",
                    canonical_json_bytes(attempt_context).decode("utf-8"),
                    body.get("diagnostic"),
                    "[]",
                    body.get("asm_artifact_sha256"),
                    body.get("c_artifact_sha256"),
                    cache_status,
                    _utc_now(),
                ),
            )

    rva_to_body = {rva: body_id for body_id, rva in body_by_ordinal.values()}
    unresolved_calls = 0
    for body in bundle["bodies"]:
        source_body_id, _ = body_by_ordinal[int(body["ordinal"])]
        for index, reference in enumerate(body.get("references", [])):
            source_rva = int(str(reference["source_instruction_rva"]), 0)
            target_rva_raw = (
                int(str(reference["target_rva"]), 0)
                if reference.get("target_rva") is not None
                else None
            )
            target_rva = _sqlite_address(target_rva_raw)
            target_body_id = (
                rva_to_body.get(target_rva) if target_rva is not None else None
            )
            kind = str(reference["kind"])
            if kind == "unresolved_call":
                resolution = "unresolved"
                unresolved_calls += 1
            elif target_body_id is not None:
                resolution = "resolved_native_body"
            elif reference.get("target_address") is not None:
                resolution = "resolved_raw_target"
            else:
                resolution = "unresolved"
            reference_id = f"native-reference:{digest_json([build_id, source_body_id, source_rva, index, reference])}"
            db.execute(
                """INSERT OR IGNORE INTO native_references(
                    native_reference_id,build_id,source_native_body_id,reference_kind,
                    source_instruction_rva,target_raw,target_rva,target_native_body_id,
                    resolution_status,evidence_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    reference_id,
                    build_id,
                    source_body_id,
                    kind,
                    source_rva,
                    reference.get("target_address") or reference.get("raw_operand"),
                    target_rva,
                    target_body_id,
                    resolution,
                    canonical_json_bytes(reference).decode("utf-8"),
                ),
            )
            if resolution == "unresolved" and "call" in kind:
                region_id = f"unresolved-region:{digest_json([build_id, revision_id, source_body_id, source_rva, index])}"
                db.execute(
                    """INSERT OR IGNORE INTO unresolved_code_regions(
                        unresolved_code_region_id,build_id,component_revision_id,region_kind,
                        start_rva,end_rva,raw_target,reason,evidence_json
                    ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        region_id,
                        build_id,
                        revision_id,
                        "unresolved_call_target",
                        source_rva,
                        source_rva,
                        reference.get("raw_operand"),
                        "ghidra_call_target_unresolved",
                        canonical_json_bytes(reference).decode("utf-8"),
                    ),
                )
    for index, region in enumerate(bundle["unattributed_executable_ranges"]):
        start = int(str(region["start_rva"]), 0)
        end = int(str(region["end_rva"]), 0)
        region_id = f"unresolved-region:{digest_json([build_id, revision_id, 'unattributed', start, end, index])}"
        db.execute(
            """INSERT OR IGNORE INTO unresolved_code_regions(
                unresolved_code_region_id,build_id,component_revision_id,region_kind,
                start_rva,end_rva,raw_target,reason,evidence_json
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                region_id,
                build_id,
                revision_id,
                "unattributed_executable_range",
                start,
                end,
                None,
                "executable_bytes_not_attributed_to_discovered_function",
                canonical_json_bytes(region).decode("utf-8"),
            ),
        )
    pending = sum(
        1 for body in bundle["bodies"] if body["body_output_status"] == "pending"
    )
    if record_module_analysis:
        db.execute(
            """INSERT INTO native_module_analyses(
                    native_module_analysis_id,component_revision_id,analysis_context_sha256,
                    analysis_id,status,output_manifest_sha256,function_count,pending_count
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(component_revision_id,analysis_context_sha256) DO UPDATE SET
                    analysis_id=excluded.analysis_id,
                    status=excluded.status,
                    output_manifest_sha256=excluded.output_manifest_sha256,
                    function_count=excluded.function_count,
                    pending_count=excluded.pending_count""",
            (
                f"native-module-analysis:{digest_json([revision_id, bundle['analysis_context_sha256']])}",
                revision_id,
                bundle["analysis_context_sha256"],
                analysis_id,
                "partial" if pending else "completed",
                bundle_sha256,
                len(bundle["bodies"]),
                pending,
            ),
        )
    return {
        "body_count": len(bundle["bodies"]),
        "component_revision_id": revision_id,
        "unresolved_call_count": unresolved_calls,
    }


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _coverage(
    db: sqlite3.Connection,
    *,
    build_id: str,
    analysis_key: str,
    metadata_result: dict[str, Any],
) -> dict[str, Any]:
    bodies = [
        dict(row)
        for row in db.execute(
            """SELECT native_body_id,body_output_status,module_logical_path,rva
               FROM body_observations WHERE build_id=? AND scope_decision='game_decompile'
               ORDER BY module_logical_path COLLATE NOCASE,rva""",
            (build_id,),
        )
    ]
    by_status = {
        status: [
            str(row["native_body_id"])
            for row in bodies
            if row["body_output_status"] == status
        ]
        for status in sorted(BODY_STATUSES)
    }
    regions: dict[str, list[dict[str, Any]]] = {}
    for row in db.execute(
        """SELECT unresolved_code_region_id,region_kind,start_rva,end_rva,raw_target,reason
           FROM unresolved_code_regions WHERE build_id=?
           ORDER BY region_kind,start_rva,end_rva,unresolved_code_region_id""",
        (build_id,),
    ):
        item = dict(row)
        regions.setdefault(str(item.pop("region_kind")), []).append(item)
    counts = {status: len(values) for status, values in by_status.items()}
    approved_count = len(bodies)
    reconciled = approved_count == sum(counts.values())
    return {
        "analysis_key": analysis_key,
        "approved_body_count": approved_count,
        "body_ids_by_status": by_status,
        "body_status_counts": counts,
        "build_id": build_id,
        "discovery_complete": False,
        "discovery_complete_reason": (
            "metadata_catalog_unavailable_and_unattributed_ranges_reported_separately"
        ),
        "exact_body_reconciliation": reconciled,
        "expected_methods": {
            "catalog_status": (
                "available"
                if metadata_result["status"] == "parsed"
                else f"unavailable_{metadata_result['status']}"
            ),
            "without_resolved_body": regions.get("expected_method_without_body", []),
        },
        "identified_bodies_all_terminal": counts["pending"] == 0,
        "schema_version": 1,
        "unattributed_executable_ranges": regions.get(
            "unattributed_executable_range", []
        ),
        "unconfirmed_function_candidates": regions.get(
            "unconfirmed_function_candidate", []
        ),
        "unresolved_call_targets": regions.get("unresolved_call_target", []),
    }


def _body_rows(db: sqlite3.Connection, build_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.execute(
            """SELECT * FROM body_observations
               WHERE build_id=? AND scope_decision='game_decompile'
               ORDER BY module_logical_path COLLATE NOCASE,rva""",
            (build_id,),
        )
    ]


def _body_symbols(
    db: sqlite3.Connection, *, build_id: str, native_body_id: str
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for row in db.execute(
        """SELECT so.symbol_id,so.observed_name,so.namespace,so.managed_signature,
                  so.signature_key,so.static_kind,so.provenance_json,
                  sbl.entrypoint_role,sbl.body_resolution_status
           FROM symbol_body_links sbl
           JOIN symbol_observations so
             ON so.symbol_id=sbl.symbol_id AND so.build_id=sbl.build_id
            AND so.component_revision_id=sbl.component_revision_id
           WHERE sbl.build_id=? AND sbl.native_body_id=?
           ORDER BY so.symbol_id""",
        (build_id, native_body_id),
    ):
        value = dict(row)
        provenance = json.loads(str(value.pop("provenance_json")))
        value["assembly"] = provenance.get("assembly")
        values.append(value)
    return values


def _body_references(
    db: sqlite3.Connection, *, build_id: str, native_body_id: str
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in db.execute(
            """SELECT reference_kind,source_instruction_rva,target_raw,target_rva,
                      target_native_body_id,resolution_status
               FROM native_references
               WHERE build_id=? AND source_native_body_id=?
               ORDER BY source_instruction_rva,native_reference_id""",
            (build_id, native_body_id),
        )
    ]


def _body_prototype(
    db: sqlite3.Connection, *, build_id: str, native_body_id: str
) -> dict[str, Any] | None:
    row = db.execute(
        """SELECT architecture,abi,entrypoint_role,calling_convention,prototype_text,
                  provenance,status
           FROM native_prototypes WHERE build_id=? AND native_body_id=?
           ORDER BY native_prototype_id LIMIT 1""",
        (build_id, native_body_id),
    ).fetchone()
    return dict(row) if row is not None else None


def _all_body_symbols(
    db: sqlite3.Connection, *, build_id: str
) -> dict[str, list[dict[str, Any]]]:
    values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in db.execute(
        """SELECT sbl.native_body_id,so.symbol_id,so.observed_name,so.namespace,
                  so.managed_signature,so.signature_key,so.static_kind,
                  so.provenance_json,sbl.entrypoint_role,
                  sbl.body_resolution_status
           FROM symbol_body_links sbl
           JOIN symbol_observations so
             ON so.symbol_id=sbl.symbol_id AND so.build_id=sbl.build_id
            AND so.component_revision_id=sbl.component_revision_id
           WHERE sbl.build_id=?
           ORDER BY sbl.native_body_id,so.symbol_id""",
        (build_id,),
    ):
        value = dict(row)
        body_id = str(value.pop("native_body_id"))
        provenance = json.loads(str(value.pop("provenance_json")))
        value["assembly"] = provenance.get("assembly")
        values[body_id].append(value)
    return dict(values)


def _all_body_references(
    db: sqlite3.Connection, *, build_id: str
) -> dict[str, list[dict[str, Any]]]:
    values: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in db.execute(
        """SELECT source_native_body_id,reference_kind,source_instruction_rva,
                  target_raw,target_rva,target_native_body_id,resolution_status
           FROM native_references
           WHERE build_id=?
           ORDER BY source_native_body_id,source_instruction_rva,native_reference_id""",
        (build_id,),
    ):
        value = dict(row)
        body_id = str(value.pop("source_native_body_id"))
        values[body_id].append(value)
    return dict(values)


def _all_body_prototypes(
    db: sqlite3.Connection, *, build_id: str
) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        """SELECT native_body_id,architecture,abi,entrypoint_role,
                  calling_convention,prototype_text,provenance,status
           FROM native_prototypes WHERE build_id=?
           ORDER BY native_body_id,native_prototype_id""",
        (build_id,),
    ):
        value = dict(row)
        body_id = str(value.pop("native_body_id"))
        values.setdefault(body_id, value)
    return values


def _function_markdown(
    *, body: dict[str, Any], symbol: dict[str, Any], prefix: str
) -> bytes:
    c_link = (
        f"[{body['native_body_id']}.c]({prefix}bodies/{body['native_body_id']}.c)"
        if body["c_artifact_sha256"]
        else "indisponible (voir diagnostic)"
    )
    lines = [
        f"# {symbol.get('observed_name') or 'fonction sans nom'}",
        "",
        f"- Corps persistant : `{body['native_body_id']}`",
        f"- Symbole persistant : `{symbol['symbol_id']}`",
        f"- Module : `{body['module_logical_path']}`",
        f"- RVA : `0x{int(body['rva']):x}` ; offset fichier : `{body['file_offset']}`",
        f"- État : `{body['body_output_status']}`",
        f"- Signature managée : [{body['native_body_id']}.managed-signature.txt]({prefix}bodies/{body['native_body_id']}.managed-signature.txt)",
        f"- Prototype natif : [{body['native_body_id']}.prototype.txt]({prefix}bodies/{body['native_body_id']}.prototype.txt)",
        f"- ASM : [{body['native_body_id']}.asm]({prefix}bodies/{body['native_body_id']}.asm)",
        f"- Pseudocode C : {c_link}",
        f"- Références : [{body['native_body_id']}.references.json]({prefix}bodies/{body['native_body_id']}.references.json)",
        f"- Diagnostic : [{body['native_body_id']}.diagnostic.json]({prefix}bodies/{body['native_body_id']}.diagnostic.json)",
        f"- Manifeste canonique : [{body['native_body_id']}.json]({prefix}bodies/{body['native_body_id']}.json)",
        "",
        "> Le C est un pseudocode Ghidra, pas le source original ni une preuve de compilabilité.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _write_staged_bytes(path: Path, data: bytes) -> None:
    """Write a new private staging file without per-file durability barriers."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def _write_staged_json(path: Path, value: Any) -> None:
    _write_staged_bytes(path, pretty_json_bytes(value))


def _publish_analysis_output(
    *,
    db: sqlite3.Connection,
    roots: NativeRoots,
    build_id: str,
    snapshot_id: str,
    analysis_key: str,
    metadata_result: dict[str, Any],
    module_digests: dict[str, str],
) -> tuple[Path, dict[str, Any], bool]:
    path_alias = f"m2-{analysis_key.removeprefix('m2-')[:20]}"
    relative = Path("builds") / build_id / path_alias
    destination = roots.output / relative
    if (destination / "analysis-manifest.json").is_file():
        existing = read_json(destination / "analysis-manifest.json")
        if existing.get("analysis_key") != analysis_key:
            raise ValidationError(
                "Collision de publication M2.", error_code="native_output_collision"
            )
        return destination, read_json(destination / "coverage.json"), False

    staging = roots.output / ".staging" / f"native-{uuid.uuid4()}"
    staging.mkdir(parents=True, exist_ok=False)
    try:
        bodies = _body_rows(db, build_id)
        native_body_csv: list[dict[str, Any]] = []
        prototypes_csv: list[dict[str, Any]] = []
        locations_csv: list[dict[str, Any]] = []
        links_csv: list[dict[str, Any]] = []
        references_csv: list[dict[str, Any]] = []
        module_indexes: dict[str, list[tuple[str, str]]] = {}
        body_manifest_digests: dict[str, str] = {}
        symbols_by_body = _all_body_symbols(db, build_id=build_id)
        references_by_body = _all_body_references(db, build_id=build_id)
        prototypes_by_body = _all_body_prototypes(db, build_id=build_id)
        for body in bodies:
            native_body_id = str(body["native_body_id"])
            symbols = symbols_by_body.get(native_body_id, [])
            if not symbols:
                raise ValidationError(
                    "Corps sans symbole natif associé.",
                    error_code="native_symbol_link_missing",
                )
            references = references_by_body.get(native_body_id, [])
            prototype = prototypes_by_body.get(native_body_id)
            body_root = staging / "native" / "bodies"
            if body["asm_artifact_sha256"]:
                _write_staged_bytes(
                    body_root / f"{native_body_id}.asm",
                    _read_artifact(roots.artifacts, str(body["asm_artifact_sha256"])),
                )
            if body["c_artifact_sha256"]:
                _write_staged_bytes(
                    body_root / f"{native_body_id}.c",
                    _read_artifact(roots.artifacts, str(body["c_artifact_sha256"])),
                )
            _write_staged_json(
                body_root / f"{native_body_id}.references.json",
                {"references": references, "schema_version": 1},
            )
            _write_staged_json(
                body_root / f"{native_body_id}.diagnostic.json",
                {
                    "body_output_status": body["body_output_status"],
                    "diagnostic": body["diagnostic"],
                    "schema_version": 1,
                },
            )
            prototype_text = (
                str(prototype.get("prototype_text") or "unknown")
                if prototype
                else "unknown"
            )
            _write_staged_bytes(
                body_root / f"{native_body_id}.prototype.txt",
                (prototype_text + "\n").encode("utf-8"),
            )
            managed = [
                str(item["managed_signature"])
                for item in symbols
                if item.get("managed_signature")
            ]
            _write_staged_bytes(
                body_root / f"{native_body_id}.managed-signature.txt",
                (("\n".join(managed) if managed else "unavailable") + "\n").encode(
                    "utf-8"
                ),
            )
            manifest = {
                "artifacts": {
                    "asm_sha256": body["asm_artifact_sha256"],
                    "c_sha256": body["c_artifact_sha256"],
                },
                "body_output_status": body["body_output_status"],
                "build_id": build_id,
                "diagnostic": body["diagnostic"],
                "location": {
                    "architecture": body["architecture"],
                    "file_offset": body["file_offset"],
                    "format": body["file_format"],
                    "module": body["module_logical_path"],
                    "module_sha256": body["module_sha256"],
                    "preferred_va": body["preferred_va"],
                    "rva": f"0x{int(body['rva']):x}",
                },
                "native_body_id": native_body_id,
                "native_prototype": prototype,
                "raw_body_hash": body["raw_body_hash"],
                "references": references,
                "schema_version": 1,
                "symbols": symbols,
            }
            manifest_data = pretty_json_bytes(manifest)
            body_manifest_digests[native_body_id] = sha256_bytes(manifest_data)
            _write_staged_bytes(body_root / f"{native_body_id}.json", manifest_data)
            module_slug = _slug(Path(str(body["module_logical_path"])).name)
            for symbol in symbols:
                view_name = f"{int(body['rva']):08x}-{_slug(str(symbol.get('observed_name') or symbol['symbol_id']))}.md"
                view_path = (
                    staging / "native" / "index" / "by-module" / module_slug / view_name
                )
                _write_staged_bytes(
                    view_path,
                    _function_markdown(body=body, symbol=symbol, prefix="../../../"),
                )
                module_indexes.setdefault(module_slug, []).append(
                    (str(symbol.get("observed_name") or symbol["symbol_id"]), view_name)
                )
                if str(symbol.get("observed_name") or "").startswith(("FUN_", "LAB_")):
                    unnamed = (
                        staging
                        / "native"
                        / "index"
                        / "unnamed"
                        / f"{native_body_id}.md"
                    )
                    _write_staged_bytes(
                        unnamed,
                        _function_markdown(body=body, symbol=symbol, prefix="../../"),
                    )
                if symbol.get("managed_signature"):
                    managed_view = (
                        staging
                        / "native"
                        / "index"
                        / "by-managed-type"
                        / _slug(str(symbol.get("assembly") or "unknown-assembly"))
                        / _slug(str(symbol.get("namespace") or "unknown-type"))
                        / view_name
                    )
                    _write_staged_bytes(
                        managed_view,
                        _function_markdown(
                            body=body, symbol=symbol, prefix="../../../../"
                        ),
                    )
                links_csv.append(
                    {
                        "body_resolution_status": symbol["body_resolution_status"],
                        "build_id": build_id,
                        "entrypoint_role": symbol["entrypoint_role"],
                        "managed_signature": symbol["managed_signature"],
                        "native_body_id": native_body_id,
                        "symbol_id": symbol["symbol_id"],
                    }
                )
            native_body_csv.append(
                {
                    "asm_sha256": body["asm_artifact_sha256"],
                    "body_output_status": body["body_output_status"],
                    "c_sha256": body["c_artifact_sha256"],
                    "diagnostic": body["diagnostic"],
                    "module_logical_path": body["module_logical_path"],
                    "native_body_id": native_body_id,
                    "raw_body_hash": body["raw_body_hash"],
                    "rva": f"0x{int(body['rva']):x}",
                    "scope_decision": body["scope_decision"],
                }
            )
            locations_csv.append(
                {
                    "architecture": body["architecture"],
                    "build_id": build_id,
                    "file_offset": body["file_offset"],
                    "format": body["file_format"],
                    "module_logical_path": body["module_logical_path"],
                    "module_sha256": body["module_sha256"],
                    "native_body_id": native_body_id,
                    "preferred_va": body["preferred_va"],
                    "rva": f"0x{int(body['rva']):x}",
                }
            )
            if prototype:
                prototypes_csv.append(
                    {
                        "build_id": build_id,
                        "native_body_id": native_body_id,
                        **prototype,
                    }
                )
            for reference in references:
                references_csv.append(
                    {"source_native_body_id": native_body_id, **reference}
                )

        for module_slug, items in module_indexes.items():
            lines = [f"# Module {module_slug}", ""]
            lines.extend(f"- [{name}]({path})" for name, path in sorted(items))
            lines.append("")
            _write_staged_bytes(
                staging / "native" / "index" / "by-module" / module_slug / "README.md",
                "\n".join(lines).encode("utf-8"),
            )

        _write_staged_bytes(
            staging / "native_bodies.csv",
            _csv_bytes(
                [
                    "native_body_id",
                    "module_logical_path",
                    "rva",
                    "scope_decision",
                    "body_output_status",
                    "raw_body_hash",
                    "asm_sha256",
                    "c_sha256",
                    "diagnostic",
                ],
                native_body_csv,
            ),
        )
        _write_staged_bytes(
            staging / "native_prototypes.csv",
            _csv_bytes(
                [
                    "native_body_id",
                    "build_id",
                    "architecture",
                    "abi",
                    "entrypoint_role",
                    "calling_convention",
                    "prototype_text",
                    "provenance",
                    "status",
                ],
                prototypes_csv,
            ),
        )
        _write_staged_bytes(
            staging / "native_locations.csv",
            _csv_bytes(
                [
                    "native_body_id",
                    "build_id",
                    "module_logical_path",
                    "module_sha256",
                    "architecture",
                    "format",
                    "rva",
                    "file_offset",
                    "preferred_va",
                ],
                locations_csv,
            ),
        )
        _write_staged_bytes(
            staging / "symbol_body_links.csv",
            _csv_bytes(
                [
                    "symbol_id",
                    "native_body_id",
                    "build_id",
                    "entrypoint_role",
                    "body_resolution_status",
                    "managed_signature",
                ],
                links_csv,
            ),
        )
        _write_staged_bytes(
            staging / "references.csv",
            _csv_bytes(
                [
                    "source_native_body_id",
                    "reference_kind",
                    "source_instruction_rva",
                    "target_raw",
                    "target_rva",
                    "target_native_body_id",
                    "resolution_status",
                ],
                references_csv,
            ),
        )
        _write_staged_json(
            staging / "metadata" / "adapter-result.json", metadata_result
        )
        bsim_index = {
            "modules": {
                logical_path: _load_module_bundle(roots.artifacts, digest).get(
                    "bsim", {"status": "not_recorded"}
                )
                for logical_path, digest in sorted(module_digests.items())
            },
            "schema_version": 1,
        }
        _write_staged_json(staging / "native" / "bsim-index.json", bsim_index)
        coverage = _coverage(
            db,
            build_id=build_id,
            analysis_key=analysis_key,
            metadata_result=metadata_result,
        )
        if not coverage["exact_body_reconciliation"]:
            raise ValidationError(
                "Réconciliation de couverture native inexacte.",
                error_code="native_coverage_mismatch",
            )
        _write_staged_json(staging / "coverage.json", coverage)
        analysis_manifest = {
            "analysis_key": analysis_key,
            "body_manifest_sha256": body_manifest_digests,
            "build_id": build_id,
            "metadata_status": metadata_result["status"],
            "module_manifest_sha256": module_digests,
            "producer": NATIVE_PRODUCER,
            "schema_version": 1,
            "snapshot_id": snapshot_id,
        }
        _write_staged_json(staging / "analysis-manifest.json", analysis_manifest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "sync"):
            os.sync()
        os.replace(staging, destination)
        fsync_directory(destination.parent)
        atomic_write_json(
            roots.output / "current.json",
            {
                "analysis": relative.as_posix(),
                "analysis_key": analysis_key,
                "build_id": build_id,
                "schema_version": 1,
                "snapshot_id": snapshot_id,
            },
        )
        return destination, coverage, True
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _native_producer_digest(adapter: GhidraAdapter) -> str:
    package_root = Path(__file__).parent
    files = [
        package_root / "native.py",
        package_root / "ghidra_adapter.py",
        package_root / "il2cpp.py",
        package_root / "pe.py",
        adapter.script,
    ]
    return digest_json({path.name: sha256_file(path)[0] for path in files})


def _store_report_steps(
    db: sqlite3.Connection, *, analysis_id: str, report: RunReport
) -> None:
    for item in report.steps:
        value = item.public()
        db.execute(
            """INSERT INTO stage_runs(
                stage_run_id,analysis_id,step_id,parent_step_id,stage_name,substep_name,
                component_id,status,reason,cache_status,tool_name,tool_version,
                started_at,ended_at,duration_ms,input_item_count,input_bytes,
                output_item_count,output_bytes,cpu_time_ms,peak_rss_bytes,error_code
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"{analysis_id}:{value['step_id']}",
                analysis_id,
                value["step_id"],
                value["parent_step_id"],
                value["stage_name"],
                value["substep_name"],
                value["component_id"],
                value["status"],
                value["reason"],
                value["cache_status"],
                value["tool_name"],
                value["tool_version"],
                value["started_at"],
                value["ended_at"],
                value["duration_ms"],
                value["input_item_count"],
                value["input_bytes"],
                value["output_item_count"],
                value["output_bytes"],
                value["cpu_time_ms"],
                value["peak_rss_bytes"],
                value["error_code"],
            ),
        )


def analyze_native_snapshot(
    *,
    roots: NativeRoots,
    snapshot_id: str,
    profile: LoadedYaml,
    input_profile: LoadedYaml,
    policy: LoadedYaml,
    tools_lock: dict[str, Any],
    migrations_root: Path,
    adapter: GhidraAdapter,
    enforce_read_only_inputs: bool,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    assert_no_live_source_environment()
    if enforce_read_only_inputs:
        assert_inputs_read_only(roots.inputs)
    manifest_path = roots.inputs / "snapshots" / snapshot_id / "capture-manifest.json"
    if not manifest_path.is_file():
        raise ValidationError(
            "Snapshot M2 absent.", error_code="native_snapshot_missing"
        )
    manifest = read_json(manifest_path)
    if manifest.get("snapshot_id") != snapshot_id:
        raise ValidationError(
            "Identité du snapshot M2 incohérente.",
            error_code="native_snapshot_mismatch",
        )
    if manifest.get("selection_sha256") != input_profile.sha256:
        raise ValidationError(
            "Allowlist du snapshot M2 incompatible.",
            error_code="selection_digest_mismatch",
        )
    if policy.data.get("input_selection_id") != manifest.get("selection_id"):
        raise ValidationError(
            "Politique M2 liée à une autre allowlist.",
            error_code="policy_selection_mismatch",
        )
    verify_snapshot(roots.inputs, snapshot_id, full_hash=False)
    manifest_sha256, _ = sha256_file(manifest_path)
    approved = _approved_modules(manifest, policy)
    payloads = _manifest_payloads(manifest)
    snapshot_files = roots.inputs / "snapshots" / snapshot_id / "files"
    metadata_result = inspect_metadata_pair(
        manifest=manifest, snapshot_files=snapshot_files
    )
    tool_context = {
        **adapter.context(),
        "policy_sha256": policy.sha256,
        "tools_lock_sha256": digest_json(tools_lock),
    }
    analysis_basis = {
        "metadata_pair": {
            "binary": (metadata_result.get("binary") or {}).get("sha256"),
            "metadata": (metadata_result.get("metadata") or {}).get("sha256"),
        },
        "modules": [
            {
                "logical_path": item["logical_path"],
                "sha256": payloads[item["logical_path"]]["sha256"],
            }
            for item in approved
        ],
        "producer_digest": _native_producer_digest(adapter),
        "profile_sha256": profile.sha256,
        "snapshot_id": snapshot_id,
        "tool_context": tool_context,
    }
    analysis_key = f"m2-{digest_json(analysis_basis)}"
    run_id = workflow_run_id or f"run-m2-{uuid.uuid4()}"
    analysis_id = f"run:{run_id}"
    report = RunReport(run_id, "native-analysis")
    report.snapshot_id = snapshot_id
    module_digests: dict[str, str] = {}
    module_cache: dict[str, str] = {}
    try:
        with (
            registry_writer_lock(roots.state),
            Registry(roots.state / "registry.sqlite", migrations_root) as registry,
        ):
            db = registry.db
            db.execute("BEGIN IMMEDIATE")
            try:
                _register_snapshot(registry, manifest, manifest_sha256, run_id)
                db.execute(
                    """INSERT INTO analysis_runs(
                            analysis_id,workflow_run_id,snapshot_id,analysis_key,status,started_at
                        ) VALUES(?,?,?,?,?,?)""",
                    (
                        analysis_id,
                        run_id,
                        snapshot_id,
                        analysis_key,
                        "running",
                        report.started_at,
                    ),
                )
                for decision in _scope_decisions(manifest, policy):
                    decision_id = (
                        f"scope:{digest_json([snapshot_id, decision['subject_id']])}"
                    )
                    db.execute(
                        """INSERT OR REPLACE INTO scope_decisions(
                                scope_decision_id,snapshot_id,subject_kind,subject_id,
                                decision,reason,evidence_refs_json
                            ) VALUES(?,?,?,?,?,?,?)""",
                        (
                            decision_id,
                            snapshot_id,
                            decision["subject_kind"],
                            decision["subject_id"],
                            decision["decision"],
                            decision["reason"],
                            canonical_json_bytes(decision["evidence_refs"]).decode(
                                "utf-8"
                            ),
                        ),
                    )
                with report.step(
                    "analysis.metadata",
                    "metadata",
                    category="analysis",
                    tool_name="modkit.il2cpp.bounded-header",
                    tool_version="1",
                ) as step:
                    step.input_item_count = 2
                    step.output_item_count = 1
                    step.reason = metadata_result["status"]
                db.execute(
                    """INSERT INTO metadata_adapter_results(
                            metadata_adapter_result_id,analysis_id,build_id,
                            binary_input_object_id,metadata_input_object_id,status,
                            catalog_published,fallback_used,details_json
                        ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        f"metadata-result:{uuid.uuid4()}",
                        analysis_id,
                        manifest["build_id"],
                        (metadata_result.get("binary") or {}).get("object_id"),
                        (metadata_result.get("metadata") or {}).get("object_id"),
                        metadata_result["status"],
                        int(bool(metadata_result["catalog_published"])),
                        int(bool(metadata_result["fallback_used"])),
                        canonical_json_bytes(metadata_result).decode("utf-8"),
                    ),
                )

                bundles: dict[str, dict[str, Any]] = {}
                for decision in approved:
                    logical_path = str(decision["logical_path"])
                    payload = payloads[logical_path]
                    module_sha256 = str(payload["sha256"])
                    module_path = confined_path(snapshot_files, logical_path)
                    pe = PeImage(module_path)
                    module_context = {
                        "load_context": pe.load_context(),
                        "module_sha256": module_sha256,
                        "policy_sha256": policy.sha256,
                        "tool_context": tool_context,
                    }
                    module_context_sha256 = digest_json(module_context)
                    revision_id = _component_revision_id(logical_path, module_sha256)
                    cached = db.execute(
                        """SELECT output_manifest_sha256 FROM native_module_analyses
                               WHERE component_revision_id=? AND analysis_context_sha256=?
                                 AND status='completed'""",
                        (revision_id, module_context_sha256),
                    ).fetchone()
                    stage_id = f"analysis.native.{_slug(Path(logical_path).name)}"
                    if (
                        cached is not None
                        and object_path(roots.artifacts, str(cached[0])).is_file()
                    ):
                        bundle_digest = str(cached[0])
                        bundle = _load_module_bundle(roots.artifacts, bundle_digest)
                        module_cache[logical_path] = "hit"
                        report.add_step(
                            stage_id,
                            "native_module",
                            category="analysis",
                            component_id=revision_id,
                            status="cache_hit",
                            reason="complete_module_context_match",
                            cache_status="hit",
                            tool_name="Ghidra",
                            tool_version="12.1.4 PUBLIC",
                            input_item_count=1,
                            input_bytes=int(payload["size_bytes"]),
                            output_item_count=len(bundle["bodies"]),
                        )
                    else:
                        with report.step(
                            stage_id,
                            "native_module",
                            category="analysis",
                            component_id=revision_id,
                            cache_status="miss",
                            tool_name="Ghidra",
                            tool_version="12.1.4 PUBLIC",
                        ) as step:
                            step.input_item_count = 1
                            step.input_bytes = int(payload["size_bytes"])
                            exported = adapter.export_module(
                                module_path=module_path,
                                module_logical_path=logical_path,
                                module_sha256=module_sha256,
                            )
                            if exported.resumed:
                                step.reason = "validated_private_intermediate_resume"
                            bundle, bundle_digest = normalize_ghidra_export(
                                export=exported,
                                module_logical_path=logical_path,
                                module_sha256=module_sha256,
                                pe=pe,
                                analysis_context_sha256=module_context_sha256,
                                artifacts_root=roots.artifacts,
                            )
                            step.output_item_count = len(bundle["bodies"])
                            step.output_bytes = sum(
                                int(body.get("body_byte_count", 0))
                                for body in bundle["bodies"]
                            )
                        module_cache[logical_path] = "miss"
                    bundles[logical_path] = bundle
                    module_digests[logical_path] = bundle_digest

                for logical_path, bundle in bundles.items():
                    if module_cache[logical_path] == "hit":
                        revision_id = _component_revision_id(
                            logical_path, str(bundle["module_sha256"])
                        )
                        materialized_count = int(
                            db.execute(
                                """SELECT COUNT(*) FROM body_observations
                                   WHERE build_id=? AND component_revision_id=?""",
                                (manifest["build_id"], revision_id),
                            ).fetchone()[0]
                        )
                        if materialized_count == len(bundle["bodies"]):
                            continue
                    _ingest_module(
                        db=db,
                        build_id=str(manifest["build_id"]),
                        analysis_id=analysis_id,
                        bundle=bundle,
                        bundle_sha256=module_digests[logical_path],
                        cache_status=module_cache[logical_path],
                        tool_context=tool_context,
                    )
                analysis_key = f"m2-{digest_json({'basis': analysis_basis, 'module_manifests': module_digests})}"
                db.execute(
                    "UPDATE analysis_runs SET analysis_key=? WHERE analysis_id=?",
                    (analysis_key, analysis_id),
                )
                with report.step(
                    "analysis.native.publish",
                    "publish",
                    category="publication",
                    tool_name="modkit.native",
                    tool_version=NATIVE_PRODUCER["version"],
                ) as step:
                    destination, coverage, published = _publish_analysis_output(
                        db=db,
                        roots=roots,
                        build_id=str(manifest["build_id"]),
                        snapshot_id=snapshot_id,
                        analysis_key=analysis_key,
                        metadata_result=metadata_result,
                        module_digests=module_digests,
                    )
                    step.status = "completed" if published else "cache_hit"
                    step.cache_status = "miss" if published else "hit"
                    step.output_item_count = int(coverage["approved_body_count"])
                coverage_data = pretty_json_bytes(coverage)
                db.execute(
                    """INSERT INTO coverage_reports(
                            coverage_report_id,analysis_id,build_id,report_sha256,
                            approved_body_count,c_and_asm_count,asm_only_count,
                            disassembly_failed_count,pending_count,exact_reconciliation,
                            discovery_complete
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        f"coverage:{uuid.uuid4()}",
                        analysis_id,
                        manifest["build_id"],
                        sha256_bytes(coverage_data),
                        coverage["approved_body_count"],
                        coverage["body_status_counts"]["c_and_asm"],
                        coverage["body_status_counts"]["asm_only"],
                        coverage["body_status_counts"]["disassembly_failed"],
                        coverage["body_status_counts"]["pending"],
                        int(coverage["exact_body_reconciliation"]),
                        int(coverage["discovery_complete"]),
                    ),
                )
                report.metadata.update(
                    {
                        "analysis_key": analysis_key,
                        "build_id": manifest["build_id"],
                        "metadata_status": metadata_result["status"],
                        "migrations_applied": registry.applied_migrations,
                        "module_cache": module_cache,
                        "native_body_count": coverage["approved_body_count"],
                    }
                )
                report.finish("completed")
                _store_report_steps(db, analysis_id=analysis_id, report=report)
                db.execute(
                    "UPDATE analysis_runs SET status='completed',ended_at=? WHERE analysis_id=?",
                    (report.ended_at, analysis_id),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise
        publish_report(roots.output, report.public())
        return {
            "analysis_key": analysis_key,
            "build_id": manifest["build_id"],
            "coverage": coverage,
            "metadata_status": metadata_result["status"],
            "module_cache": module_cache,
            "output": destination.relative_to(roots.output).as_posix(),
            "report": f"reports/{run_id}/run-report.json",
            "snapshot_id": snapshot_id,
            "workflow_run_id": run_id,
        }
    except BaseException:
        report.finish("failed")
        publish_report(roots.output, report.public())
        raise


def native_roots_from_analyzer(roots: AnalyzerRoots, ghidra_root: Path) -> NativeRoots:
    return NativeRoots(
        inputs=roots.inputs,
        state=roots.state,
        artifacts=roots.artifacts,
        ghidra=ghidra_root,
        work=roots.work,
        output=roots.output,
    )
