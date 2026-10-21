from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import (
    _register_snapshot,
    assert_inputs_read_only,
    assert_no_live_source_environment,
)
from .capture import verify_snapshot
from .config import LoadedYaml
from .errors import ValidationError
from .native import (
    _approved_modules,
    _component_revision_id,
    _ingest_module,
    _load_module_bundle,
    _manifest_payloads,
    _slug,
    _store_report_steps,
)
from .registry import Registry, registry_writer_lock
from .reporting import RunReport, publish_report
from .util import (
    atomic_write_json,
    canonical_json_bytes,
    digest_json,
    fsync_directory,
    object_path,
    pretty_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

COMPARE_PRODUCER = {"name": "modkit.compare", "version": "0.1.0"}
FINGERPRINT_ALGORITHM = "dependency-fingerprint-v1-strict"


@dataclass(frozen=True)
class CompareRoots:
    inputs: Path
    state: Path
    artifacts: Path
    output: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _producer_digest() -> str:
    paths = [Path(__file__), Path(__file__).with_name("native.py")]
    return digest_json({path.name: sha256_file(path)[0] for path in paths})


def _load_snapshot(
    roots: CompareRoots, snapshot_id: str, input_profile: LoadedYaml
) -> tuple[dict[str, Any], str]:
    path = roots.inputs / "snapshots" / snapshot_id / "capture-manifest.json"
    if not path.is_file():
        raise ValidationError(
            f"Snapshot de comparaison absent : {snapshot_id}",
            error_code="comparison_snapshot_missing",
        )
    value = read_json(path)
    if value.get("snapshot_id") != snapshot_id:
        raise ValidationError(
            "Identité de snapshot incohérente.",
            error_code="comparison_snapshot_mismatch",
        )
    if value.get("selection_sha256") != input_profile.sha256:
        raise ValidationError(
            "Allowlist du snapshot de comparaison incompatible.",
            error_code="selection_digest_mismatch",
        )
    verify_snapshot(roots.inputs, snapshot_id, full_hash=False)
    return value, sha256_file(path)[0]


def _validate_annotations(annotations: LoadedYaml) -> dict[str, Any]:
    value = annotations.data
    if value.get("schema_version") != 1:
        raise ValidationError(
            "Version des annotations de matching non prise en charge.",
            error_code="matching_annotations_schema",
        )
    allowed = {"schema_version", "reviews", "bsim_candidates", "layouts"}
    unknown = set(value) - allowed
    if unknown:
        raise ValidationError(
            f"Clés d'annotations inconnues : {sorted(unknown)}",
            error_code="matching_annotations_unknown_key",
        )
    for field in ("reviews", "bsim_candidates", "layouts"):
        if not isinstance(value.get(field, []), list):
            raise ValidationError(
                f"Liste d'annotations invalide : {field}",
                error_code="matching_annotations_invalid",
            )
    return value


def _materialize_cached_build(
    *,
    db: sqlite3.Connection,
    roots: CompareRoots,
    manifest: dict[str, Any],
    policy: LoadedYaml,
    analysis_id: str,
) -> dict[str, Any]:
    payloads = _manifest_payloads(manifest)
    build_id = str(manifest["build_id"])
    result: dict[str, Any] = {"already_materialized": 0, "cache_materialized": 0}
    for decision in _approved_modules(manifest, policy):
        logical_path = str(decision["logical_path"])
        module_sha256 = str(payloads[logical_path]["sha256"])
        revision_id = _component_revision_id(logical_path, module_sha256)
        observed = int(
            db.execute(
                """SELECT COUNT(*) FROM body_observations
                   WHERE build_id=? AND component_revision_id=?""",
                (build_id, revision_id),
            ).fetchone()[0]
        )
        candidates = [
            str(row[0])
            for row in db.execute(
                """SELECT DISTINCT output_manifest_sha256
                   FROM native_module_analyses
                   WHERE component_revision_id=? AND status='completed'
                   ORDER BY output_manifest_sha256""",
                (revision_id,),
            )
        ]
        valid: list[tuple[str, dict[str, Any]]] = []
        for digest in candidates:
            if not object_path(roots.artifacts, digest).is_file():
                continue
            bundle = _load_module_bundle(roots.artifacts, digest)
            if (
                bundle.get("module_logical_path") == logical_path
                and bundle.get("module_sha256") == module_sha256
            ):
                valid.append((digest, bundle))
        if observed:
            expected = len(valid[0][1]["bodies"]) if valid else observed
            if observed != expected:
                raise ValidationError(
                    f"Matérialisation native partielle : {logical_path}",
                    error_code="comparison_partial_native_materialization",
                )
            result["already_materialized"] += 1
            continue
        unique = {digest: bundle for digest, bundle in valid}
        if len(unique) != 1:
            reason = "absent" if not unique else "ambigu"
            raise ValidationError(
                f"Bundle M2 complet {reason} pour {logical_path}; une auto-analyse globale du module exact est requise.",
                error_code="comparison_requires_native_analysis",
            )
        digest, bundle = next(iter(unique.items()))
        _ingest_module(
            db=db,
            build_id=build_id,
            analysis_id=analysis_id,
            bundle=bundle,
            bundle_sha256=digest,
            cache_status="hit",
            tool_context={
                "bundle_sha256": digest,
                "materialization": "exact_completed_m2_bundle",
            },
            record_attempts=False,
            record_module_analysis=False,
        )
        result["cache_materialized"] += 1
    return result


class _ReferenceDigests:
    def __init__(self) -> None:
        self.all = hashlib.sha256()
        self.calls = hashlib.sha256()
        self.data = hashlib.sha256()
        self.count = 0
        self.call_count = 0
        self.data_count = 0

    def update(self, item: dict[str, Any], *, is_call: bool) -> None:
        encoded = canonical_json_bytes(item)
        self.all.update(encoded)
        self.count += 1
        target = self.calls if is_call else self.data
        target.update(encoded)
        if is_call:
            self.call_count += 1
        else:
            self.data_count += 1

    def public(self) -> dict[str, Any]:
        return {
            "call_targets_hash": self.calls.hexdigest(),
            "reference_context_hash": self.all.hexdigest(),
            "referenced_data_hash": self.data.hexdigest(),
            "reference_count": self.count,
            "call_reference_count": self.call_count,
            "data_reference_count": self.data_count,
        }


def _layout_map(annotations: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in annotations.get("layouts", []):
        if not isinstance(item, dict):
            raise ValidationError(
                "Annotation de layout invalide.",
                error_code="matching_annotations_invalid",
            )
        build_id = str(item.get("build_id", ""))
        body_id = str(item.get("native_body_id", ""))
        layout_hash = str(item.get("layout_hash", ""))
        if not build_id or not body_id or len(layout_hash) != 64:
            raise ValidationError(
                "Annotation de layout incomplète.",
                error_code="matching_annotations_invalid",
            )
        result[(build_id, body_id)] = item
    return result


def build_dependency_fingerprints(
    db: sqlite3.Connection,
    *,
    build_id: str,
    annotations: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build strict fingerprints without normalizing unproven immediates."""
    body_rows = [
        dict(row)
        for row in db.execute(
            """SELECT native_body_id,component_revision_id,module_logical_path,
                      module_sha256,rva,raw_body_hash,body_output_status,
                      asm_artifact_sha256,c_artifact_sha256,instruction_count,
                      body_byte_count,reference_context_hash
               FROM body_observations WHERE build_id=?
               ORDER BY module_logical_path,rva,native_body_id""",
            (build_id,),
        )
    ]
    prototypes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in db.execute(
        """SELECT native_body_id,architecture,abi,entrypoint_role,
                  calling_convention,prototype_text,provenance,status
           FROM native_prototypes WHERE build_id=?
           ORDER BY native_body_id,entrypoint_role,native_prototype_id""",
        (build_id,),
    ):
        prototypes[str(row[0])].append(
            {
                "abi": row[2],
                "architecture": row[1],
                "calling_convention": row[4],
                "entrypoint_role": row[3],
                "prototype_text": row[5],
                "provenance": row[6],
                "status": row[7],
            }
        )
    managed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in db.execute(
        """SELECT sbl.native_body_id,so.signature_key,
                  so.managed_signature,so.static_kind
           FROM symbol_body_links sbl
           JOIN symbol_observations so
             ON so.symbol_id=sbl.symbol_id AND so.build_id=sbl.build_id
            AND so.component_revision_id=sbl.component_revision_id
           JOIN symbols s ON s.symbol_id=so.symbol_id
           WHERE sbl.build_id=? AND s.symbol_kind='managed_method'
           ORDER BY sbl.native_body_id,so.signature_key,so.symbol_id""",
        (build_id,),
    ):
        managed[str(row[0])].append(
            {
                "managed_signature": row[2],
                "signature_key": row[1],
                "static_kind": row[3],
            }
        )
    rvas = {str(row["native_body_id"]): int(row["rva"]) for row in body_rows}
    references: dict[str, _ReferenceDigests] = {}
    for row in db.execute(
        """SELECT source_native_body_id,reference_kind,source_instruction_rva,
                  target_raw,target_rva,target_native_body_id,resolution_status,
                  evidence_json
           FROM native_references WHERE build_id=?
           ORDER BY source_native_body_id,source_instruction_rva,reference_kind,
                    COALESCE(target_raw,''),native_reference_id""",
        (build_id,),
    ):
        body_id = str(row[0])
        accumulator = references.setdefault(body_id, _ReferenceDigests())
        try:
            evidence = json.loads(str(row[7]))
        except json.JSONDecodeError:
            evidence = {
                "parse_error": True,
                "raw_sha256": sha256_bytes(str(row[7]).encode()),
            }
        item = {
            "evidence": evidence,
            "kind": row[1],
            "resolution_status": row[6],
            "source_instruction_delta": int(row[2]) - rvas.get(body_id, int(row[2])),
            "target_native_body_id": row[5],
            "target_raw": row[3],
            "target_rva": f"0x{int(row[4]):x}" if row[4] is not None else None,
        }
        accumulator.update(item, is_call="call" in str(row[1]).casefold())
    layouts = _layout_map(annotations)
    result: dict[str, dict[str, Any]] = {}
    empty_refs = _ReferenceDigests().public()
    for row in body_rows:
        body_id = str(row["native_body_id"])
        signature_payload = {
            "managed": managed.get(body_id, []),
            "native": prototypes.get(body_id, []),
        }
        refs = references[body_id].public() if body_id in references else empty_refs
        layout = layouts.get((build_id, body_id))
        raw_hash = row["raw_body_hash"]
        strict_payload = {
            "asm_artifact_sha256": row["asm_artifact_sha256"],
            "body_byte_count": row["body_byte_count"],
            "instruction_count": row["instruction_count"],
            "raw_body_hash": raw_hash,
        }
        completeness = (
            "complete"
            if raw_hash is not None
            and row["body_output_status"] in {"c_and_asm", "asm_only"}
            and layout is not None
            else "partial"
        )
        fingerprint = {
            "algorithm_version": FINGERPRINT_ALGORITHM,
            "build_id": build_id,
            "call_targets_hash": refs["call_targets_hash"],
            "component_revision_id": row["component_revision_id"],
            "completeness": completeness,
            "evidence": {
                "body_output_status": row["body_output_status"],
                "call_reference_count": refs["call_reference_count"],
                "data_reference_count": refs["data_reference_count"],
                "layout_evidence_refs": layout.get("evidence_refs", [])
                if layout
                else [],
                "normalization": "none; semantic constants and field offsets are preserved",
                "reference_count": refs["reference_count"],
            },
            "layout_hash": layout.get("layout_hash") if layout else None,
            "module_logical_path": row["module_logical_path"],
            "module_sha256": row["module_sha256"],
            "native_body_id": body_id,
            "raw_body_hash": raw_hash,
            "reference_context_hash": refs["reference_context_hash"],
            "referenced_data_hash": refs["referenced_data_hash"],
            "rva": int(row["rva"]),
            "semantic_operands_hash": raw_hash,
            "signature_hash": digest_json(signature_payload),
            "strict_semantic_hash": digest_json(strict_payload),
        }
        fingerprint["dependency_fingerprint_id"] = (
            f"dependency-fingerprint:{digest_json([build_id, body_id, FINGERPRINT_ALGORITHM])}"
        )
        result[body_id] = fingerprint
    return result


def _store_fingerprints(
    db: sqlite3.Connection, fingerprints: dict[str, dict[str, Any]]
) -> None:
    for item in fingerprints.values():
        values = (
            item["dependency_fingerprint_id"],
            item["build_id"],
            item["native_body_id"],
            item["component_revision_id"],
            item["algorithm_version"],
            item["raw_body_hash"],
            item["strict_semantic_hash"],
            item["semantic_operands_hash"],
            item["signature_hash"],
            item["layout_hash"],
            item["call_targets_hash"],
            item["referenced_data_hash"],
            item["reference_context_hash"],
            item["completeness"],
            canonical_json_bytes(item["evidence"]).decode("utf-8"),
        )
        existing = db.execute(
            """SELECT raw_body_hash,strict_semantic_hash,semantic_operands_hash,
                      signature_hash,layout_hash,call_targets_hash,
                      referenced_data_hash,reference_context_hash,completeness,
                      evidence_json
               FROM dependency_fingerprints
               WHERE build_id=? AND native_body_id=? AND algorithm_version=?""",
            (item["build_id"], item["native_body_id"], item["algorithm_version"]),
        ).fetchone()
        if existing is not None:
            expected = values[5:]
            if tuple(existing) != expected:
                raise ValidationError(
                    "Une empreinte immuable existante diffère; versionnez l'algorithme.",
                    error_code="dependency_fingerprint_conflict",
                )
            continue
        db.execute(
            """INSERT INTO dependency_fingerprints(
                dependency_fingerprint_id,build_id,native_body_id,
                component_revision_id,algorithm_version,raw_body_hash,
                strict_semantic_hash,semantic_operands_hash,signature_hash,
                layout_hash,call_targets_hash,referenced_data_hash,
                reference_context_hash,completeness,evidence_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            values,
        )


def _symbol_records(
    db: sqlite3.Connection,
    *,
    build_id: str,
    fingerprints: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        """SELECT so.symbol_id,s.symbol_kind,so.observed_name,so.namespace,
                  so.managed_signature,so.signature_key,so.static_kind,
                  so.body_resolution_status,sbl.native_body_id,
                  sbl.entrypoint_role,bo.module_logical_path,bo.rva
           FROM symbol_observations so
           JOIN symbols s ON s.symbol_id=so.symbol_id
           LEFT JOIN symbol_body_links sbl
             ON sbl.symbol_id=so.symbol_id AND sbl.build_id=so.build_id
            AND sbl.component_revision_id=so.component_revision_id
           LEFT JOIN body_observations bo
             ON bo.native_body_id=sbl.native_body_id AND bo.build_id=so.build_id
           WHERE so.build_id=?
           ORDER BY so.symbol_id,COALESCE(sbl.entrypoint_role,''),
                    COALESCE(sbl.native_body_id,'')""",
        (build_id,),
    ):
        symbol_id = str(row[0])
        if symbol_id in records:
            continue
        body_id = str(row[8]) if row[8] is not None else None
        records[symbol_id] = {
            "body_resolution_status": row[7],
            "entrypoint_role": row[9],
            "fingerprint": fingerprints.get(body_id) if body_id else None,
            "managed_signature": row[4],
            "module_logical_path": row[10],
            "name": row[2],
            "namespace": row[3],
            "native_body_id": body_id,
            "rva": int(row[11]) if row[11] is not None else None,
            "signature_key": row[5],
            "static_kind": row[6],
            "symbol_id": symbol_id,
            "symbol_kind": row[1],
        }
    return records


def _index_unique(
    records: dict[str, dict[str, Any]], key_function: Any
) -> dict[Any, str]:
    grouped: dict[Any, list[str]] = defaultdict(list)
    for symbol_id, item in records.items():
        key = key_function(item)
        if key is not None:
            grouped[key].append(symbol_id)
    return {key: values[0] for key, values in grouped.items() if len(values) == 1}


def match_symbols(
    source: dict[str, dict[str, Any]],
    destination: dict[str, dict[str, Any]],
    annotations: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return explainable matches; similarity evidence always remains a candidate."""
    source_signatures = _index_unique(source, lambda item: item.get("signature_key"))
    destination_signatures = _index_unique(
        destination, lambda item: item.get("signature_key")
    )
    destination_names = _index_unique(
        destination,
        lambda item: (
            (
                item.get("module_logical_path"),
                item.get("namespace"),
                item.get("name"),
                item.get("symbol_kind"),
            )
            if item.get("name")
            else None
        ),
    )
    source_names = _index_unique(
        source,
        lambda item: (
            (
                item.get("module_logical_path"),
                item.get("namespace"),
                item.get("name"),
                item.get("symbol_kind"),
            )
            if item.get("name")
            else None
        ),
    )
    destination_hashes = _index_unique(
        destination,
        lambda item: (
            (
                item.get("module_logical_path"),
                (item.get("fingerprint") or {}).get("raw_body_hash"),
            )
            if (item.get("fingerprint") or {}).get("raw_body_hash")
            else None
        ),
    )
    source_hashes = _index_unique(
        source,
        lambda item: (
            (
                item.get("module_logical_path"),
                (item.get("fingerprint") or {}).get("raw_body_hash"),
            )
            if (item.get("fingerprint") or {}).get("raw_body_hash")
            else None
        ),
    )
    reviews: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in annotations.get("reviews", []):
        if not isinstance(item, dict) or item.get("decision") not in {
            "confirmed",
            "rejected",
        }:
            raise ValidationError(
                "Revue d'appariement invalide.",
                error_code="matching_annotations_invalid",
            )
        reviews[str(item.get("source_symbol_id"))].append(item)
    bsim: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in annotations.get("bsim_candidates", []):
        if not isinstance(item, dict):
            raise ValidationError(
                "Candidat BSim invalide.",
                error_code="matching_annotations_invalid",
            )
        bsim[str(item.get("source_symbol_id"))].append(item)

    results: list[dict[str, Any]] = []
    observed_destinations: set[str] = set()
    for source_id in sorted(source):
        source_item = source[source_id]
        destination_id: str | None = None
        method = "unmatched"
        status = "unmatched"
        score: float | None = None
        evidence: list[dict[str, Any]] = []
        contradictions: list[dict[str, Any]] = []
        alternatives: list[dict[str, Any]] = []

        confirmed_reviews = [
            item
            for item in reviews.get(source_id, [])
            if item["decision"] == "confirmed"
        ]
        rejected_destinations = {
            str(item.get("destination_symbol_id"))
            for item in reviews.get(source_id, [])
            if item["decision"] == "rejected"
        }
        if len(confirmed_reviews) > 1:
            raise ValidationError(
                f"Plusieurs revues confirmées pour {source_id}.",
                error_code="matching_review_conflict",
            )
        if confirmed_reviews:
            destination_id = str(confirmed_reviews[0].get("destination_symbol_id"))
            if destination_id not in destination:
                raise ValidationError(
                    "La revue cible un symbole absent du build destination.",
                    error_code="matching_review_target_missing",
                )
            method = "reviewed_annotation"
            status = "confirmed"
            evidence.append(
                {
                    "evidence_refs": confirmed_reviews[0].get("evidence_refs", []),
                    "reason": confirmed_reviews[0].get("reason"),
                    "reviewer": confirmed_reviews[0].get("reviewer"),
                }
            )
        elif source_id in destination:
            destination_id = source_id
            method = "persistent_symbol_identity"
            status = "confirmed"
            evidence.append({"symbol_id": source_id})
        else:
            signature = source_item.get("signature_key")
            if (
                signature
                and source_signatures.get(signature) == source_id
                and destination_signatures.get(signature) not in rejected_destinations
            ):
                destination_id = destination_signatures.get(signature)
                if destination_id:
                    method = "managed_signature_identity"
                    status = "confirmed"
                    evidence.append({"signature_key": signature})

        if status != "confirmed":
            candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
            name_key = (
                source_item.get("module_logical_path"),
                source_item.get("namespace"),
                source_item.get("name"),
                source_item.get("symbol_kind"),
            )
            by_name = (
                destination_names.get(name_key) if source_item.get("name") else None
            )
            if (
                by_name
                and source_names.get(name_key) == source_id
                and by_name not in rejected_destinations
            ):
                candidates[by_name].append(
                    {"method": "unique_observed_name_candidate", "name_key": name_key}
                )
            raw_hash = (source_item.get("fingerprint") or {}).get("raw_body_hash")
            by_hash = (
                destination_hashes.get(
                    (source_item.get("module_logical_path"), raw_hash)
                )
                if raw_hash
                else None
            )
            if (
                by_hash
                and source_hashes.get(
                    (source_item.get("module_logical_path"), raw_hash)
                )
                == source_id
                and by_hash not in rejected_destinations
            ):
                candidates[by_hash].append(
                    {"method": "raw_body_hash_candidate", "raw_body_hash": raw_hash}
                )
            for item in bsim.get(source_id, []):
                target = str(item.get("destination_symbol_id"))
                if target in destination and target not in rejected_destinations:
                    candidates[target].append(
                        {
                            "evidence_refs": item.get("evidence_refs", []),
                            "method": "bsim_candidate",
                            "score": item.get("score"),
                        }
                    )
            if len(candidates) == 1:
                destination_id, candidate_evidence = next(iter(candidates.items()))
                methods = [str(item["method"]) for item in candidate_evidence]
                method = (
                    "raw_body_hash_candidate"
                    if "raw_body_hash_candidate" in methods
                    else methods[0]
                )
                status = "candidate"
                evidence.extend(candidate_evidence)
                scores = [
                    float(item["score"])
                    for item in candidate_evidence
                    if item.get("score") is not None
                ]
                score = max(scores) if scores else None
            elif len(candidates) > 1:
                status = "conflict"
                method = "unmatched"
                for candidate_id, candidate_evidence in sorted(candidates.items()):
                    alternatives.append(
                        {
                            "destination_symbol_id": candidate_id,
                            "evidence": candidate_evidence,
                        }
                    )
                contradictions.append(
                    {"reason": "independent_candidate_methods_disagree"}
                )
        if status == "unmatched" and rejected_destinations:
            contradictions.extend(
                {
                    "destination_symbol_id": item,
                    "reason": "explicitly_rejected_by_review",
                }
                for item in sorted(rejected_destinations)
            )
        if destination_id is not None:
            observed_destinations.add(destination_id)
        match_id = f"match:{digest_json([source_id, destination_id, method, status])}"
        results.append(
            {
                "alternatives": alternatives,
                "contradictions": contradictions,
                "destination_native_body_id": (
                    destination[destination_id].get("native_body_id")
                    if destination_id is not None
                    else None
                ),
                "destination_symbol_id": destination_id,
                "evidence": evidence,
                "match_id": match_id,
                "match_method": method,
                "match_status": status,
                "review_required": status not in {"confirmed", "unmatched"},
                "score": score,
                "source_native_body_id": source_item.get("native_body_id"),
                "source_symbol_id": source_id,
            }
        )
    for destination_id in sorted(set(destination) - observed_destinations):
        item = destination[destination_id]
        results.append(
            {
                "alternatives": [],
                "contradictions": [],
                "destination_native_body_id": item.get("native_body_id"),
                "destination_symbol_id": destination_id,
                "evidence": [],
                "match_id": f"match:{digest_json([None, destination_id, 'unmatched'])}",
                "match_method": "unmatched",
                "match_status": "unmatched",
                "review_required": False,
                "score": None,
                "source_native_body_id": None,
                "source_symbol_id": None,
            }
        )
    return results


def classify_change(
    source: dict[str, Any] | None,
    destination: dict[str, Any] | None,
    match_status: str,
) -> tuple[list[str], str, list[str]]:
    """Classify a match without treating unknown dependencies as unchanged."""
    if source is None:
        return ["added"], "not_applicable", ["destination_symbol_newly_observed"]
    if destination is None:
        return (
            ["not_observed", "unknown"],
            "requires_review",
            [
                "source_symbol_not_observed_in_destination",
                "discovery_is_not_proven_complete",
            ],
        )
    if match_status != "confirmed":
        return ["unknown"], "requires_review", ["identity_not_confirmed"]
    flags: list[str] = []
    reasons: list[str] = []
    if source.get("rva") != destination.get("rva"):
        flags.append("relocated")
        reasons.append("native_location_changed")
    if source.get("name") != destination.get("name"):
        flags.append("renamed")
        reasons.append("observed_name_changed")
    source_fp = source.get("fingerprint")
    destination_fp = destination.get("fingerprint")
    if source_fp is None or destination_fp is None:
        flags.append("unknown")
        reasons.append("body_or_fingerprint_missing")
    else:
        if (
            source_fp.get("raw_body_hash") != destination_fp.get("raw_body_hash")
            or source_fp.get("strict_semantic_hash")
            != destination_fp.get("strict_semantic_hash")
            or source_fp.get("semantic_operands_hash")
            != destination_fp.get("semantic_operands_hash")
        ):
            flags.append("body_changed")
            reasons.append("strict_body_or_semantic_operand_changed")
        if source_fp.get("signature_hash") != destination_fp.get("signature_hash"):
            flags.append("signature_changed")
            reasons.append("managed_or_native_signature_changed")
        source_layout = source_fp.get("layout_hash")
        destination_layout = destination_fp.get("layout_hash")
        if source_layout is not None and destination_layout is not None:
            if source_layout != destination_layout:
                flags.append("layout_changed")
                reasons.append("type_or_field_layout_changed")
        elif source_layout != destination_layout:
            flags.append("unknown")
            reasons.append("layout_evidence_missing_for_one_build")
        if source_fp.get("call_targets_hash") != destination_fp.get(
            "call_targets_hash"
        ):
            flags.append("references_changed")
            reasons.append("call_target_dependencies_changed")
        if source_fp.get("referenced_data_hash") != destination_fp.get(
            "referenced_data_hash"
        ):
            flags.append("referenced_data_changed")
            reasons.append("referenced_data_dependencies_changed")
    flags = list(dict.fromkeys(flags))
    reasons = list(dict.fromkeys(reasons))
    if not flags:
        return [], "unchanged", []
    invalidating = {
        "body_changed",
        "layout_changed",
        "references_changed",
        "referenced_data_changed",
        "relocated",
        "signature_changed",
    }
    if invalidating.intersection(flags):
        return flags, "invalidated", reasons
    return flags, "requires_review", reasons


def build_changes(
    matches: list[dict[str, Any]],
    source: dict[str, dict[str, Any]],
    destination: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for match in matches:
        source_item = (
            source.get(str(match["source_symbol_id"]))
            if match["source_symbol_id"]
            else None
        )
        destination_item = (
            destination.get(str(match["destination_symbol_id"]))
            if match["destination_symbol_id"]
            else None
        )
        flags, invalidation, reasons = classify_change(
            source_item, destination_item, str(match["match_status"])
        )
        evidence = {
            "destination_fingerprint": (
                destination_item.get("fingerprint") if destination_item else None
            ),
            "source_fingerprint": source_item.get("fingerprint")
            if source_item
            else None,
        }
        result.append(
            {
                "change_flags": flags,
                "comparison_change_id": f"change:{digest_json([match['match_id'], flags, invalidation])}",
                "dependency_evidence": evidence,
                "destination_native_body_id": match["destination_native_body_id"],
                "destination_symbol_id": match["destination_symbol_id"],
                "invalidation_reasons": reasons,
                "invalidation_status": invalidation,
                "match_id": match["match_id"],
                "source_native_body_id": match["source_native_body_id"],
                "source_symbol_id": match["source_symbol_id"],
            }
        )
    return result


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _ndjson_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(item) for item in rows)


def _comparison_readme(summary: dict[str, Any]) -> bytes:
    counts = summary["change_flag_counts"]
    lines = [
        "# Comparaison multi-build",
        "",
        f"- Build source : `{summary['source_build_id']}`",
        f"- Build destination : `{summary['destination_build_id']}`",
        f"- Clé : `{summary['comparison_key']}`",
        f"- Appariements confirmés : {summary['match_status_counts'].get('confirmed', 0)}",
        f"- Candidats à revoir : {summary['match_status_counts'].get('candidate', 0)}",
        f"- Conflits : {summary['match_status_counts'].get('conflict', 0)}",
        f"- Invalidations : {summary['invalidation_status_counts'].get('invalidated', 0)}",
        "",
        "## Changements",
        "",
        "| Drapeau | Nombre |",
        "|---|---:|",
    ]
    for name in (
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
    ):
        lines.append(f"| `{name}` | {counts.get(name, 0)} |")
    lines.extend(
        [
            "",
            "> Les hash de corps sont stricts : aucun immédiat, offset de champ ou constante métier n'est neutralisé sans preuve de relocation. Un candidat BSim ou un hash similaire exige toujours une revue.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _symbol_page(
    change: dict[str, Any], match_by_id: dict[str, dict[str, Any]]
) -> bytes:
    match = match_by_id[str(change["match_id"])]
    flags = change["change_flags"] or ["unchanged"]
    lines = [
        "# Changement de symbole",
        "",
        f"- Symbole source : `{change['source_symbol_id']}`",
        f"- Symbole destination : `{change['destination_symbol_id']}`",
        f"- Corps source : `{change['source_native_body_id']}`",
        f"- Corps destination : `{change['destination_native_body_id']}`",
        f"- Appariement : `{match['match_method']}` / `{match['match_status']}`",
        f"- Invalidation : `{change['invalidation_status']}`",
        f"- Changements : {', '.join(f'`{item}`' for item in flags)}",
        "",
        "## Raisons",
        "",
    ]
    reasons = change["invalidation_reasons"] or [
        "Aucune dépendance observée n'a changé."
    ]
    lines.extend(f"- {reason}" for reason in reasons)
    lines.extend(
        [
            "",
            "## Limite",
            "",
            "Cette fiche décrit des preuves statiques. Elle ne certifie ni ABI runtime ni compatibilité d'un hook.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _summary(
    *,
    comparison_key: str,
    source_build_id: str,
    destination_build_id: str,
    source_snapshot_id: str,
    destination_snapshot_id: str,
    matches: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    source_fingerprints: dict[str, dict[str, Any]],
    destination_fingerprints: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    match_counts: dict[str, int] = defaultdict(int)
    invalidation_counts: dict[str, int] = defaultdict(int)
    flag_counts: dict[str, int] = defaultdict(int)
    for item in matches:
        match_counts[str(item["match_status"])] += 1
    for item in changes:
        invalidation_counts[str(item["invalidation_status"])] += 1
        for flag in item["change_flags"]:
            flag_counts[str(flag)] += 1
    return {
        "change_flag_counts": dict(sorted(flag_counts.items())),
        "comparison_key": comparison_key,
        "destination_build_id": destination_build_id,
        "destination_fingerprint_count": len(destination_fingerprints),
        "destination_snapshot_id": destination_snapshot_id,
        "fingerprint_algorithm": FINGERPRINT_ALGORITHM,
        "invalidation_status_counts": dict(sorted(invalidation_counts.items())),
        "match_count": len(matches),
        "match_status_counts": dict(sorted(match_counts.items())),
        "producer": COMPARE_PRODUCER,
        "schema_version": 1,
        "source_build_id": source_build_id,
        "source_fingerprint_count": len(source_fingerprints),
        "source_snapshot_id": source_snapshot_id,
        "uncertainties": {
            "bsim_candidates_confirm_identity": False,
            "discovery_completeness_claimed": False,
            "missing_layouts_are_unchanged": False,
            "runtime_compatibility_certified": False,
        },
    }


def _publish_comparison(
    *,
    roots: CompareRoots,
    summary: dict[str, Any],
    matches: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    source_fingerprints: dict[str, dict[str, Any]],
    destination_fingerprints: dict[str, dict[str, Any]],
) -> tuple[Path, str, bool, list[dict[str, str]]]:
    key = str(summary["comparison_key"])
    build_pair = (
        f"{str(summary['source_build_id']).removeprefix('build-')[:16]}-to-"
        f"{str(summary['destination_build_id']).removeprefix('build-')[:16]}"
    )
    relative = Path("comparisons") / build_pair / key[:19]
    destination = roots.output / relative
    if destination.is_dir():
        manifest = read_json(destination / "comparison.json")
        if manifest.get("comparison_key") != key:
            raise ValidationError(
                "Collision de sortie M3.", error_code="comparison_output_collision"
            )
        output_manifest = read_json(destination / "output-manifest.json")
        return destination, str(output_manifest["manifest_sha256"]), False, []
    staging_parent = roots.output / "comparisons" / ".staging"
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="m3-", dir=staging_parent))
    documentation: list[dict[str, str]] = []
    try:
        files: dict[str, bytes] = {
            "README.md": _comparison_readme(summary),
            "changes.csv": _csv_bytes(
                [
                    "comparison_change_id",
                    "source_build_id",
                    "destination_build_id",
                    "match_id",
                    "source_symbol_id",
                    "destination_symbol_id",
                    "source_native_body_id",
                    "destination_native_body_id",
                    "change_flags_json",
                    "invalidation_status",
                    "invalidation_reasons_json",
                ],
                [
                    {
                        **item,
                        "destination_build_id": summary["destination_build_id"],
                        "change_flags_json": json.dumps(
                            item["change_flags"], ensure_ascii=False
                        ),
                        "invalidation_reasons_json": json.dumps(
                            item["invalidation_reasons"], ensure_ascii=False
                        ),
                        "source_build_id": summary["source_build_id"],
                    }
                    for item in changes
                ],
            ),
            "changes.ndjson": _ndjson_bytes(changes),
            "comparison.json": pretty_json_bytes(summary),
            "dependency-fingerprints.ndjson": _ndjson_bytes(
                sorted(
                    [*source_fingerprints.values(), *destination_fingerprints.values()],
                    key=lambda item: (
                        str(item["build_id"]),
                        str(item["native_body_id"]),
                    ),
                )
            ),
            "invalidation.json": pretty_json_bytes(
                {
                    "invalidated": [
                        item["comparison_change_id"]
                        for item in changes
                        if item["invalidation_status"] == "invalidated"
                    ],
                    "requires_review": [
                        item["comparison_change_id"]
                        for item in changes
                        if item["invalidation_status"] == "requires_review"
                    ],
                    "schema_version": 1,
                }
            ),
            "matches.csv": _csv_bytes(
                [
                    "match_id",
                    "source_symbol_id",
                    "destination_symbol_id",
                    "source_native_body_id",
                    "destination_native_body_id",
                    "match_method",
                    "match_status",
                    "score",
                    "review_required",
                    "evidence_json",
                    "contradictions_json",
                    "alternatives_json",
                ],
                [
                    {
                        **item,
                        "alternatives_json": json.dumps(
                            item["alternatives"], ensure_ascii=False
                        ),
                        "contradictions_json": json.dumps(
                            item["contradictions"], ensure_ascii=False
                        ),
                        "evidence_json": json.dumps(
                            item["evidence"], ensure_ascii=False
                        ),
                    }
                    for item in matches
                ],
            ),
            "matches.ndjson": _ndjson_bytes(matches),
        }
        match_by_id = {str(item["match_id"]): item for item in matches}
        for item in changes:
            if item["invalidation_status"] == "unchanged":
                continue
            subject = str(item["destination_symbol_id"] or item["source_symbol_id"])
            logical = f"symbols/{_slug(subject)}.md"
            content = _symbol_page(item, match_by_id)
            files[logical] = content
            documentation.append(
                {
                    "content_sha256": sha256_bytes(content),
                    "dependency_digest": digest_json(item),
                    "relative_path": logical,
                    "subject_id": subject,
                }
            )
        digests: dict[str, str] = {}
        for logical, data in sorted(files.items()):
            path = staging.joinpath(*logical.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            digests[logical] = sha256_bytes(data)
        manifest_sha256 = digest_json(digests)
        output_manifest = {
            "files": digests,
            "manifest_sha256": manifest_sha256,
            "schema_version": 1,
        }
        (staging / "output-manifest.json").write_bytes(
            pretty_json_bytes(output_manifest)
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, destination)
        fsync_directory(destination.parent)
        atomic_write_json(
            roots.output / "comparisons" / "current.json",
            {
                "comparison": relative.as_posix(),
                "comparison_key": key,
                "destination_build_id": summary["destination_build_id"],
                "schema_version": 1,
                "source_build_id": summary["source_build_id"],
            },
        )
        return destination, manifest_sha256, True, documentation
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _persist_comparison(
    db: sqlite3.Connection,
    *,
    comparison_id: str,
    comparison_key: str,
    analysis_id: str,
    source_build_id: str,
    destination_build_id: str,
    producer_digest: str,
    annotation_digest: str,
    matches: list[dict[str, Any]],
    changes: list[dict[str, Any]],
    annotations: dict[str, Any],
) -> None:
    existing = db.execute(
        "SELECT 1 FROM build_comparisons WHERE comparison_id=?", (comparison_id,)
    ).fetchone()
    if existing:
        db.execute(
            "DELETE FROM documentation_outputs WHERE comparison_id=?", (comparison_id,)
        )
        db.execute(
            "DELETE FROM comparison_changes WHERE comparison_id=?", (comparison_id,)
        )
        db.execute("DELETE FROM match_reviews WHERE comparison_id=?", (comparison_id,))
        db.execute("DELETE FROM matches WHERE comparison_id=?", (comparison_id,))
        db.execute(
            """UPDATE build_comparisons SET analysis_id=?,status='partial',
                      output_manifest_sha256=NULL,completed_at=NULL
               WHERE comparison_id=?""",
            (analysis_id, comparison_id),
        )
    else:
        db.execute(
            """INSERT INTO build_comparisons(
                comparison_id,comparison_key,source_build_id,destination_build_id,
                analysis_id,producer_digest,annotation_digest,status,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                comparison_id,
                comparison_key,
                source_build_id,
                destination_build_id,
                analysis_id,
                producer_digest,
                annotation_digest,
                "partial",
                _utc_now(),
            ),
        )
    for item in matches:
        db.execute(
            """INSERT INTO matches(
                match_id,comparison_id,source_symbol_id,destination_symbol_id,
                source_native_body_id,destination_native_body_id,match_method,
                match_status,score,review_required,evidence_json,
                contradictions_json,alternatives_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"{comparison_id}:{item['match_id']}",
                comparison_id,
                item["source_symbol_id"],
                item["destination_symbol_id"],
                item["source_native_body_id"],
                item["destination_native_body_id"],
                item["match_method"],
                item["match_status"],
                item["score"],
                int(item["review_required"]),
                canonical_json_bytes(item["evidence"]).decode("utf-8"),
                canonical_json_bytes(item["contradictions"]).decode("utf-8"),
                canonical_json_bytes(item["alternatives"]).decode("utf-8"),
            ),
        )
    for item in changes:
        db.execute(
            """INSERT INTO comparison_changes(
                comparison_change_id,comparison_id,match_id,source_symbol_id,
                destination_symbol_id,source_native_body_id,
                destination_native_body_id,change_flags_json,
                invalidation_status,invalidation_reasons_json,
                dependency_evidence_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"{comparison_id}:{item['comparison_change_id']}",
                comparison_id,
                f"{comparison_id}:{item['match_id']}",
                item["source_symbol_id"],
                item["destination_symbol_id"],
                item["source_native_body_id"],
                item["destination_native_body_id"],
                canonical_json_bytes(item["change_flags"]).decode("utf-8"),
                item["invalidation_status"],
                canonical_json_bytes(item["invalidation_reasons"]).decode("utf-8"),
                canonical_json_bytes(item["dependency_evidence"]).decode("utf-8"),
            ),
        )
    for item in annotations.get("reviews", []):
        source_id = str(item["source_symbol_id"])
        destination_id = str(item["destination_symbol_id"])
        db.execute(
            """INSERT INTO match_reviews(
                match_review_id,comparison_id,source_symbol_id,
                destination_symbol_id,decision,reason,reviewer,
                evidence_refs_json,annotation_digest
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                f"match-review:{digest_json([comparison_id, source_id, destination_id, item])}",
                comparison_id,
                source_id,
                destination_id,
                item["decision"],
                str(item.get("reason", "")),
                str(item.get("reviewer", "unknown")),
                canonical_json_bytes(item.get("evidence_refs", [])).decode("utf-8"),
                annotation_digest,
            ),
        )
    for annotation_kind, items, subject_kind in (
        ("bsim_candidate", annotations.get("bsim_candidates", []), "symbol_match"),
        ("layout_hash", annotations.get("layouts", []), "native_body"),
    ):
        for item in items:
            subject_id = str(
                item.get("native_body_id") or item.get("source_symbol_id") or "invalid"
            )
            applicability = {
                key: item[key]
                for key in ("build_id", "destination_symbol_id")
                if item.get(key) is not None
            }
            value = {
                key: value
                for key, value in item.items()
                if key not in {"evidence_refs", "reviewer"}
            }
            item_digest = digest_json(item)
            db.execute(
                """INSERT OR IGNORE INTO annotations(
                    annotation_id,subject_kind,subject_id,annotation_kind,
                    applicability_json,value_json,evidence_refs_json,author,
                    annotation_digest,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"annotation:{item_digest}",
                    subject_kind,
                    subject_id,
                    annotation_kind,
                    canonical_json_bytes(applicability).decode("utf-8"),
                    canonical_json_bytes(value).decode("utf-8"),
                    canonical_json_bytes(item.get("evidence_refs", [])).decode("utf-8"),
                    str(item.get("reviewer", "profile")),
                    item_digest,
                    _utc_now(),
                ),
            )


def compare_builds(
    *,
    roots: CompareRoots,
    source_snapshot_id: str,
    destination_snapshot_id: str,
    input_profile: LoadedYaml,
    policy: LoadedYaml,
    annotations: LoadedYaml,
    migrations_root: Path,
    enforce_read_only_inputs: bool,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    assert_no_live_source_environment()
    if enforce_read_only_inputs:
        assert_inputs_read_only(roots.inputs)
    if source_snapshot_id == destination_snapshot_id:
        raise ValidationError(
            "La comparaison exige deux snapshots distincts.",
            error_code="comparison_same_snapshot",
        )
    source_manifest, source_manifest_sha256 = _load_snapshot(
        roots, source_snapshot_id, input_profile
    )
    destination_manifest, destination_manifest_sha256 = _load_snapshot(
        roots, destination_snapshot_id, input_profile
    )
    annotation_data = _validate_annotations(annotations)
    producer_digest = _producer_digest()
    run_id = workflow_run_id or f"run-m3-{uuid.uuid4()}"
    analysis_id = f"run:{run_id}"
    report = RunReport(run_id, "build-comparison")
    report.snapshot_id = destination_snapshot_id
    destination: Path | None = None
    comparison_key = ""
    comparison_id = ""
    published = False
    summary: dict[str, Any] = {}
    with (
        registry_writer_lock(roots.state),
        Registry(roots.state / "registry.sqlite", migrations_root) as registry,
    ):
        db = registry.db
        db.execute("BEGIN IMMEDIATE")
        try:
            _register_snapshot(
                registry, source_manifest, source_manifest_sha256, run_id
            )
            _register_snapshot(
                registry, destination_manifest, destination_manifest_sha256, run_id
            )
            preliminary_key = f"m3-{digest_json([source_snapshot_id, destination_snapshot_id, producer_digest, annotations.sha256])}"
            db.execute(
                """INSERT INTO analysis_runs(
                    analysis_id,workflow_run_id,snapshot_id,analysis_key,status,started_at
                ) VALUES(?,?,?,?,?,?)""",
                (
                    analysis_id,
                    run_id,
                    destination_snapshot_id,
                    preliminary_key,
                    "running",
                    report.started_at,
                ),
            )
            with report.step(
                "comparison.materialize",
                "materialize_native_observations",
                category="analysis",
                cache_status="hit",
                tool_name="modkit.native",
                tool_version="0.2.0",
            ) as step:
                source_materialization = _materialize_cached_build(
                    db=db,
                    roots=roots,
                    manifest=source_manifest,
                    policy=policy,
                    analysis_id=analysis_id,
                )
                destination_materialization = _materialize_cached_build(
                    db=db,
                    roots=roots,
                    manifest=destination_manifest,
                    policy=policy,
                    analysis_id=analysis_id,
                )
                step.input_item_count = 8
                step.output_item_count = (
                    source_materialization["cache_materialized"]
                    + destination_materialization["cache_materialized"]
                )
                step.reason = "exact_completed_m2_bundles_only"
            with report.step(
                "comparison.fingerprints",
                "dependency_fingerprints",
                category="analysis",
                tool_name="modkit.compare",
                tool_version=COMPARE_PRODUCER["version"],
            ) as step:
                source_fingerprints = build_dependency_fingerprints(
                    db,
                    build_id=str(source_manifest["build_id"]),
                    annotations=annotation_data,
                )
                destination_fingerprints = build_dependency_fingerprints(
                    db,
                    build_id=str(destination_manifest["build_id"]),
                    annotations=annotation_data,
                )
                fingerprint_basis = {
                    "destination": sorted(
                        (
                            body_id,
                            digest_json(item),
                        )
                        for body_id, item in destination_fingerprints.items()
                    ),
                    "source": sorted(
                        (body_id, digest_json(item))
                        for body_id, item in source_fingerprints.items()
                    ),
                }
                comparison_key = f"m3-{digest_json({'annotations': annotations.sha256, 'fingerprints': fingerprint_basis, 'producer': producer_digest, 'source_build_id': source_manifest['build_id'], 'destination_build_id': destination_manifest['build_id']})}"
                comparison_id = f"comparison:{comparison_key}"
                step.input_item_count = len(source_fingerprints) + len(
                    destination_fingerprints
                )
                step.output_item_count = step.input_item_count
            db.execute(
                "UPDATE analysis_runs SET analysis_key=? WHERE analysis_id=?",
                (comparison_key, analysis_id),
            )
            build_pair = (
                f"{str(source_manifest['build_id']).removeprefix('build-')[:16]}-to-"
                f"{str(destination_manifest['build_id']).removeprefix('build-')[:16]}"
            )
            relative = Path("comparisons") / build_pair / comparison_key[:19]
            existing = db.execute(
                """SELECT comparison_id,output_manifest_sha256,status
                   FROM build_comparisons WHERE comparison_key=?""",
                (comparison_key,),
            ).fetchone()
            if (
                existing is not None
                and existing[2] == "completed"
                and (roots.output / relative / "output-manifest.json").is_file()
                and read_json(roots.output / relative / "output-manifest.json").get(
                    "manifest_sha256"
                )
                == existing[1]
            ):
                destination = roots.output / relative
                comparison_id = str(existing[0])
                summary = read_json(destination / "comparison.json")
                report.add_step(
                    "comparison.matching",
                    "symbol_matching",
                    category="analysis",
                    status="cache_hit",
                    reason="complete_comparison_key_match",
                    cache_status="hit",
                    tool_name="modkit.compare",
                    tool_version=COMPARE_PRODUCER["version"],
                    input_item_count=len(source_fingerprints)
                    + len(destination_fingerprints),
                    output_item_count=int(summary["match_count"]),
                )
                report.add_step(
                    "comparison.documentation",
                    "incremental_documentation",
                    category="publication",
                    status="cache_hit",
                    reason="content_identical_no_rewrite",
                    cache_status="hit",
                    tool_name="modkit.compare",
                    tool_version=COMPARE_PRODUCER["version"],
                )
            else:
                _store_fingerprints(db, source_fingerprints)
                _store_fingerprints(db, destination_fingerprints)
                with report.step(
                    "comparison.matching",
                    "symbol_matching",
                    category="analysis",
                    cache_status="miss",
                    tool_name="modkit.compare",
                    tool_version=COMPARE_PRODUCER["version"],
                ) as step:
                    source_symbols = _symbol_records(
                        db,
                        build_id=str(source_manifest["build_id"]),
                        fingerprints=source_fingerprints,
                    )
                    destination_symbols = _symbol_records(
                        db,
                        build_id=str(destination_manifest["build_id"]),
                        fingerprints=destination_fingerprints,
                    )
                    matches = match_symbols(
                        source_symbols, destination_symbols, annotation_data
                    )
                    changes = build_changes(
                        matches, source_symbols, destination_symbols
                    )
                    step.input_item_count = len(source_symbols) + len(
                        destination_symbols
                    )
                    step.output_item_count = len(matches)
                summary = _summary(
                    comparison_key=comparison_key,
                    source_build_id=str(source_manifest["build_id"]),
                    destination_build_id=str(destination_manifest["build_id"]),
                    source_snapshot_id=source_snapshot_id,
                    destination_snapshot_id=destination_snapshot_id,
                    matches=matches,
                    changes=changes,
                    source_fingerprints=source_fingerprints,
                    destination_fingerprints=destination_fingerprints,
                )
                _persist_comparison(
                    db,
                    comparison_id=comparison_id,
                    comparison_key=comparison_key,
                    analysis_id=analysis_id,
                    source_build_id=str(source_manifest["build_id"]),
                    destination_build_id=str(destination_manifest["build_id"]),
                    producer_digest=producer_digest,
                    annotation_digest=annotations.sha256,
                    matches=matches,
                    changes=changes,
                    annotations=annotation_data,
                )
                with report.step(
                    "comparison.documentation",
                    "incremental_documentation",
                    category="publication",
                    cache_status="miss",
                    tool_name="modkit.compare",
                    tool_version=COMPARE_PRODUCER["version"],
                ) as step:
                    destination, output_manifest_sha256, published, documentation = (
                        _publish_comparison(
                            roots=roots,
                            summary=summary,
                            matches=matches,
                            changes=changes,
                            source_fingerprints=source_fingerprints,
                            destination_fingerprints=destination_fingerprints,
                        )
                    )
                    step.status = "completed" if published else "cache_hit"
                    step.cache_status = "miss" if published else "hit"
                    step.output_item_count = len(documentation) + 8
                for item in documentation:
                    db.execute(
                        """INSERT INTO documentation_outputs(
                            documentation_output_id,comparison_id,subject_id,
                            dependency_digest,content_sha256,relative_path
                        ) VALUES(?,?,?,?,?,?)""",
                        (
                            f"documentation:{digest_json([comparison_id, item['subject_id'], item['relative_path']])}",
                            comparison_id,
                            item["subject_id"],
                            item["dependency_digest"],
                            item["content_sha256"],
                            item["relative_path"],
                        ),
                    )
                db.execute(
                    """UPDATE build_comparisons
                       SET status='completed',output_manifest_sha256=?,completed_at=?
                       WHERE comparison_id=?""",
                    (output_manifest_sha256, _utc_now(), comparison_id),
                )
            report.metadata.update(
                {
                    "comparison_id": comparison_id,
                    "comparison_key": comparison_key,
                    "destination_build_id": destination_manifest["build_id"],
                    "migrations_applied": registry.applied_migrations,
                    "published": published,
                    "source_build_id": source_manifest["build_id"],
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
    if destination is None:
        raise RuntimeError("Comparison output was not resolved")
    return {
        "cache_status": "miss" if published else "hit",
        "comparison_id": comparison_id,
        "comparison_key": comparison_key,
        "destination_build_id": destination_manifest["build_id"],
        "output": destination.relative_to(roots.output).as_posix(),
        "report": f"reports/{run_id}/run-report.json",
        "source_build_id": source_manifest["build_id"],
        "summary": {
            "change_flag_counts": summary["change_flag_counts"],
            "invalidation_status_counts": summary["invalidation_status_counts"],
            "match_count": summary["match_count"],
            "match_status_counts": summary["match_status_counts"],
        },
    }
