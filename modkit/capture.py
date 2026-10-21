from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from typing import Any

from .errors import CaptureError, ValidationError
from .handoff import publish_handoff
from .planner import CapturePlan, PlannedPayload, SourceStat
from .reporting import RunReport
from .util import (
    atomic_write_json,
    digest_json,
    materialize_object,
    object_path,
    pretty_json_bytes,
    publish_cas_staging,
    read_json,
    sha256_bytes,
    sha256_file,
    stream_hash,
)

CAPTURE_PRODUCER = {"name": "modkit.capture", "version": "0.1.0"}


def _load_previous_payloads(inputs_root: Path) -> dict[str, dict[str, Any]]:
    pointer = inputs_root / "current.json"
    if not pointer.is_file():
        return {}
    try:
        report_path = inputs_root / str(read_json(pointer)["capture_report"])
        value = read_json(report_path)
        source_index = value.get("metadata", {}).get("source_index", [])
        return {str(item["logical_path"]): item for item in source_index}
    except (OSError, KeyError, TypeError, ValueError):
        return {}


def _stat_equal(left: SourceStat, right: SourceStat) -> bool:
    return left.stable_tuple() == right.stable_tuple()


def _hash_one_pass(
    payload: PlannedPayload, staging_root: Path, *, stage: bool
) -> tuple[str, int, Path | None, int, int, SourceStat]:
    """Hash with pre/post stat checks, retrying once only on a concurrent change."""
    expected_stat = payload.stat
    total_bytes_read = 0
    for attempt in (1, 2):
        before = SourceStat.from_path(payload.source_path)
        if not _stat_equal(before, expected_stat):
            raise CaptureError(
                f"Entrée modifiée après la planification : {payload.logical_path}",
                error_code="input_changed_since_plan",
            )
        staging: Path | None = None
        try:
            if stage:
                staging_root.mkdir(parents=True, exist_ok=True)
                descriptor, name = tempfile.mkstemp(
                    prefix="payload-", suffix=".part", dir=staging_root
                )
                staging = Path(name)
                with (
                    payload.source_path.open("rb") as source,
                    os.fdopen(descriptor, "wb") as destination,
                ):
                    digest, size = stream_hash(source, destination)
            else:
                with payload.source_path.open("rb") as source:
                    digest, size = stream_hash(source)
            after = SourceStat.from_path(payload.source_path)
            total_bytes_read += size
            if size != before.size_bytes or not _stat_equal(before, after):
                staging and staging.unlink(missing_ok=True)
                if attempt == 1:
                    expected_stat = after
                    continue
                raise CaptureError(
                    f"Entrée modifiée pendant deux lectures : {payload.logical_path}",
                    error_code="input_changed_during_capture",
                )
            return digest, size, staging, attempt, total_bytes_read, after
        except BaseException:
            if staging is not None:
                staging.unlink(missing_ok=True)
            raise
    raise AssertionError("unreachable")


def _capture_payload(
    payload: PlannedPayload,
    inputs_root: Path,
    previous: dict[str, Any] | None,
) -> tuple[dict[str, Any], bool, int, SourceStat, int]:
    prior_same_metadata = bool(
        previous
        and previous.get("size_bytes") == payload.stat.size_bytes
        and previous.get("source_mtime_ns") == payload.stat.mtime_ns
        and isinstance(previous.get("sha256"), str)
    )
    staging_root = inputs_root / "staging"
    digest, size, staging, attempts, bytes_read, final_stat = _hash_one_pass(
        payload, staging_root, stage=not prior_same_metadata
    )
    destination = object_path(inputs_root, digest)
    created = False
    if staging is None:
        if previous and digest == previous.get("sha256") and destination.is_file():
            pass
        else:
            # Strictly detect A04: if content changed while size/mtime stayed equal,
            # take one verified staging read so the new object can be published.
            (
                digest_second,
                size_second,
                staging,
                retry_attempts,
                retry_bytes,
                final_stat,
            ) = _hash_one_pass(payload, staging_root, stage=True)
            attempts += retry_attempts
            bytes_read += retry_bytes
            if digest_second != digest or size_second != size:
                staging.unlink(missing_ok=True)
                raise CaptureError(
                    f"Contenu instable sans changement de métadonnées : {payload.logical_path}",
                    error_code="content_drift_during_capture",
                )
            destination = object_path(inputs_root, digest)

    if staging is not None:
        created = publish_cas_staging(staging, destination)
    if not destination.is_file() or destination.stat().st_size != size:
        raise CaptureError(
            f"Objet CAS absent ou de taille invalide : {digest}",
            error_code="cas_publication_failed",
        )

    return (
        {
            "feature": payload.feature,
            "identity_contribution": payload.identity_contribution,
            "logical_path": payload.logical_path,
            "object_id": f"sha256:{digest}",
            "presence": "present",
            "required": payload.required,
            "roles": sorted(set(payload.roles)),
            "rule_id": payload.rule_id,
            "sha256": digest,
            "size_bytes": size,
            "source_kind": payload.source_kind,
        },
        created,
        bytes_read,
        final_stat,
        attempts,
    )


def _identity_basis(
    plan: CapturePlan, payloads: list[dict[str, Any]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    common = {
        "payloads": [
            {
                "identity_contribution": item["identity_contribution"],
                "logical_path": item["logical_path"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
            }
            for item in sorted(
                payloads, key=lambda value: value["logical_path"].casefold()
            )
        ],
        "schema_version": 2,
        "selection_id": plan.selection_id,
        "selection_sha256": plan.selection_sha256,
    }
    build = {
        **common,
        "payloads": [
            item
            for item in common["payloads"]
            if item["identity_contribution"] == "build_content"
        ],
    }
    return common, build


def publish_snapshot(
    plan: CapturePlan,
    inputs_root: Path,
    *,
    workflow_run_id: str,
    handoff_root: Path | None = None,
    handoff_slot: str | None = None,
    report: RunReport | None = None,
) -> dict[str, Any]:
    """Capture a precomputed plan; this function never inventories the source again."""
    report = report or RunReport(workflow_run_id, "capture")
    previous = _load_previous_payloads(inputs_root)
    captured: list[dict[str, Any]] = []
    captured_stats: list[SourceStat] = []
    captured_attempts: list[int] = []
    objects_created = 0
    objects_reused = 0
    bytes_read = 0
    bytes_created = 0

    with report.step(
        "capture.payloads", "capture", category="capture", parent_step_id=None
    ) as step:
        step.input_item_count = len(plan.payloads)
        step.input_bytes = plan.estimated_bytes
        for payload in plan.payloads:
            (
                observation,
                created,
                payload_bytes_read,
                final_stat,
                read_attempts,
            ) = _capture_payload(
                payload, inputs_root, previous.get(payload.logical_path)
            )
            captured.append(observation)
            captured_stats.append(final_stat)
            captured_attempts.append(read_attempts)
            bytes_read += payload_bytes_read
            if created:
                objects_created += 1
                bytes_created += observation["size_bytes"]
            else:
                objects_reused += 1
        step.input_bytes = bytes_read
        step.output_item_count = objects_created
        step.output_bytes = bytes_created

    snapshot_basis, build_basis = _identity_basis(plan, captured)
    snapshot_id = f"snapshot-{digest_json(snapshot_basis)}"
    build_id = f"build-{digest_json(build_basis)}"
    manifest = {
        "absences": sorted(
            plan.absences, key=lambda item: str(item.get("logical_path", "")).casefold()
        ),
        "atomic_publication": {"method": "staging_then_rename", "published": True},
        "build_id": build_id,
        "coherence": plan.coherence,
        "features": sorted(plan.features),
        "inventory": sorted(
            (
                {key: value for key, value in item.items() if key != "mtime_ns"}
                for item in plan.inventory
            ),
            key=lambda item: str(item.get("logical_path", "")).casefold(),
        ),
        "payloads": sorted(captured, key=lambda item: item["logical_path"].casefold()),
        "plan_id": plan.plan_id,
        "producer": CAPTURE_PRODUCER,
        "schema_version": 2,
        "selection_id": plan.selection_id,
        "selection_sha256": plan.selection_sha256,
        "snapshot_id": snapshot_id,
        "totals": {
            "inventory_observations": len(plan.inventory),
            "payload_bytes": sum(item["size_bytes"] for item in captured),
            "payloads": len(captured),
        },
    }
    manifest_bytes = pretty_json_bytes(manifest)
    manifest_sha256 = sha256_bytes(manifest_bytes)
    snapshot_root = inputs_root / "snapshots" / snapshot_id

    with report.step(
        "capture.publish_snapshot",
        "publish_snapshot",
        category="publication",
        parent_step_id=None,
    ) as step:
        existing_manifest = snapshot_root / "capture-manifest.json"
        if existing_manifest.is_file():
            existing_digest, _ = sha256_file(existing_manifest)
            if existing_digest != manifest_sha256:
                raise CaptureError(
                    f"Collision d'identité de snapshot : {snapshot_id}",
                    error_code="snapshot_identity_collision",
                )
            step.status = "cache_hit"
            step.cache_status = "hit"
            step.reason = "snapshot_identical_already_published"
        else:
            staging_snapshot = inputs_root / "staging" / f"snapshot-{uuid.uuid4().hex}"
            files_root = staging_snapshot / "files"
            for item in captured:
                materialize_object(
                    object_path(inputs_root, item["sha256"]),
                    files_root.joinpath(*item["logical_path"].split("/")),
                )
            atomic_write_json(staging_snapshot / "capture-manifest.json", manifest)
            snapshot_root.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(staging_snapshot, snapshot_root)
            except FileExistsError:
                # Another writer published the exact immutable snapshot first.
                if (
                    not existing_manifest.is_file()
                    or sha256_file(existing_manifest)[0] != manifest_sha256
                ):
                    raise CaptureError(
                        "Publication concurrente incohérente.",
                        error_code="snapshot_publish_race",
                    )
            step.output_item_count = len(captured) + 1
            step.output_bytes = len(manifest_bytes)
        atomic_write_json(
            inputs_root / "current.json",
            {
                "capture_report": f"run-reports/{workflow_run_id}.json",
                "manifest_sha256": manifest_sha256,
                "schema_version": 1,
                "snapshot_id": snapshot_id,
            },
        )

    report.snapshot_id = snapshot_id
    report.metadata.update(
        {
            "build_id": build_id,
            "bytes_read": bytes_read,
            "objects_created": objects_created,
            "objects_reused": objects_reused,
            "plan_id": plan.plan_id,
            "selection_id": plan.selection_id,
            "snapshot_manifest_sha256": manifest_sha256,
            "source_index": [
                {
                    "logical_path": item.logical_path,
                    "sha256": captured[index]["sha256"],
                    "size_bytes": captured_stats[index].size_bytes,
                    "source_mtime_ns": captured_stats[index].mtime_ns,
                }
                for index, item in enumerate(plan.payloads)
            ],
            "same_metadata_content_drifts": sum(
                1
                for index, payload in enumerate(plan.payloads)
                if previous.get(payload.logical_path)
                and previous[payload.logical_path].get("size_bytes")
                == payload.stat.size_bytes
                and previous[payload.logical_path].get("source_mtime_ns")
                == payload.stat.mtime_ns
                and captured_stats[index].size_bytes == payload.stat.size_bytes
                and captured_stats[index].mtime_ns == payload.stat.mtime_ns
                and previous[payload.logical_path].get("sha256")
                != captured[index]["sha256"]
            ),
            "payload_read_attempts": sum(captured_attempts),
            "retried_payloads": sum(
                1 for attempts in captured_attempts if attempts > 1
            ),
        }
    )

    if handoff_root is not None and handoff_slot is not None:
        handoff_record = {
            "capture_report": f"run-reports/{workflow_run_id}.json",
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "snapshot_manifest_sha256": manifest_sha256,
            "workflow_run_id": workflow_run_id,
        }
        # Finish and publish the capture report before exposing the handoff.
        report.finish("completed")
        atomic_write_json(
            inputs_root / "run-reports" / f"{workflow_run_id}.json", report.public()
        )
        publish_handoff(handoff_root, handoff_slot, handoff_record)
    else:
        report.finish("completed")
        atomic_write_json(
            inputs_root / "run-reports" / f"{workflow_run_id}.json", report.public()
        )
    return {
        "build_id": build_id,
        "manifest_sha256": manifest_sha256,
        "snapshot_id": snapshot_id,
        "workflow_run_id": workflow_run_id,
    }


def verify_snapshot(
    inputs_root: Path, snapshot_id: str, *, full_hash: bool = False
) -> dict[str, Any]:
    snapshot_root = inputs_root / "snapshots" / snapshot_id
    manifest_path = snapshot_root / "capture-manifest.json"
    if not manifest_path.is_file():
        raise ValidationError(
            f"Snapshot absent : {snapshot_id}", error_code="snapshot_missing"
        )
    manifest = read_json(manifest_path)
    if manifest.get("snapshot_id") != snapshot_id:
        raise ValidationError(
            "L'identité interne du snapshot ne correspond pas au chemin.",
            error_code="snapshot_id_mismatch",
        )
    checked = 0
    checked_bytes = 0
    for item in manifest.get("payloads", []):
        logical = str(item["logical_path"])
        digest = str(item["sha256"])
        expected_size = int(item["size_bytes"])
        obj = object_path(inputs_root, digest)
        materialized = snapshot_root / "files" / Path(*logical.split("/"))
        for candidate in (obj, materialized):
            if not candidate.is_file() or candidate.stat().st_size != expected_size:
                raise ValidationError(
                    f"Payload absent ou tronqué : {logical}",
                    error_code="snapshot_payload_missing",
                )
        if full_hash:
            observed, size = sha256_file(obj)
            if observed != digest or size != expected_size:
                raise ValidationError(
                    f"Hash CAS invalide : {logical}",
                    error_code="snapshot_hash_mismatch",
                )
            checked_bytes += size
        checked += 1
    return {
        "full_hash": full_hash,
        "payloads_checked": checked,
        "bytes_hashed": checked_bytes,
        "snapshot_id": snapshot_id,
        "status": "valid",
    }
