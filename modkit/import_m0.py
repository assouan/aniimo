from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .capture import publish_snapshot
from .config import LoadedYaml, enabled_features
from .errors import ValidationError
from .planner import CapturePlan, PlannedPayload, SourceStat
from .reporting import RunReport
from .util import atomic_write_json, digest_json, read_json, sha256_file


def import_m0_bundle(
    *,
    bundle_root: Path,
    inputs_root: Path,
    handoff_root: Path,
    slot: str,
    input_profile: LoadedYaml,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    """Validate and reimport an M0 acquisition; never relabel its schema in place."""
    source_manifest_path = bundle_root / "snapshot" / "capture-manifest.json"
    source_files = bundle_root / "snapshot" / "files"
    if not source_manifest_path.is_file() or not source_files.is_dir():
        raise ValidationError("Bundle M0 incomplet.", error_code="m0_bundle_incomplete")
    source = read_json(source_manifest_path)
    if (
        source.get("schema_version") != 1
        or source.get("bundle_kind") != "m0_acquisition"
    ):
        raise ValidationError(
            "Le bundle source n’est pas un contrat M0 reconnu.",
            error_code="m0_bundle_schema",
        )
    if source.get("selection_id") != input_profile.data.get("selection_id"):
        raise ValidationError(
            "selection_id du bundle M0 incompatible.",
            error_code="m0_selection_mismatch",
        )
    if source.get("allowlist_sha256") != input_profile.sha256:
        raise ValidationError(
            "Digest d’allowlist du bundle M0 incompatible.",
            error_code="m0_allowlist_mismatch",
        )

    payloads: list[PlannedPayload] = []
    verified_bytes = 0
    for item in source.get("payloads", []):
        logical = str(item["logical_path"])
        path = source_files.joinpath(*logical.split("/"))
        observed, size = sha256_file(path)
        if observed != item.get("sha256") or size != item.get("size_bytes"):
            raise ValidationError(
                f"Payload M0 invalide : {logical}",
                error_code="m0_payload_hash_mismatch",
            )
        verified_bytes += size
        payloads.append(
            PlannedPayload(
                logical_path=logical,
                source_path=path,
                source_kind="external"
                if logical.startswith("distribution/")
                else "m0_import",
                rule_id=str(item["rule_id"]),
                feature=str(item["feature"]),
                required=bool(item.get("required", False)),
                roles=list(item.get("roles", [])),
                identity_contribution=str(
                    item.get("identity_contribution", "build_content")
                ),
                stat=SourceStat.from_path(path),
            )
        )
    public_basis = {
        "absences": source.get("absences", []),
        "coherence": source.get("coherence", []),
        "features": source.get("features", enabled_features(input_profile)),
        "inventory": source.get("inventory", []),
        "payloads": [
            {
                "feature": item.feature,
                "logical_path": item.logical_path,
                "rule_id": item.rule_id,
                "size_bytes": item.stat.size_bytes,
            }
            for item in payloads
        ],
        "schema_version": 1,
        "selection_id": source["selection_id"],
        "selection_sha256": source["allowlist_sha256"],
    }
    plan = CapturePlan(
        schema_version=1,
        selection_id=source["selection_id"],
        selection_sha256=source["allowlist_sha256"],
        features=list(source.get("features", enabled_features(input_profile))),
        payloads=payloads,
        absences=list(source.get("absences", [])),
        inventory=list(source.get("inventory", [])),
        coherence=list(source.get("coherence", [])),
        estimated_bytes=sum(item.stat.size_bytes for item in payloads),
        plan_id=f"plan-{digest_json(public_basis)}",
    )
    run_id = workflow_run_id or f"run-{uuid.uuid4()}"
    report = RunReport(run_id, "capture")
    report.metadata.update(
        {
            "import_contract": "m0_to_m1_v1",
            "m0_capture_id": source.get("capture_id"),
            "m0_manifest_sha256": sha256_file(source_manifest_path)[0],
            "verified_source_bytes": verified_bytes,
        }
    )
    result = publish_snapshot(
        plan,
        inputs_root,
        workflow_run_id=run_id,
        handoff_root=handoff_root,
        handoff_slot=slot,
        report=report,
    )
    receipt = {
        "m0_capture_id": source.get("capture_id"),
        "m0_manifest_sha256": sha256_file(source_manifest_path)[0],
        "m1_snapshot_id": result["snapshot_id"],
        "schema_version": 1,
        "verified_payload_bytes": verified_bytes,
        "verified_payloads": len(payloads),
        "workflow_run_id": run_id,
    }
    atomic_write_json(
        inputs_root / "imports" / result["snapshot_id"] / f"{run_id}.json", receipt
    )
    return {**result, "import_receipt": receipt}
