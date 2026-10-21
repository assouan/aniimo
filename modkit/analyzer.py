from __future__ import annotations

import fnmatch
import json
import os
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capture import verify_snapshot
from .config import LoadedYaml
from .doctor import quick_preflight, stable_doctor
from .errors import ValidationError
from .handoff import claim_handoff
from .registry import Registry, registry_writer_lock
from .reporting import RunReport, merge_reports, publish_report
from .util import (
    atomic_write_bytes,
    atomic_write_json,
    digest_json,
    object_path,
    pretty_json_bytes,
    publish_cas_staging,
    read_json,
    sha256_bytes,
    sha256_file,
)

ANALYZER_PRODUCER = {"name": "modkit.analyzer", "version": "0.1.0"}
ToolInvoker = Callable[[str, str], None]


@dataclass(frozen=True)
class AnalyzerRoots:
    inputs: Path
    handoff: Path
    state: Path
    artifacts: Path
    cache: Path
    work: Path
    output: Path


def _producer_digest() -> str:
    package_root = Path(__file__).parent
    return digest_json(
        {
            path.name: sha256_file(path)[0]
            for path in sorted(package_root.glob("*.py"), key=lambda item: item.name)
        }
    )


def assert_inputs_read_only(inputs_root: Path) -> None:
    probe = inputs_root / f".modkit-write-probe-{uuid.uuid4().hex}"
    try:
        descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return
    else:
        os.close(descriptor)
        probe.unlink(missing_ok=True)
    raise ValidationError(
        "La racine /inputs de l’analyseur est inscriptible.",
        error_code="inputs_not_read_only",
    )


def assert_no_live_source_environment() -> None:
    forbidden = [
        name for name in ("GAME_DIR", "STEAM_APP_MANIFEST") if os.environ.get(name)
    ]
    if forbidden:
        raise ValidationError(
            f"Variables de source live visibles par l’analyseur : {', '.join(forbidden)}",
            error_code="live_source_boundary_violation",
        )


def _validate_handoff(
    record: dict[str, Any], inputs_root: Path, input_profile: LoadedYaml
) -> tuple[dict[str, Any], Path]:
    required = {
        "schema_version",
        "workflow_run_id",
        "snapshot_id",
        "snapshot_manifest_sha256",
    }
    if not required.issubset(record):
        raise ValidationError("Remise incomplète.", error_code="handoff_incomplete")
    if record.get("schema_version") != 1:
        raise ValidationError(
            "Version de remise non prise en charge.",
            error_code="handoff_schema_unsupported",
        )
    snapshot_id = str(record["snapshot_id"])
    manifest_path = inputs_root / "snapshots" / snapshot_id / "capture-manifest.json"
    if not manifest_path.is_file():
        raise ValidationError(
            "Snapshot remis absent.", error_code="handoff_snapshot_missing"
        )
    digest, _ = sha256_file(manifest_path)
    if digest != record["snapshot_manifest_sha256"]:
        raise ValidationError(
            "Digest du manifeste remis invalide.",
            error_code="handoff_manifest_digest_mismatch",
        )
    manifest = read_json(manifest_path)
    if manifest.get("snapshot_id") != snapshot_id:
        raise ValidationError(
            "Snapshot remis incohérent.", error_code="handoff_snapshot_id_mismatch"
        )
    if manifest.get("selection_id") != input_profile.data.get("selection_id"):
        raise ValidationError(
            "Selection ID du snapshot incompatible.", error_code="selection_id_mismatch"
        )
    if manifest.get("selection_sha256") != input_profile.sha256:
        raise ValidationError(
            "Digest de l’allowlist incompatible.",
            error_code="selection_digest_mismatch",
        )
    verify_snapshot(inputs_root, snapshot_id, full_hash=False)
    return manifest, manifest_path


def _scope_decisions(
    manifest: dict[str, Any], policy: LoadedYaml
) -> list[dict[str, Any]]:
    data = policy.data
    approved = {
        Path(value).name.casefold()
        for value in data.get("approved", {}).get("game_decompile", [])
    }
    full = {
        Path(value).name.casefold()
        for value in data.get("approved", {}).get("full_module_decompile", [])
    }
    reference_patterns = list(
        data.get("classification_hints", {}).get("likely_reference_only_names", [])
    )
    excluded_patterns = list(
        data.get("classification_hints", {}).get("likely_excluded_names", [])
    )
    decisions: list[dict[str, Any]] = []
    for item in manifest.get("payloads", []):
        path = str(item["logical_path"])
        name = Path(path).name
        roles = set(item.get("roles", []))
        evidence = [f"snapshot:/{path}", f"capture-rule:{item.get('rule_id')}"]
        if name.casefold() in approved:
            decision = "game_decompile"
            reason = "explicit_approved_module"
            scope = "full_module" if name.casefold() in full else "selected_symbols"
        elif any(
            fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
            for pattern in excluded_patterns
        ):
            decision = "excluded"
            reason = "explicit_category_hint"
            scope = "none"
        elif any(
            fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
            for pattern in reference_patterns
        ):
            decision = "reference_only"
            reason = "known_external_reference"
            scope = "signatures_and_references"
        elif roles.intersection(
            {
                "native_analysis_candidate",
                "game_integration_candidate",
                "generated_game_code_candidate",
                "launcher",
                "pe_identity",
            }
        ):
            decision = "needs_review"
            reason = "filename_or_role_is_not_ownership_proof"
            scope = "discovery_only"
        else:
            decision = "reference_only"
            reason = "captured_evidence_not_implementation_target"
            scope = "evidence_only"
        decisions.append(
            {
                "decision": decision,
                "evidence_refs": evidence,
                "logical_path": path,
                "reason": reason,
                "scope": scope,
                "subject_id": f"component:{path}",
                "subject_kind": "component",
            }
        )
    return sorted(decisions, key=lambda item: item["logical_path"].casefold())


def build_analysis_plan(
    manifest: dict[str, Any],
    profile: LoadedYaml,
    policy: LoadedYaml,
    tools_lock: dict[str, Any],
) -> dict[str, Any]:
    if policy.data.get("input_selection_id") != manifest.get("selection_id"):
        raise ValidationError(
            "Politique de décompilation liée à une autre sélection.",
            error_code="policy_selection_mismatch",
        )
    decisions = _scope_decisions(manifest, policy)
    approved = [item for item in decisions if item["decision"] == "game_decompile"]
    stages = [
        {"enabled": True, "name": "scope", "targets": len(decisions)},
        {
            "enabled": profile.data.get("analysis", {}).get("ghidra") == "enabled",
            "execution": "m1_adapter_contract_only",
            "name": "ghidra",
            "targets": [item["logical_path"] for item in approved],
        },
        {
            "enabled": profile.data.get("analysis", {}).get("bsim") == "enabled",
            "execution": "m1_adapter_contract_only",
            "name": "bsim",
            "targets": [item["logical_path"] for item in approved],
        },
    ]
    basis = {
        "policy_sha256": policy.sha256,
        "producer_digest": _producer_digest(),
        "profile_sha256": profile.sha256,
        "snapshot_id": manifest["snapshot_id"],
        "tools_lock_sha256": digest_json(tools_lock),
    }
    return {
        "analysis_key": f"analysis-{digest_json(basis)}",
        "basis": basis,
        "decisions": decisions,
        "producer": ANALYZER_PRODUCER,
        "schema_version": 1,
        "stages": stages,
    }


def _publish_artifact(artifacts_root: Path, data: bytes) -> tuple[str, Path, bool]:
    digest = sha256_bytes(data)
    destination = object_path(artifacts_root, digest)
    if destination.is_file():
        return digest, destination, False
    staging_root = artifacts_root / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix="artifact-", suffix=".part", dir=staging_root
    )
    staging = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        created = publish_cas_staging(staging, destination)
    finally:
        staging.unlink(missing_ok=True)
    return digest, destination, created


def _register_snapshot(
    registry: Registry, manifest: dict[str, Any], manifest_digest: str, run_id: str
) -> None:
    db = registry.db
    db.execute(
        "INSERT OR IGNORE INTO builds(build_id,snapshot_id,created_by_run_id) VALUES(?,?,?)",
        (manifest["build_id"], manifest["snapshot_id"], run_id),
    )
    db.execute(
        """INSERT OR IGNORE INTO snapshots(
            snapshot_id,build_id,selection_id,selection_sha256,manifest_sha256,manifest_logical_path,imported_from
        ) VALUES(?,?,?,?,?,?,?)""",
        (
            manifest["snapshot_id"],
            manifest["build_id"],
            manifest["selection_id"],
            manifest["selection_sha256"],
            manifest_digest,
            f"snapshot:/{manifest['snapshot_id']}/capture-manifest.json",
            manifest.get("imported_from"),
        ),
    )
    for item in manifest.get("payloads", []):
        object_id = str(item["object_id"])
        db.execute(
            "INSERT OR IGNORE INTO input_objects(input_object_id,sha256,size_bytes,storage_path) VALUES(?,?,?,?)",
            (
                object_id,
                item["sha256"],
                item["size_bytes"],
                f"inputs:/objects/sha256/{item['sha256'][:2]}/{item['sha256']}",
            ),
        )
        input_file_id = (
            f"input-file:{digest_json([manifest['snapshot_id'], item['logical_path']])}"
        )
        db.execute(
            "INSERT OR IGNORE INTO input_files(input_file_id,snapshot_id,logical_path,input_object_id,identity_contribution) VALUES(?,?,?,?,?)",
            (
                input_file_id,
                manifest["snapshot_id"],
                item["logical_path"],
                object_id,
                item["identity_contribution"],
            ),
        )
        observation_id = f"capture-observation:{digest_json([manifest['snapshot_id'], item['rule_id'], item['logical_path']])}"
        db.execute(
            """INSERT OR IGNORE INTO capture_observations(
                capture_observation_id,snapshot_id,capture_rule_id,feature,mode,logical_path,presence,input_object_id,bounded_metadata_json
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                observation_id,
                manifest["snapshot_id"],
                item.get("rule_id"),
                item.get("feature"),
                "payload",
                item["logical_path"],
                "present",
                object_id,
                "{}",
            ),
        )


def _run_cached_stage(
    *,
    registry: Registry,
    report: RunReport,
    analysis_id: str,
    stage_name: str,
    cache_context: dict[str, Any],
    artifact_value: dict[str, Any],
    roots: AnalyzerRoots,
    output_relative: Path,
    tool_name: str,
    tool_version: str,
    invoker: ToolInvoker | None,
    targets: list[str],
) -> dict[str, Any]:
    cache_key = f"{stage_name}:{digest_json(cache_context)}"
    cached = registry.cache_entry(cache_key)
    destination = roots.output / output_relative
    if cached is not None:
        artifact = object_path(roots.artifacts, str(cached["artifact_sha256"]))
        if (
            artifact.is_file()
            and destination.is_file()
            and sha256_file(artifact)[0] == cached["artifact_sha256"]
            and sha256_file(destination)[0] == cached["artifact_sha256"]
        ):
            step = report.add_step(
                f"analysis.{stage_name}",
                stage_name,
                category="analysis",
                status="cache_hit",
                reason="complete_cache_key_match",
                cache_status="hit",
                tool_name=tool_name,
                tool_version=tool_version,
                input_item_count=len(targets),
                output_item_count=1,
                output_bytes=artifact.stat().st_size,
            )
            return {
                "artifact_sha256": cached["artifact_sha256"],
                "cache_status": "hit",
                "step": step.public(),
            }

    with report.step(
        f"analysis.{stage_name}",
        stage_name,
        category="analysis",
        cache_status="miss",
        tool_name=tool_name,
        tool_version=tool_version,
    ) as step:
        step.input_item_count = len(targets)
        if invoker is not None:
            for target in targets:
                invoker(stage_name, target)
        data = pretty_json_bytes(artifact_value)
        artifact_digest, _, _ = _publish_artifact(roots.artifacts, data)
        atomic_write_bytes(destination, data)
        registry.put_cache_entry(
            key=cache_key,
            stage_name=stage_name,
            artifact_sha256=artifact_digest,
            artifact_logical_path=f"artifact:/objects/sha256/{artifact_digest[:2]}/{artifact_digest}",
            producer_name=ANALYZER_PRODUCER["name"],
            producer_version=ANALYZER_PRODUCER["version"],
            context=cache_context,
            analysis_id=analysis_id,
        )
        step.output_item_count = 1
        step.output_bytes = len(data)
    return {"artifact_sha256": artifact_digest, "cache_status": "miss"}


def analyze_handoff(
    *,
    roots: AnalyzerRoots,
    slot: str,
    profile: LoadedYaml,
    input_profile: LoadedYaml,
    policy: LoadedYaml,
    tools_lock: dict[str, Any],
    migrations_root: Path,
    enforce_read_only_inputs: bool,
    tool_invoker: ToolInvoker | None = None,
) -> dict[str, Any]:
    assert_no_live_source_environment()
    claim = claim_handoff(roots.handoff, slot)
    record = claim.record
    run_id = str(record.get("workflow_run_id", "invalid"))
    report = RunReport(run_id, "analysis")
    try:
        with report.step(
            "analysis.quick_preflight", "quick_preflight", category="control"
        ) as step:
            quick = quick_preflight(
                "analyzer",
                {
                    "inputs": (roots.inputs, False),
                    "handoff": (roots.handoff, True),
                    "state": (roots.state, True),
                    "artifacts": (roots.artifacts, True),
                    "cache": (roots.cache, True),
                    "work": (roots.work, True),
                    "output": (roots.output, True),
                },
                require_inputs_read_only=enforce_read_only_inputs,
            )
            step.output_item_count = len(quick["checks"])
        with report.step("analysis.doctor", "doctor", category="control") as step:
            doctor, cache_status = stable_doctor(
                role="analyzer",
                profile=profile,
                tools_lock=tools_lock,
                cache_root=roots.cache,
                refresh=False,
            )
            step.cache_status = cache_status
            step.status = "cache_hit" if cache_status == "hit" else "completed"
            step.output_item_count = len(doctor["checks"])
        with report.step("analysis.preflight", "preflight", category="control") as step:
            manifest, manifest_path = _validate_handoff(
                record, roots.inputs, input_profile
            )
            step.input_item_count = len(manifest.get("payloads", []))
            step.input_bytes = manifest_path.stat().st_size
        report.snapshot_id = manifest["snapshot_id"]
        manifest_digest = str(record["snapshot_manifest_sha256"])
        plan = build_analysis_plan(manifest, profile, policy, tools_lock)
        analysis_id = f"run:{run_id}"

        with registry_writer_lock(roots.state):  # noqa: SIM117
            with Registry(roots.state / "registry.sqlite", migrations_root) as registry:
                registry.db.execute("BEGIN IMMEDIATE")
                try:
                    _register_snapshot(registry, manifest, manifest_digest, run_id)
                    registry.db.execute(
                        "INSERT INTO analysis_runs(analysis_id,workflow_run_id,snapshot_id,analysis_key,status,started_at) VALUES(?,?,?,?,?,?)",
                        (
                            analysis_id,
                            run_id,
                            manifest["snapshot_id"],
                            plan["analysis_key"],
                            "running",
                            report.started_at,
                        ),
                    )
                    for decision in plan["decisions"]:
                        decision_id = f"scope:{digest_json([manifest['snapshot_id'], decision['subject_id']])}"
                        registry.db.execute(
                            """INSERT OR REPLACE INTO scope_decisions(
                                scope_decision_id,snapshot_id,subject_kind,subject_id,decision,reason,evidence_refs_json
                            ) VALUES(?,?,?,?,?,?,?)""",
                            (
                                decision_id,
                                manifest["snapshot_id"],
                                decision["subject_kind"],
                                decision["subject_id"],
                                decision["decision"],
                                decision["reason"],
                                json.dumps(
                                    decision["evidence_refs"], ensure_ascii=False
                                ),
                            ),
                        )

                    build_root = Path("builds") / manifest["build_id"] / "m1"
                    scope_result = _run_cached_stage(
                        registry=registry,
                        report=report,
                        analysis_id=analysis_id,
                        stage_name="scope",
                        cache_context={
                            **plan["basis"],
                            "stage": "scope",
                            "decisions": plan["decisions"],
                        },
                        artifact_value=plan,
                        roots=roots,
                        output_relative=build_root / "scope-plan.json",
                        tool_name="modkit-scope",
                        tool_version="0.1.0",
                        invoker=None,
                        targets=[item["logical_path"] for item in plan["decisions"]],
                    )
                    approved = [
                        item["logical_path"]
                        for item in plan["decisions"]
                        if item["decision"] == "game_decompile"
                    ]
                    ghidra_result = _run_cached_stage(
                        registry=registry,
                        report=report,
                        analysis_id=analysis_id,
                        stage_name="ghidra",
                        cache_context={
                            **plan["basis"],
                            "stage": "ghidra",
                            "targets": approved,
                            "mode": "m1_adapter_contract",
                        },
                        artifact_value={
                            "decompilation_performed": False,
                            "operation": "m1_adapter_contract",
                            "requested_targets": approved,
                            "schema_version": 1,
                            "tool": "ghidra",
                        },
                        roots=roots,
                        output_relative=build_root / "ghidra-plan.json",
                        tool_name="Ghidra",
                        tool_version="12.1.4-contract",
                        invoker=tool_invoker,
                        targets=approved,
                    )
                    bsim_result = _run_cached_stage(
                        registry=registry,
                        report=report,
                        analysis_id=analysis_id,
                        stage_name="bsim",
                        cache_context={
                            **plan["basis"],
                            "stage": "bsim",
                            "targets": approved,
                            "mode": "m1_adapter_contract",
                        },
                        artifact_value={
                            "signatures_generated": False,
                            "operation": "m1_adapter_contract",
                            "requested_targets": approved,
                            "schema_version": 1,
                            "tool": "bsim",
                        },
                        roots=roots,
                        output_relative=build_root / "bsim-plan.json",
                        tool_name="Ghidra BSim",
                        tool_version="12.1.4-contract",
                        invoker=tool_invoker,
                        targets=approved,
                    )
                    checkpoint = {
                        "analysis_key": plan["analysis_key"],
                        "artifacts": {
                            "bsim": bsim_result["artifact_sha256"],
                            "ghidra": ghidra_result["artifact_sha256"],
                            "scope": scope_result["artifact_sha256"],
                        },
                        "schema_version": 1,
                        "snapshot_id": manifest["snapshot_id"],
                    }
                    atomic_write_json(
                        roots.state / "checkpoints" / f"{plan['analysis_key']}.json",
                        checkpoint,
                    )
                    report.metadata.update(
                        {
                            "analysis_key": plan["analysis_key"],
                            "build_id": manifest["build_id"],
                            "migrations_applied": registry.applied_migrations,
                            "migrations_root": "repository:/migrations",
                            "scope_counts": {
                                decision: sum(
                                    1
                                    for item in plan["decisions"]
                                    if item["decision"] == decision
                                )
                                for decision in (
                                    "game_decompile",
                                    "reference_only",
                                    "excluded",
                                    "needs_review",
                                )
                            },
                            "tool_lock_status": tools_lock.get("lock_status"),
                        }
                    )
                    report.finish("completed")
                    for item in report.steps:
                        value = item.public()
                        registry.db.execute(
                            """INSERT INTO stage_runs(
                                stage_run_id,analysis_id,step_id,parent_step_id,stage_name,substep_name,component_id,
                                status,reason,cache_status,tool_name,tool_version,started_at,ended_at,duration_ms,
                                input_item_count,input_bytes,output_item_count,output_bytes,cpu_time_ms,peak_rss_bytes,error_code
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
                    registry.db.execute(
                        "UPDATE analysis_runs SET status='completed', ended_at=? WHERE analysis_id=?",
                        (report.ended_at, analysis_id),
                    )
                    registry.db.commit()
                except BaseException:
                    registry.db.rollback()
                    raise

        capture_report_path = roots.inputs / str(record.get("capture_report", ""))
        capture_report = (
            read_json(capture_report_path) if capture_report_path.is_file() else None
        )
        combined = merge_reports(capture_report, report)
        publish_report(roots.output, combined)
        claim.complete()
        return {
            "analysis_key": plan["analysis_key"],
            "build_id": manifest["build_id"],
            "cache": {
                "bsim": bsim_result["cache_status"],
                "ghidra": ghidra_result["cache_status"],
                "scope": scope_result["cache_status"],
            },
            "report": f"reports/{run_id}/run-report.json",
            "snapshot_id": manifest["snapshot_id"],
            "workflow_run_id": run_id,
        }
    except BaseException:
        report.finish("failed")
        try:
            failed_report = merge_reports(None, report)
            publish_report(roots.output, failed_report)
        finally:
            if claim.path.exists():
                claim.fail()
        raise
