from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import AnalyzerRoots, analyze_handoff, build_analysis_plan
from .capture import publish_snapshot, verify_snapshot
from .compare import CompareRoots, compare_builds
from .config import load_yaml
from .doctor import quick_preflight, stable_doctor
from .errors import ModkitError
from .ghidra_adapter import GhidraAdapter
from .import_m0 import import_m0_bundle
from .lua_analysis import LuaRoots, analyze_lua_snapshot, import_runtime_observations
from .native import NativeRoots, analyze_native_snapshot
from .planner import build_capture_plan
from .reporting import RunReport
from .sdk import (
    SdkRoots,
    finalize_sdk_release,
    generate_sdk_release,
    package_sdk_release,
    verify_sdk_package,
)
from .util import pretty_json_bytes, read_json
from .watch import watch_capture

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _path(value: str) -> Path:
    return Path(value)


def _default(name: str, fallback: str) -> str:
    return os.environ.get(name, fallback)


def _add_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=_path,
        default=_path(
            _default("MODKIT_CONFIG", str(REPOSITORY_ROOT / "profiles/aniimo.yaml"))
        ),
    )


def _add_input_profile(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input-selection",
        type=_path,
        default=_path(
            _default(
                "MODKIT_INPUT_SELECTION",
                str(REPOSITORY_ROOT / "profiles/aniimo.inputs.yaml"),
            )
        ),
    )


def _add_analysis_roots(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    parser.add_argument(
        "--handoff-root",
        type=_path,
        default=_path(_default("MODKIT_HANDOFF_ROOT", "/handoff")),
    )
    parser.add_argument(
        "--state-root",
        type=_path,
        default=_path(_default("MODKIT_STATE_ROOT", "/state")),
    )
    parser.add_argument(
        "--artifacts-root",
        type=_path,
        default=_path(_default("MODKIT_ARTIFACTS_ROOT", "/artifacts")),
    )
    parser.add_argument(
        "--cache-root",
        type=_path,
        default=_path(_default("MODKIT_CACHE_ROOT", "/cache")),
    )
    parser.add_argument(
        "--work-root", type=_path, default=_path(_default("MODKIT_WORK_ROOT", "/work"))
    )
    parser.add_argument(
        "--output-root",
        type=_path,
        default=_path(_default("MODKIT_OUTPUT_ROOT", "/output")),
    )


def _load_tools_lock(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ModkitError(
            f"Lock d’outillage absent : {path}",
            exit_code=2,
            error_code="tools_lock_missing",
        )
    value = read_json(path)
    if not isinstance(value, dict):
        raise ModkitError(
            "Lock d’outillage invalide.", exit_code=2, error_code="tools_lock_invalid"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modkit", description="Pipeline local reproductible Aniimo"
    )
    parser.add_argument("--version", action="version", version=f"modkit {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser(
        "doctor", help="Vérifier l’infrastructure et les adaptateurs"
    )
    _add_config(doctor)
    _add_analysis_roots(doctor)
    doctor.add_argument("--role", choices=("capture", "analyzer"), default="analyzer")
    doctor.add_argument("--refresh", action="store_true")
    doctor.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )

    capture = commands.add_parser(
        "capture", help="Planifier et capturer une installation"
    )
    _add_config(capture)
    _add_input_profile(capture)
    capture.add_argument(
        "--game-root",
        type=_path,
        default=_path(_default("MODKIT_GAME_ROOT", "/source/game")),
    )
    capture.add_argument(
        "--steam-manifest",
        type=_path,
        default=_path(
            _default("MODKIT_STEAM_MANIFEST", "/source/steam/appmanifest.acf")
        ),
    )
    capture.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    capture.add_argument(
        "--handoff-root",
        type=_path,
        default=_path(_default("MODKIT_HANDOFF_ROOT", "/handoff")),
    )
    capture.add_argument(
        "--handoff-slot", default=_default("MODKIT_HANDOFF_SLOT", "aniimo-default")
    )
    capture.add_argument("--disable-feature", action="append", default=[])
    capture.add_argument("--dry-run", action="store_true")
    capture.add_argument("--run-id")
    capture.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )

    watch = commands.add_parser(
        "watch", help="Surveiller et capturer séquentiellement les changements locaux"
    )
    _add_config(watch)
    _add_input_profile(watch)
    watch.add_argument(
        "--game-root",
        type=_path,
        default=_path(_default("MODKIT_GAME_ROOT", "/source/game")),
    )
    watch.add_argument(
        "--steam-manifest",
        type=_path,
        default=_path(
            _default("MODKIT_STEAM_MANIFEST", "/source/steam/appmanifest.acf")
        ),
    )
    watch.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    watch.add_argument(
        "--handoff-root",
        type=_path,
        default=_path(_default("MODKIT_HANDOFF_ROOT", "/handoff")),
    )
    watch.add_argument(
        "--handoff-slot", default=_default("MODKIT_HANDOFF_SLOT", "aniimo-watch")
    )
    watch.add_argument("--disable-feature", action="append", default=[])
    watch.add_argument("--interval", type=float, default=300.0)
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--max-iterations", type=int, help=argparse.SUPPRESS)
    watch.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )

    plan = commands.add_parser(
        "plan", help="Construire le plan d’analyse d’un snapshot publié"
    )
    _add_config(plan)
    _add_input_profile(plan)
    plan.add_argument(
        "--decompilation-policy",
        type=_path,
        default=_path(
            _default(
                "MODKIT_DECOMPILATION_POLICY",
                str(REPOSITORY_ROOT / "profiles/aniimo.decompilation.yaml"),
            )
        ),
    )
    plan.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    plan.add_argument("--snapshot", required=True)
    plan.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )

    analyze = commands.add_parser(
        "analyze", help="Analyser le snapshot exact d’une remise"
    )
    _add_config(analyze)
    _add_input_profile(analyze)
    _add_analysis_roots(analyze)
    analyze.add_argument(
        "--decompilation-policy",
        type=_path,
        default=_path(
            _default(
                "MODKIT_DECOMPILATION_POLICY",
                str(REPOSITORY_ROOT / "profiles/aniimo.decompilation.yaml"),
            )
        ),
    )
    analyze.add_argument("--handoff", choices=("required",), default="required")
    analyze.add_argument(
        "--handoff-slot", default=_default("MODKIT_HANDOFF_SLOT", "aniimo-default")
    )
    analyze.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )
    analyze.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )
    analyze.add_argument(
        "--allow-writable-inputs-for-fixture",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    native = commands.add_parser(
        "native-analyze",
        help="Analyser les modules natifs approuvés d'un snapshot exact",
    )
    _add_config(native)
    _add_input_profile(native)
    native.add_argument(
        "--decompilation-policy",
        type=_path,
        default=_path(
            _default(
                "MODKIT_DECOMPILATION_POLICY",
                str(REPOSITORY_ROOT / "profiles/aniimo.decompilation.yaml"),
            )
        ),
    )
    native.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    native.add_argument(
        "--state-root",
        type=_path,
        default=_path(_default("MODKIT_STATE_ROOT", "/state")),
    )
    native.add_argument(
        "--artifacts-root",
        type=_path,
        default=_path(_default("MODKIT_ARTIFACTS_ROOT", "/artifacts")),
    )
    native.add_argument(
        "--ghidra-root",
        type=_path,
        default=_path(_default("MODKIT_GHIDRA_ROOT", "/ghidra-state")),
    )
    native.add_argument(
        "--work-root",
        type=_path,
        default=_path(_default("MODKIT_WORK_ROOT", "/work")),
    )
    native.add_argument(
        "--output-root",
        type=_path,
        default=_path(_default("MODKIT_OUTPUT_ROOT", "/output")),
    )
    native.add_argument("--snapshot", required=True)
    native.add_argument("--run-id")
    native.add_argument(
        "--tools-lock", type=_path, default=REPOSITORY_ROOT / "tools.lock.json"
    )
    native.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )
    native.add_argument(
        "--ghidra-headless",
        type=_path,
        default=_path(
            _default("MODKIT_GHIDRA_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
        ),
    )
    native.add_argument(
        "--ghidra-script",
        type=_path,
        default=REPOSITORY_ROOT / "ghidra/ExportApprovedFunctions.java",
    )
    native.add_argument(
        "--allow-writable-inputs-for-fixture",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    compare = commands.add_parser(
        "compare-builds", help="Comparer deux snapshots natifs analysés"
    )
    _add_input_profile(compare)
    compare.add_argument(
        "--decompilation-policy",
        type=_path,
        default=_path(
            _default(
                "MODKIT_DECOMPILATION_POLICY",
                str(REPOSITORY_ROOT / "profiles/aniimo.decompilation.yaml"),
            )
        ),
    )
    compare.add_argument(
        "--annotations",
        type=_path,
        default=_path(
            _default(
                "MODKIT_MATCHING_ANNOTATIONS",
                str(REPOSITORY_ROOT / "profiles/aniimo.matching.yaml"),
            )
        ),
    )
    compare.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    compare.add_argument(
        "--state-root",
        type=_path,
        default=_path(_default("MODKIT_STATE_ROOT", "/state")),
    )
    compare.add_argument(
        "--artifacts-root",
        type=_path,
        default=_path(_default("MODKIT_ARTIFACTS_ROOT", "/artifacts")),
    )
    compare.add_argument(
        "--output-root",
        type=_path,
        default=_path(_default("MODKIT_OUTPUT_ROOT", "/output")),
    )
    compare.add_argument("--source-snapshot", required=True)
    compare.add_argument("--destination-snapshot", required=True)
    compare.add_argument("--run-id")
    compare.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )
    compare.add_argument(
        "--allow-writable-inputs-for-fixture",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    lua = commands.add_parser(
        "lua-analyze", help="Analyser statiquement les archives Lua d'un snapshot exact"
    )
    _add_config(lua)
    _add_input_profile(lua)
    _add_analysis_roots(lua)
    lua.add_argument("--snapshot", required=True)
    lua.add_argument("--run-id")
    lua.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )
    lua.add_argument(
        "--allow-writable-inputs-for-fixture",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    lua_import = commands.add_parser(
        "lua-import",
        help="Importer des observations Lua issues d'un processus autorisÃ©",
    )
    _add_analysis_roots(lua_import)
    lua_import.add_argument("observation", type=_path)
    lua_import.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )

    sdk_generate = commands.add_parser(
        "sdk-generate", help="Générer les manifestes exacts d'une release SDK"
    )
    sdk_generate.add_argument("--build", action="append", required=True)
    sdk_generate.add_argument("--sdk-version", required=True)
    sdk_generate.add_argument("--adapter-version", required=True)
    sdk_generate.add_argument("--run-id")
    sdk_generate.add_argument(
        "--state-root",
        type=_path,
        default=_path(_default("MODKIT_STATE_ROOT", "/state")),
    )
    sdk_generate.add_argument(
        "--output-root",
        type=_path,
        default=_path(_default("MODKIT_OUTPUT_ROOT", "/output")),
    )
    sdk_generate.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )

    sdk_package = commands.add_parser(
        "sdk-package", help="Créer le package SDK déterministe autorisé"
    )
    sdk_package.add_argument("--compiled-root", type=_path, required=True)
    sdk_package.add_argument("--generated-root", type=_path, required=True)
    sdk_package.add_argument("--documentation", type=_path, required=True)
    sdk_package.add_argument("--destination", type=_path, required=True)

    sdk_finalize = commands.add_parser(
        "sdk-finalize", help="Consigner le package et les validations SDK"
    )
    sdk_finalize.add_argument("--generated-root", type=_path, required=True)
    sdk_finalize.add_argument("--package", type=_path, required=True)
    sdk_finalize.add_argument("--contract", type=_path, required=True)
    sdk_finalize.add_argument("--test-report", type=_path, required=True)
    sdk_finalize.add_argument("--run-id")
    sdk_finalize.add_argument(
        "--state-root",
        type=_path,
        default=_path(_default("MODKIT_STATE_ROOT", "/state")),
    )
    sdk_finalize.add_argument(
        "--output-root",
        type=_path,
        default=_path(_default("MODKIT_OUTPUT_ROOT", "/output")),
    )
    sdk_finalize.add_argument(
        "--migrations-root", type=_path, default=REPOSITORY_ROOT / "migrations"
    )

    sdk_verify = commands.add_parser(
        "sdk-verify", help="Vérifier l’allowlist et les empreintes d’un package SDK"
    )
    sdk_verify.add_argument("package", type=_path)
    sdk_verify.add_argument("--expected-sha256")

    imported = commands.add_parser(
        "import-m0", help="Valider et réimporter un bundle M0 dans le contrat M1"
    )
    _add_input_profile(imported)
    imported.add_argument("bundle", type=_path)
    imported.add_argument("--inputs-root", type=_path, required=True)
    imported.add_argument("--handoff-root", type=_path, required=True)
    imported.add_argument(
        "--handoff-slot", default=_default("MODKIT_HANDOFF_SLOT", "aniimo-default")
    )
    imported.add_argument("--run-id")

    verify = commands.add_parser("verify", help="Vérifier un snapshot immuable")
    verify.add_argument(
        "--inputs-root",
        type=_path,
        default=_path(_default("MODKIT_INPUTS_ROOT", "/inputs")),
    )
    verify.add_argument("--snapshot", default="current")
    verify.add_argument("--full-hash", action="store_true")
    verify.add_argument("--scope", choices=("static",), default="static")

    return parser


def _print(value: Any) -> None:
    sys.stdout.buffer.write(pretty_json_bytes(value))


def _resolve_snapshot(inputs_root: Path, requested: str) -> str:
    if requested == "current":
        pointer = read_json(inputs_root / "current.json")
        return str(pointer["snapshot_id"])
    return requested


def _capture_command(
    args: argparse.Namespace, *, publish_handoff_record: bool = True
) -> dict[str, Any]:
    profile = load_yaml(args.config)
    selection = load_yaml(args.input_selection)
    run_id = args.run_id or f"run-{uuid.uuid4()}"
    report = RunReport(run_id, "capture")
    with report.step(
        "capture.quick_preflight", "quick_preflight", category="control"
    ) as step:
        if args.dry_run:
            if not args.game_root.is_dir() or not args.steam_manifest.is_file():
                raise ModkitError(
                    "Sources de capture absentes.",
                    exit_code=2,
                    error_code="capture_source_missing",
                )
            quick = {"checks": [{"name": "sources", "status": "passed"}]}
        else:
            quick = quick_preflight(
                "capture",
                {
                    "game": (args.game_root, False),
                    "steam_manifest_parent": (args.steam_manifest.parent, False),
                    "inputs": (args.inputs_root, True),
                    "handoff": (args.handoff_root, True),
                },
            )
        step.output_item_count = len(quick["checks"])
    if not args.dry_run:
        with report.step("capture.doctor", "doctor", category="control") as step:
            doctor, cache_status = stable_doctor(
                role="capture",
                profile=profile,
                tools_lock=_load_tools_lock(args.tools_lock),
                cache_root=args.handoff_root / "doctor-cache" / "capture",
                refresh=False,
            )
            step.cache_status = cache_status
            step.status = "cache_hit" if cache_status == "hit" else "completed"
            step.output_item_count = len(doctor["checks"])
    with report.step("capture.plan", "plan", category="planning") as step:
        plan = build_capture_plan(
            selection,
            args.game_root,
            args.steam_manifest,
            disabled_features=set(args.disable_feature),
        )
        step.input_item_count = len(plan.payloads) + len(plan.inventory)
        step.input_bytes = plan.estimated_bytes
        step.output_item_count = len(plan.payloads)
    if args.dry_run:
        report.finish("completed")
        return {
            "dry_run": True,
            "plan": plan.public(),
            "report": report.public(),
            "writes_to_inputs": 0,
        }
    return publish_snapshot(
        plan,
        args.inputs_root,
        workflow_run_id=run_id,
        handoff_root=args.handoff_root if publish_handoff_record else None,
        handoff_slot=args.handoff_slot if publish_handoff_record else None,
        report=report,
    )


def _watch_command(args: argparse.Namespace) -> dict[str, Any]:
    stop = threading.Event()
    previous_handlers: dict[signal.Signals, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        stop.set()

    if not args.once:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)

    def capture_once() -> dict[str, Any]:
        iteration = argparse.Namespace(**vars(args))
        iteration.dry_run = False
        iteration.run_id = f"run-watch-{uuid.uuid4()}"
        return _capture_command(iteration, publish_handoff_record=False)

    try:
        return watch_capture(
            inputs_root=args.inputs_root,
            handoff_root=args.handoff_root,
            handoff_slot=args.handoff_slot,
            interval_seconds=args.interval,
            capture_once=capture_once,
            stop_event=stop,
            once=args.once,
            max_iterations=args.max_iterations,
            continue_on_error=not args.once,
        )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _plan_command(args: argparse.Namespace) -> dict[str, Any]:
    profile = load_yaml(args.config)
    selection = load_yaml(args.input_selection)
    policy = load_yaml(args.decompilation_policy)
    snapshot_id = _resolve_snapshot(args.inputs_root, args.snapshot)
    manifest = read_json(
        args.inputs_root / "snapshots" / snapshot_id / "capture-manifest.json"
    )
    if manifest.get("selection_sha256") != selection.sha256:
        raise ModkitError(
            "Snapshot lié à une autre allowlist.",
            exit_code=5,
            error_code="selection_digest_mismatch",
        )
    return build_analysis_plan(
        manifest, profile, policy, _load_tools_lock(args.tools_lock)
    )


def _analyze_command(args: argparse.Namespace) -> dict[str, Any]:
    roots = AnalyzerRoots(
        inputs=args.inputs_root,
        handoff=args.handoff_root,
        state=args.state_root,
        artifacts=args.artifacts_root,
        cache=args.cache_root,
        work=args.work_root,
        output=args.output_root,
    )
    return analyze_handoff(
        roots=roots,
        slot=args.handoff_slot,
        profile=load_yaml(args.config),
        input_profile=load_yaml(args.input_selection),
        policy=load_yaml(args.decompilation_policy),
        tools_lock=_load_tools_lock(args.tools_lock),
        migrations_root=args.migrations_root,
        enforce_read_only_inputs=not args.allow_writable_inputs_for_fixture,
    )


def _native_analyze_command(args: argparse.Namespace) -> dict[str, Any]:
    profile = load_yaml(args.config)
    analysis = profile.data.get("analysis", {})
    roots = NativeRoots(
        inputs=args.inputs_root,
        state=args.state_root,
        artifacts=args.artifacts_root,
        ghidra=args.ghidra_root,
        work=args.work_root,
        output=args.output_root,
    )
    adapter = GhidraAdapter(
        executable=args.ghidra_headless,
        script=args.ghidra_script,
        project_root=args.ghidra_root / "m2",
        work_root=args.work_root / "m2",
        timeout_seconds=int(analysis.get("primary_decompile_timeout_seconds", 15)),
        maximum_primary_timeouts=int(analysis.get("max_primary_timeouts_per_run", 16)),
        difficult_timeout_seconds=int(
            analysis.get("difficult_queue", {}).get("timeout_seconds", 120)
        ),
        maximum_difficult_bodies=int(
            analysis.get("difficult_queue", {}).get("max_bodies_per_run", 2)
        ),
        maximum_difficult_wall_seconds=int(
            analysis.get("difficult_queue", {}).get("max_wall_time_seconds", 240)
        ),
        bsim_executable=Path(_default("MODKIT_BSIM", "/opt/ghidra/support/bsim")),
        bsim_enabled=analysis.get("bsim") == "enabled",
    )
    result = analyze_native_snapshot(
        roots=roots,
        snapshot_id=args.snapshot,
        profile=profile,
        input_profile=load_yaml(args.input_selection),
        policy=load_yaml(args.decompilation_policy),
        tools_lock=_load_tools_lock(args.tools_lock),
        migrations_root=args.migrations_root,
        adapter=adapter,
        enforce_read_only_inputs=not args.allow_writable_inputs_for_fixture,
        workflow_run_id=args.run_id,
    )
    coverage = dict(result.pop("coverage"))
    result["coverage_summary"] = {
        "approved_body_count": coverage["approved_body_count"],
        "body_status_counts": coverage["body_status_counts"],
        "discovery_complete": coverage["discovery_complete"],
        "exact_body_reconciliation": coverage["exact_body_reconciliation"],
    }
    return result


def _compare_builds_command(args: argparse.Namespace) -> dict[str, Any]:
    return compare_builds(
        roots=CompareRoots(
            inputs=args.inputs_root,
            state=args.state_root,
            artifacts=args.artifacts_root,
            output=args.output_root,
        ),
        source_snapshot_id=args.source_snapshot,
        destination_snapshot_id=args.destination_snapshot,
        input_profile=load_yaml(args.input_selection),
        policy=load_yaml(args.decompilation_policy),
        annotations=load_yaml(args.annotations),
        migrations_root=args.migrations_root,
        enforce_read_only_inputs=not args.allow_writable_inputs_for_fixture,
        workflow_run_id=args.run_id,
    )


def _lua_analyze_command(args: argparse.Namespace) -> dict[str, Any]:
    return analyze_lua_snapshot(
        roots=LuaRoots(
            inputs=args.inputs_root,
            state=args.state_root,
            artifacts=args.artifacts_root,
            work=args.work_root,
            output=args.output_root,
        ),
        snapshot_id=args.snapshot,
        profile=load_yaml(args.config),
        input_profile=load_yaml(args.input_selection),
        migrations_root=args.migrations_root,
        enforce_read_only_inputs=not args.allow_writable_inputs_for_fixture,
        workflow_run_id=args.run_id,
    )


def _lua_import_command(args: argparse.Namespace) -> dict[str, Any]:
    return import_runtime_observations(
        roots=LuaRoots(
            inputs=args.inputs_root,
            state=args.state_root,
            artifacts=args.artifacts_root,
            work=args.work_root,
            output=args.output_root,
        ),
        observation_path=args.observation,
        migrations_root=args.migrations_root,
    )


def _sdk_generate_command(args: argparse.Namespace) -> dict[str, Any]:
    return generate_sdk_release(
        roots=SdkRoots(state=args.state_root, output=args.output_root),
        build_ids=args.build,
        sdk_version=args.sdk_version,
        adapter_version=args.adapter_version,
        migrations_root=args.migrations_root,
        workflow_run_id=args.run_id,
    )


def _sdk_package_command(args: argparse.Namespace) -> dict[str, Any]:
    return package_sdk_release(
        compiled_root=args.compiled_root,
        generated_root=args.generated_root,
        documentation_path=args.documentation,
        destination=args.destination,
    )


def _sdk_finalize_command(args: argparse.Namespace) -> dict[str, Any]:
    return finalize_sdk_release(
        roots=SdkRoots(state=args.state_root, output=args.output_root),
        generated_root=args.generated_root,
        package_path=args.package,
        contract_path=args.contract,
        test_report_path=args.test_report,
        migrations_root=args.migrations_root,
        workflow_run_id=args.run_id,
    )


def _sdk_verify_command(args: argparse.Namespace) -> dict[str, Any]:
    return verify_sdk_package(args.package, expected_sha256=args.expected_sha256)


def _doctor_command(args: argparse.Namespace) -> dict[str, Any]:
    profile = load_yaml(args.config)
    lock = _load_tools_lock(args.tools_lock)
    cache_root = (
        args.cache_root
        if args.role == "analyzer"
        else args.handoff_root / "doctor-cache" / "capture"
    )
    result, cache_status = stable_doctor(
        role=args.role,
        profile=profile,
        tools_lock=lock,
        cache_root=cache_root,
        refresh=args.refresh,
    )
    return {"cache_status": cache_status, **result}


def _verify_command(args: argparse.Namespace) -> dict[str, Any]:
    snapshot_id = _resolve_snapshot(args.inputs_root, args.snapshot)
    return verify_snapshot(args.inputs_root, snapshot_id, full_hash=args.full_hash)


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "doctor":
        return _doctor_command(args)
    if args.command == "capture":
        return _capture_command(args)
    if args.command == "watch":
        return _watch_command(args)
    if args.command == "plan":
        return _plan_command(args)
    if args.command == "analyze":
        return _analyze_command(args)
    if args.command == "native-analyze":
        return _native_analyze_command(args)
    if args.command == "compare-builds":
        return _compare_builds_command(args)
    if args.command == "lua-analyze":
        return _lua_analyze_command(args)
    if args.command == "lua-import":
        return _lua_import_command(args)
    if args.command == "sdk-generate":
        return _sdk_generate_command(args)
    if args.command == "sdk-package":
        return _sdk_package_command(args)
    if args.command == "sdk-finalize":
        return _sdk_finalize_command(args)
    if args.command == "sdk-verify":
        return _sdk_verify_command(args)
    if args.command == "import-m0":
        return import_m0_bundle(
            bundle_root=args.bundle,
            inputs_root=args.inputs_root,
            handoff_root=args.handoff_root,
            slot=args.handoff_slot,
            input_profile=load_yaml(args.input_selection),
            workflow_run_id=args.run_id,
        )
    if args.command == "verify":
        return _verify_command(args)
    raise AssertionError(args.command)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = dispatch(args)
    except ModkitError as exc:
        sys.stderr.buffer.write(
            pretty_json_bytes(
                {
                    "error": str(exc),
                    "error_code": exc.error_code,
                    "exit_code": exc.exit_code,
                    "status": "failed",
                }
            )
        )
        return exc.exit_code
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.buffer.write(
            pretty_json_bytes(
                {
                    "error": str(exc),
                    "error_code": type(exc).__name__,
                    "exit_code": 4,
                    "status": "failed",
                }
            )
        )
        return 4
    _print(result)
    return 0
