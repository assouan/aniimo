from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from modkit.analyzer import AnalyzerRoots, analyze_handoff
from modkit.capture import publish_snapshot
from modkit.config import load_yaml
from modkit.errors import CaptureError, ValidationError
from modkit.import_m0 import import_m0_bundle
from modkit.planner import build_capture_plan
from modkit.registry import Registry
from modkit.reporting import RunReport
from modkit.util import read_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.game = root / "game"
        self.steam = root / "appmanifest_4126040.acf"
        self.inputs = root / "inputs"
        self.handoff = root / "handoff"
        self.state = root / "state"
        self.artifacts = root / "artifacts"
        self.cache = root / "cache"
        self.work = root / "work"
        self.output = root / "output"
        (self.game / "Aniimo_Data").mkdir(parents=True)
        (self.game / "Aniimo.exe").write_bytes(b"fixture-aniimo-pe")
        (self.game / "Aniimo_Data/globalgamemanagers").write_bytes(
            b"2022.3.62f1\0fixture"
        )
        for name in (
            "NEP2.dll",
            "NEPKernel.sys",
            "NEPCleaner.exe",
            "KernelDumpAnalyzer.exe",
        ):
            (self.game / name).write_bytes(f"fixture:{name}".encode("ascii"))
        self.steam.write_text(
            '"AppState"\n{\n  "appid" "4126040"\n  "StateFlags" "4"\n  "buildid" "fixture"\n}\n',
            encoding="utf-8",
        )
        self.profile = load_yaml(ROOT / "profiles/aniimo.yaml")
        self.selection = load_yaml(ROOT / "profiles/aniimo.inputs.yaml")
        self.policy = load_yaml(ROOT / "profiles/aniimo.decompilation.yaml")
        self.tools_lock = read_json(ROOT / "tools.lock.json")

    @property
    def roots(self) -> AnalyzerRoots:
        return AnalyzerRoots(
            inputs=self.inputs,
            handoff=self.handoff,
            state=self.state,
            artifacts=self.artifacts,
            cache=self.cache,
            work=self.work,
            output=self.output,
        )

    def plan(self):
        return build_capture_plan(self.selection, self.game, self.steam)

    def capture(self, run_id: str, slot: str = "fixture") -> dict[str, str]:
        report = RunReport(run_id, "capture")
        with report.step("capture.plan", "plan", category="planning"):
            plan = self.plan()
        return publish_snapshot(
            plan,
            self.inputs,
            workflow_run_id=run_id,
            handoff_root=self.handoff,
            handoff_slot=slot,
            report=report,
        )

    def analyze(
        self, slot: str, invocations: list[tuple[str, str]]
    ) -> dict[str, object]:
        return analyze_handoff(
            roots=self.roots,
            slot=slot,
            profile=self.profile,
            input_profile=self.selection,
            policy=self.policy,
            tools_lock=self.tools_lock,
            migrations_root=ROOT / "migrations",
            enforce_read_only_inputs=False,
            tool_invoker=lambda stage, target: invocations.append((stage, target)),
        )


class M1PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_dry_plan_and_real_capture_share_the_same_planner(self) -> None:
        dry_plan = self.fixture.plan()
        self.assertFalse(self.fixture.inputs.exists())
        real_plan = self.fixture.plan()
        self.assertEqual(dry_plan.plan_id, real_plan.plan_id)
        self.assertEqual(dry_plan.public(), real_plan.public())
        result = publish_snapshot(
            real_plan,
            self.fixture.inputs,
            workflow_run_id="run-plan",
            handoff_root=self.fixture.handoff,
            handoff_slot="plan",
        )
        manifest = read_json(
            self.fixture.inputs
            / "snapshots"
            / result["snapshot_id"]
            / "capture-manifest.json"
        )
        self.assertEqual(manifest["plan_id"], dry_plan.plan_id)
        self.assertEqual(len(manifest["payloads"]), 7)

    def test_cli_dry_run_stops_before_inputs_or_handoff_writes(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "modkit",
                "capture",
                "--dry-run",
                "--game-root",
                str(self.fixture.game),
                "--steam-manifest",
                str(self.fixture.steam),
                "--inputs-root",
                str(self.fixture.inputs),
                "--handoff-root",
                str(self.fixture.handoff),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value["dry_run"])
        self.assertEqual(value["writes_to_inputs"], 0)
        self.assertFalse(self.fixture.inputs.exists())
        self.assertFalse(self.fixture.handoff.exists())

    def test_second_identical_analysis_hits_all_stage_caches_without_invocation_or_rewrite(
        self,
    ) -> None:
        first_capture = self.fixture.capture("run-first", "first")
        first_invocations: list[tuple[str, str]] = []
        first = self.fixture.analyze("first", first_invocations)
        self.assertEqual(first["snapshot_id"], first_capture["snapshot_id"])
        self.assertEqual(len(first_invocations), 8)
        self.assertEqual(
            first["cache"], {"scope": "miss", "ghidra": "miss", "bsim": "miss"}
        )
        scope_plan = read_json(
            self.fixture.output / "builds" / first["build_id"] / "m1/scope-plan.json"
        )
        required = set(
            read_json(ROOT / "schemas/analysis-plan-v1.schema.json")["required"]
        )
        self.assertLessEqual(required, set(scope_plan))
        self.assertEqual(scope_plan["analysis_key"], first["analysis_key"])
        self.assertEqual(
            scope_plan["basis"]["snapshot_id"], first_capture["snapshot_id"]
        )
        self.assertEqual(
            [stage["name"] for stage in scope_plan["stages"]],
            ["scope", "ghidra", "bsim"],
        )
        outputs = sorted((self.fixture.output / "builds").rglob("*.json"))
        before = {
            path: (path.stat().st_mtime_ns, sha256_file(path)[0]) for path in outputs
        }

        second_capture = self.fixture.capture("run-second", "second")
        second_invocations: list[tuple[str, str]] = []
        second = self.fixture.analyze("second", second_invocations)
        self.assertEqual(second_capture["snapshot_id"], first_capture["snapshot_id"])
        self.assertEqual(second_invocations, [])
        self.assertEqual(
            second["cache"], {"scope": "hit", "ghidra": "hit", "bsim": "hit"}
        )
        after = {
            path: (path.stat().st_mtime_ns, sha256_file(path)[0]) for path in outputs
        }
        self.assertEqual(before, after)

        report = read_json(self.fixture.output / second["report"])
        by_id = {item["step_id"]: item for item in report["steps"]}
        self.assertEqual(by_id["analysis.ghidra"]["status"], "cache_hit")
        self.assertEqual(by_id["analysis.bsim"]["status"], "cache_hit")
        self.assertEqual(by_id["analysis.doctor"]["status"], "cache_hit")
        self.assertTrue(
            (self.fixture.output / "reports/run-second/timings.csv").is_file()
        )
        self.assertTrue(
            (self.fixture.output / "reports/run-second/report.md").is_file()
        )

    def test_interleaved_handoffs_keep_exact_snapshots_and_same_slot_fails_closed(
        self,
    ) -> None:
        first = self.fixture.capture("run-a", "slot-a")
        target = self.fixture.game / "Aniimo.exe"
        target.write_bytes(b"fixture-aniimo-v2")
        second = self.fixture.capture("run-b", "slot-b")
        self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
        self.assertEqual(
            read_json(self.fixture.inputs / "current.json")["snapshot_id"],
            second["snapshot_id"],
        )

        analyzed_first = self.fixture.analyze("slot-a", [])
        analyzed_second = self.fixture.analyze("slot-b", [])
        self.assertEqual(analyzed_first["snapshot_id"], first["snapshot_id"])
        self.assertEqual(analyzed_second["snapshot_id"], second["snapshot_id"])

        self.fixture.capture("run-c", "occupied")
        pending = self.fixture.handoff / "pending/occupied.json"
        original = pending.read_bytes()
        with self.assertRaises(CaptureError) as raised:
            self.fixture.capture("run-d", "occupied")
        self.assertEqual(raised.exception.error_code, "handoff_slot_occupied")
        self.assertEqual(pending.read_bytes(), original)

    def test_mtime_only_is_not_a_new_snapshot_but_same_metadata_content_change_is(
        self,
    ) -> None:
        first = self.fixture.capture("run-mtime-a", "mtime-a")
        target = self.fixture.game / "Aniimo.exe"
        stat_before = target.stat()
        os.utime(
            target, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns + 10_000_000)
        )
        second = self.fixture.capture("run-mtime-b", "mtime-b")
        self.assertEqual(first["snapshot_id"], second["snapshot_id"])

        stable_stat = target.stat()
        target.write_bytes(b"fixture-aniimo-v2")
        self.assertEqual(target.stat().st_size, stable_stat.st_size)
        os.utime(target, ns=(stable_stat.st_atime_ns, stable_stat.st_mtime_ns))
        third = self.fixture.capture("run-mtime-c", "mtime-c")
        self.assertNotEqual(second["snapshot_id"], third["snapshot_id"])
        report = read_json(self.fixture.inputs / "run-reports/run-mtime-c.json")
        self.assertEqual(report["metadata"]["same_metadata_content_drifts"], 1)
        self.assertEqual(report["metadata"]["retried_payloads"], 1)

    def test_source_change_after_planning_is_rejected(self) -> None:
        plan = self.fixture.plan()
        (self.fixture.game / "Aniimo.exe").write_bytes(b"changed-after-plan")
        with self.assertRaises(CaptureError) as raised:
            publish_snapshot(
                plan,
                self.fixture.inputs,
                workflow_run_id="run-stale-plan",
                handoff_root=self.fixture.handoff,
                handoff_slot="stale-plan",
            )
        self.assertEqual(raised.exception.error_code, "input_changed_since_plan")
        self.assertFalse((self.fixture.handoff / "pending/stale-plan.json").exists())

    def test_invalid_handoff_digest_is_rejected_without_current_fallback(self) -> None:
        captured = self.fixture.capture("run-invalid", "invalid")
        pending = self.fixture.handoff / "pending/invalid.json"
        record = read_json(pending)
        record["snapshot_manifest_sha256"] = "0" * 64
        pending.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(ValidationError) as raised:
            self.fixture.analyze("invalid", [])
        self.assertEqual(
            raised.exception.error_code, "handoff_manifest_digest_mismatch"
        )
        self.assertFalse((self.fixture.handoff / "pending/invalid.json").exists())
        self.assertTrue(
            any((self.fixture.handoff / "failed").glob("run-invalid--invalid.json"))
        )
        self.assertEqual(
            read_json(self.fixture.inputs / "current.json")["snapshot_id"],
            captured["snapshot_id"],
        )

    def test_registry_migrations_are_transactional_and_backed_up(self) -> None:
        migration_copy = Path(self.temporary.name) / "migration-copy"
        migration_copy.mkdir()
        shutil.copyfile(
            ROOT / "migrations/0001_capture.sql", migration_copy / "0001_capture.sql"
        )
        database = Path(self.temporary.name) / "registry-test.sqlite"
        with Registry(database, migration_copy) as registry:
            self.assertEqual(registry.applied_migrations, [1])
            self.assertEqual(
                registry.db.execute("PRAGMA foreign_keys").fetchone()[0], 1
            )
        shutil.copyfile(
            ROOT / "migrations/0002_pipeline_scope.sql",
            migration_copy / "0002_pipeline_scope.sql",
        )
        with Registry(database, migration_copy) as registry:
            self.assertEqual(registry.applied_migrations, [2])
            self.assertIsNotNone(registry.backup_path)
            self.assertTrue(registry.backup_path.is_file())
            self.assertEqual(
                registry.db.execute("PRAGMA user_version").fetchone()[0], 2
            )

    def test_m0_import_validates_hashes_and_publishes_a_new_contract(self) -> None:
        bundle = Path(self.temporary.name) / "m0"
        files = bundle / "snapshot/files"
        plan = self.fixture.plan()
        source_payloads = []
        for payload in plan.payloads:
            destination = files.joinpath(*payload.logical_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(payload.source_path, destination)
            digest, size = sha256_file(destination)
            source_payloads.append(
                {
                    "feature": payload.feature,
                    "identity_contribution": payload.identity_contribution,
                    "logical_path": payload.logical_path,
                    "required": payload.required,
                    "roles": payload.roles,
                    "rule_id": payload.rule_id,
                    "sha256": digest,
                    "size_bytes": size,
                }
            )
        source_manifest = {
            "absences": plan.absences,
            "allowlist_sha256": self.fixture.selection.sha256,
            "bundle_kind": "m0_acquisition",
            "capture_id": "m0-fixture",
            "coherence": plan.coherence,
            "features": plan.features,
            "inventory": plan.inventory,
            "payloads": source_payloads,
            "schema_version": 1,
            "selection_id": plan.selection_id,
        }
        (bundle / "snapshot/capture-manifest.json").write_text(
            json.dumps(source_manifest), encoding="utf-8"
        )
        result = import_m0_bundle(
            bundle_root=bundle,
            inputs_root=self.fixture.inputs,
            handoff_root=self.fixture.handoff,
            slot="import",
            input_profile=self.fixture.selection,
            workflow_run_id="run-import",
        )
        imported = read_json(
            self.fixture.inputs
            / "snapshots"
            / result["snapshot_id"]
            / "capture-manifest.json"
        )
        self.assertEqual(imported["schema_version"], 2)
        self.assertEqual(result["import_receipt"]["m0_capture_id"], "m0-fixture")
        self.assertTrue(
            (
                self.fixture.inputs
                / "imports"
                / result["snapshot_id"]
                / "run-import.json"
            ).is_file()
        )

    def test_analyzer_read_only_boundary_probe_rejects_writable_inputs(self) -> None:
        self.fixture.capture("run-ro", "ro")
        with self.assertRaises(ValidationError) as raised:
            analyze_handoff(
                roots=self.fixture.roots,
                slot="ro",
                profile=self.fixture.profile,
                input_profile=self.fixture.selection,
                policy=self.fixture.policy,
                tools_lock=self.fixture.tools_lock,
                migrations_root=ROOT / "migrations",
                enforce_read_only_inputs=True,
            )
        self.assertEqual(raised.exception.error_code, "inputs_not_read_only")


if __name__ == "__main__":
    unittest.main()
