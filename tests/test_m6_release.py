from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from modkit.capture import publish_snapshot
from modkit.errors import ModkitError, ValidationError
from modkit.planner import build_capture_plan
from modkit.sdk import (
    SdkRoots,
    finalize_sdk_release,
    generate_sdk_release,
    package_sdk_release,
    verify_sdk_package,
)
from modkit.util import read_json
from modkit.watch import capture_watch_lock, watch_capture
from tests.test_m1_pipeline import Fixture as CaptureFixture
from tests.test_m4_lua import LuaFixture

ROOT = Path(__file__).resolve().parents[1]


class M6ReleaseTests(unittest.TestCase):
    def test_additive_capability_hardened_package_and_compatibility_records(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            fixture = LuaFixture(root)
            first = fixture.analyze("run-m6-fixture-lua-a")
            first_build = str(first["build_id"])

            managers = fixture.game / "Aniimo_Data/globalgamemanagers"
            managers.write_bytes(managers.read_bytes() + b"-m6-second-build")
            fixture.steam.write_text(
                '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
                '"buildid" "m6-fixture-two"\n}\n',
                encoding="utf-8",
            )
            captured = publish_snapshot(
                build_capture_plan(fixture.selection, fixture.game, fixture.steam),
                fixture.inputs,
                workflow_run_id="capture-m6-fixture-two",
            )
            fixture.snapshot_id = str(captured["snapshot_id"])
            second = fixture.analyze("run-m6-fixture-lua-b")
            second_build = str(second["build_id"])

            roots = SdkRoots(state=fixture.state, output=fixture.output)
            generated = generate_sdk_release(
                roots=roots,
                build_ids=[first_build, second_build],
                sdk_version="1.1.0",
                adapter_version="1.1.0",
                migrations_root=ROOT / "migrations",
                workflow_run_id="run-m6-fixture-generate",
            )
            generated_root = fixture.output / str(generated["output_root"])
            manifests = {
                path.stem: read_json(path)
                for path in (generated_root / "adapters").glob("*.json")
            }
            self.assertEqual(len(manifests), 2)
            self.assertTrue(
                all(item["schema_version"] == 2 for item in manifests.values())
            )
            self.assertEqual(
                len({item["capability_basis_id"] for item in manifests.values()}), 1
            )
            self.assertEqual(
                len(
                    {
                        item["build_identity"]["capability_basis_id"]
                        for item in manifests.values()
                    }
                ),
                2,
            )
            optimization = read_json(
                generated_root / "native-optimization-evaluation.json"
            )
            self.assertEqual(optimization["decision"], "not_needed")
            self.assertFalse(optimization["advanced_native_matching_enabled"])

            compiled = root / "compiled"
            compiled.mkdir()
            for name in (
                "GameModAPI.Contracts.dll",
                "GameModAPI.Runtime.dll",
                "GameModAPI.Adapter.Aniimo.dll",
                "LuaCatalogExample.dll",
            ):
                (compiled / name).write_bytes(f"m6-fixture:{name}".encode("ascii"))
            documentation = root / "README.md"
            documentation.write_text("fixture SDK 1.1\n", encoding="utf-8")
            package_a = root / "sdk-a.zip"
            package_b = root / "sdk-b.zip"
            package_sdk_release(
                compiled_root=compiled,
                generated_root=generated_root,
                documentation_path=documentation,
                destination=package_a,
            )
            package_sdk_release(
                compiled_root=compiled,
                generated_root=generated_root,
                documentation_path=documentation,
                destination=package_b,
            )
            verified = verify_sdk_package(package_a)
            self.assertEqual(verified["schema_version"], 2)
            self.assertEqual(
                verified["package_sha256"],
                verify_sdk_package(package_b)["package_sha256"],
            )

            tampered = root / "tampered.zip"
            with (
                zipfile.ZipFile(package_a) as source,
                zipfile.ZipFile(
                    tampered, "w", compression=zipfile.ZIP_DEFLATED
                ) as destination,
            ):
                for info in source.infolist():
                    data = source.read(info)
                    if info.filename == "README.md":
                        data += b"tampered"
                    destination.writestr(info, data)
            with self.assertRaises(ValidationError) as raised:
                verify_sdk_package(tampered)
            self.assertEqual(
                raised.exception.error_code, "sdk_package_content_mismatch"
            )

            plugin_sha256 = hashlib.sha256(
                (compiled / "LuaCatalogExample.dll").read_bytes()
            ).hexdigest()
            results = []
            for build_id in (first_build, second_build):
                manifest = manifests[build_id]
                results.append(
                    {
                        "build_id": build_id,
                        "build_identity_basis_id": manifest["build_identity"][
                            "capability_basis_id"
                        ],
                        "capability_basis_id": manifest["capability_basis_id"],
                        "module_count": len(manifest["modules"]),
                        "module_sha256": manifest["modules"][0]["script_sha256"],
                        "status": "passed",
                    }
                )
            test_report = {
                "adapter_sdk_version": "1.1.0",
                "binary_compatibility_status": "passed",
                "build_ids": sorted([first_build, second_build]),
                "current_contract_assembly_version": "1.0.0.0",
                "old_contract_assembly_version": "1.0.0.0",
                "plugin_compiled_sdk_version": "1.0.0",
                "plugin_sha256": plugin_sha256,
                "results": results,
                "runtime_game_status": "not_tested",
                "same_plugin_binary": True,
                "schema_version": 2,
                "status": "passed",
            }
            report_path = root / "sdk-test-report.json"
            report_path.write_text(json.dumps(test_report), encoding="utf-8")
            finalized = finalize_sdk_release(
                roots=roots,
                generated_root=generated_root,
                package_path=package_a,
                contract_path=compiled / "GameModAPI.Contracts.dll",
                test_report_path=report_path,
                migrations_root=ROOT / "migrations",
                workflow_run_id="run-m6-fixture-finalize",
            )
            self.assertEqual(finalized["binary_compatibility_status"], "passed")
            self.assertEqual(finalized["signature_status"], "unsigned")
            self.assertEqual(finalized["runtime_validation_status"], "not_tested")
            with sqlite3.connect(fixture.state / "registry.sqlite") as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(*) FROM sdk_binary_compatibility_tests"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(*) FROM distribution_attestations"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(*) FROM capability_validations"
                    ).fetchone()[0],
                    12,
                )

    def test_watch_once_polls_full_capture_and_dispatches_only_changes(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            fixture = CaptureFixture(Path(temporary))

            def run_watch() -> dict[str, object]:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "modkit",
                        "watch",
                        "--once",
                        "--interval",
                        "1",
                        "--game-root",
                        str(fixture.game),
                        "--steam-manifest",
                        str(fixture.steam),
                        "--inputs-root",
                        str(fixture.inputs),
                        "--handoff-root",
                        str(fixture.handoff),
                        "--handoff-slot",
                        "m6-watch",
                    ],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)

            first = run_watch()
            self.assertEqual(first["dispatches"], 1)
            pending = fixture.handoff / "pending/m6-watch.json"
            first_record = read_json(pending)
            second = run_watch()
            self.assertEqual(second["dispatches"], 0)
            self.assertEqual(read_json(pending), first_record)

            pending.unlink()
            managers = fixture.game / "Aniimo_Data/globalgamemanagers"
            managers.write_bytes(managers.read_bytes() + b"-watch-change")
            third = run_watch()
            self.assertEqual(third["dispatches"], 1)
            self.assertNotEqual(
                read_json(pending)["snapshot_id"], first_record["snapshot_id"]
            )
            self.assertFalse((fixture.inputs / "watch/m6-watch.lock").exists())

    def test_watcher_lock_error_recovery_and_clean_stop(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            handoff = root / "handoff"
            attempts = 0

            def transient_capture() -> dict[str, str]:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise ModkitError(
                        "transient fixture failure",
                        exit_code=3,
                        error_code="fixture_transient",
                    )
                return {
                    "manifest_sha256": "a" * 64,
                    "snapshot_id": "snapshot-" + "b" * 64,
                    "workflow_run_id": "run-watch-recovered",
                }

            recovered = watch_capture(
                inputs_root=inputs,
                handoff_root=handoff,
                handoff_slot="recovery",
                interval_seconds=0.001,
                capture_once=transient_capture,
                max_iterations=2,
            )
            self.assertEqual(recovered["failures"], 1)
            self.assertEqual(recovered["captures_succeeded"], 1)
            self.assertEqual(recovered["dispatches"], 1)

            with capture_watch_lock(inputs, "overlap"):
                with self.assertRaises(ModkitError) as raised:
                    watch_capture(
                        inputs_root=inputs,
                        handoff_root=handoff,
                        handoff_slot="overlap",
                        interval_seconds=1,
                        capture_once=transient_capture,
                        once=True,
                    )
                self.assertEqual(raised.exception.error_code, "watch_slot_locked")

            stopped = threading.Event()
            stopped.set()
            result = watch_capture(
                inputs_root=inputs,
                handoff_root=handoff,
                handoff_slot="stopped",
                interval_seconds=1,
                capture_once=transient_capture,
                stop_event=stopped,
            )
            self.assertEqual(result["status"], "stopped")
            self.assertEqual(result["iterations"], 0)


if __name__ == "__main__":
    unittest.main()
